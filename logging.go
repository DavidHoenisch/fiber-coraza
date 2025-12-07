package coraza

import (
	"encoding/json"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/gofiber/fiber/v2"
	"io"
	"time"
)

type AuditLog struct {
	Timestamp    string    `json:"timestamp"`
	ID           string    `json:"transaction_id"`
	ClientIP     string    `json:"client_ip"`
	RequestURI   string    `json:"request_uri"`
	Method       string    `json:"method"`
	ResponseCode int       `json:"response_code"`
	Action       string    `json:"action"` // "Block" or "Allow"
	MatchedRules []LogRule `json:"matched_rules,omitempty"`
}

type LogRule struct {
	ID      int    `json:"id"`
	Message string `json:"message"`
	Data    string `json:"data"`
}

func writeAuditLog(c *fiber.Ctx, tx types.Transaction, consumer io.Writer) {
	// Only log if rules were matched (or remove check to log all)
	if len(tx.MatchedRules()) == 0 {
		return
	}

	logEntry := AuditLog{
		Timestamp: time.Now().Format(time.RFC3339),
		ID:        tx.ID(),
		// GET DATA FROM FIBER (Reliable & Fast)
		ClientIP:     c.IP(),
		RequestURI:   c.OriginalURL(),
		Method:       c.Method(),
		ResponseCode: c.Response().StatusCode(),
		Action:       "Allow",
	}

	if tx.IsInterrupted() {
		logEntry.Action = "Block"
	}

	// GET DATA FROM CORAZA (WAF Specifics)
	for _, r := range tx.MatchedRules() {
		logEntry.MatchedRules = append(logEntry.MatchedRules, LogRule{
			ID:      r.Rule().ID(),
			Message: r.ErrorLog(),
			Data:    r.Data(),
		})
	}

	if logBytes, err := json.Marshal(logEntry); err == nil {
		consumer.Write(append(logBytes, '\n'))
	}
}

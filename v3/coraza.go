package coraza

import (
	"bytes"
	"fmt"
	"log"

	"github.com/corazawaf/coraza/v3/types"
	"github.com/gofiber/fiber/v3"
)

func NewCoraza(config ...Config) fiber.Handler {
	cfg := configDefault(config...)

	return func(c fiber.Ctx) error {
		if cfg.Next != nil && cfg.Next(c) {
			return c.Next()
		}

		if cfg.WAF == nil {
			return c.Next()
		}
		tx := cfg.WAF.NewTransaction()

		defer func() {
			tx.ProcessLogging()

			if cfg.Consumer != nil {
				writeAuditLog(c, tx, cfg.Consumer)
			}

			if err := tx.Close(); err != nil {
				log.Printf("CORAZA: error closing TX: %v \n", err)
			}
		}()

		tx.ProcessConnection(c.IP(), 0, "", 0)
		tx.ProcessURI(c.OriginalURL(), c.Method(), string(c.Request().Header.Protocol()))

		c.Request().Header.VisitAll(func(key, value []byte) {
			tx.AddRequestHeader(string(key), string(value))
		})

		if it := tx.ProcessRequestHeaders(); it != nil {
			if !cfg.Block {
				cfg.Consumer.Write(fmt.Appendf(nil, "[trafficMatch][%d] Detected with skipped action: %s", it.RuleID, it.Action))
				return c.Next()
			}

			cfg.Consumer.Write(fmt.Appendf(nil, "[trafficMatch][%d] Coraza Responded with: %s", it.RuleID, it.Action))
			return handleIntervention(c, it)
		}

		if cfg.InspectBody && (c.Method() == "POST" || c.Method() == "PUT" || c.Method() == "PATCH") {
			bodyBytes := bytes.NewReader(c.Body())
			it, _, err := tx.ReadRequestBodyFrom(bodyBytes)
			if it != nil {
				return handleIntervention(c, it)
			}
			if err != nil && cfg.FailClosed {
				return c.SendStatus(fiber.StatusInternalServerError)
			}
		}

		if cfg.InspectBody {
			it, err := tx.ProcessRequestBody()
			if it != nil {
				return handleIntervention(c, it)
			}

			if err != nil && cfg.FailClosed {
				return c.SendStatus(fiber.StatusInternalServerError)
			}
		}

		err := c.Next()
		if err != nil {
			tx.ProcessResponseHeaders(500, "HTTP/1.1")
		} else {
			tx.ProcessResponseHeaders(c.Response().StatusCode(), "HTTP/1.1")
		}

		return err
	}
}

func handleIntervention(c fiber.Ctx, it *types.Interruption) error {
	switch it.Action {
	case "drop":
		if it.Status > 0 {
			c.Status(it.Status)
		}
		return c.Drop()
	case "deny":
		return c.Status(it.Status).SendString(fmt.Sprintf("Rule %d blocked", it.RuleID))
	case "redirect":
		redirect := c.Redirect()
		if it.Status > 0 {
			redirect.Status(it.Status)
		}
		return redirect.To(it.Data)
	}

	return nil
}

package coraza

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	// "github.com/stretchr/testify/assert" // Highly recommended, but I'll use standard lib if you prefer
)

// Helper struct to parse the JSON log in tests
type TestAuditLog struct {
	TransactionID string `json:"transaction_id"`
	ClientIP      string `json:"client_ip"`
	Action        string `json:"action"`
	MatchedRules  []struct {
		ID int `json:"id"`
	} `json:"matched_rules"`
}

func TestMiddleware_Structured_Logging(t *testing.T) {
	app := fiber.New()

	// 1. Create the Spy Buffer
	logSpy := new(bytes.Buffer)

	// 2. Define Rules (Must have SecAuditEngine On)
	rules := `
		SecAuditEngine On
		SecRule ARGS:payload "@streq malicious" "id:1234,phase:1,deny,status:403"
	`

	// 3. Configure Middleware
	app.Use(NewCoraza(Config{
		Directives: strings.NewReader(rules),
		Consumer:   logSpy, // Pass our spy
		Block:      true,
	}))

	// 4. Setup Route
	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Safe")
	})

	// 5. Fire Attack Request
	// Note: We set a fake remote addr to test the Fiber integration
	req := httptest.NewRequest("GET", "/?payload=malicious", nil)
	req.RemoteAddr = "1.2.3.4:12345"

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	// 6. Verify Blocking
	if resp.StatusCode != 403 {
		t.Errorf("Expected 403, got %d", resp.StatusCode)
	}

	// 7. Verify Logging (The "Slick" Part)
	if logSpy.Len() == 0 {
		t.Fatal("Expected logs, got empty buffer. Did you set SecAuditEngine On?")
	}

	// Parse the JSON to verify contents
	var logEntry TestAuditLog
	if err := json.Unmarshal(logSpy.Bytes(), &logEntry); err != nil {
		t.Fatalf("Failed to parse log JSON: %v. Raw log: %s", err, logSpy.String())
	}

	// Assert Hybrid Data Sources
	// Source: Fiber (req.RemoteAddr)
	if !strings.Contains(logEntry.ClientIP, "1.2.3.4") {
		t.Errorf("Expected ClientIP '1.2.3.4', got '%s'", logEntry.ClientIP)
	}

	// Source: Coraza (Rule logic)
	if logEntry.Action != "Block" {
		t.Errorf("Expected Action 'Block', got '%s'", logEntry.Action)
	}

	// Source: Coraza (Rule ID)
	if len(logEntry.MatchedRules) == 0 || logEntry.MatchedRules[0].ID != 1234 {
		t.Errorf("Expected Rule ID 1234, got %v", logEntry.MatchedRules)
	}
}

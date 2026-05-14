package coraza

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/types"
	"github.com/gofiber/fiber/v2"
)

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

func testApp(t *testing.T, cfg Config) *fiber.App {
	t.Helper()
	app := fiber.New()
	app.Use(NewCoraza(cfg))
	app.All("/*", func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusOK).SendString("ok")
	})
	return app
}

func doReq(t *testing.T, app *fiber.App, method, target string, body io.Reader) int {
	t.Helper()
	req := httptest.NewRequest(method, target, body)
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	return resp.StatusCode
}

func TestParseDirectives(t *testing.T) {
	got, err := parseDirectives(strings.NewReader("SecRuleEngine On"))
	if err != nil {
		t.Fatalf("parseDirectives returned error: %v", err)
	}
	if got != "SecRuleEngine On" {
		t.Fatalf("unexpected directives: %q", got)
	}

	if _, err := parseDirectives(errReader{}); err == nil {
		t.Fatal("expected reader error")
	}
}

func TestCreateWAF(t *testing.T) {
	waf, err := createWAF(`SecRuleEngine On`, nil)
	if err != nil {
		t.Fatalf("createWAF returned error: %v", err)
	}
	if waf == nil {
		t.Fatal("expected WAF")
	}

	if _, err := createWAF(`SecRule ARGS:id "@streq attack" "id:not-an-int,phase:1,deny"`, nil); err == nil {
		t.Fatal("expected invalid directives error")
	}
}

func TestConsumerWrites(t *testing.T) {
	var out bytes.Buffer
	NewConsumer(&out).Log("hello")
	if got := out.String(); got != "hello\n" {
		t.Fatalf("unexpected log consumer output: %q", got)
	}

	consumer := DefaultConsumer{}
	n, err := consumer.Write([]byte("audit event"))
	if err != nil {
		t.Fatalf("DefaultConsumer.Write returned error: %v", err)
	}
	if n != len("audit event") {
		t.Fatalf("DefaultConsumer.Write length = %d", n)
	}
}

func TestHandleIntervention(t *testing.T) {
	app := fiber.New()
	app.Get("/deny", func(c *fiber.Ctx) error {
		return handleIntervention(c, &types.Interruption{Action: "deny", Status: fiber.StatusTeapot})
	})
	app.Get("/redirect", func(c *fiber.Ctx) error {
		return handleIntervention(c, &types.Interruption{Action: "redirect", Status: fiber.StatusTemporaryRedirect, Data: "/login"})
	})
	app.Get("/drop", func(c *fiber.Ctx) error {
		return handleIntervention(c, &types.Interruption{Action: "drop", Status: fiber.StatusTeapot})
	})
	app.Get("/none", func(c *fiber.Ctx) error {
		if err := handleIntervention(c, &types.Interruption{Action: "pass", Status: fiber.StatusForbidden}); err != nil {
			return err
		}
		return c.SendString("continued")
	})

	if status := doReq(t, app, "GET", "/deny", nil); status != fiber.StatusTeapot {
		t.Fatalf("deny status = %d", status)
	}

	resp, err := app.Test(httptest.NewRequest("GET", "/redirect", nil))
	if err != nil {
		t.Fatalf("redirect request failed: %v", err)
	}
	if resp.StatusCode != fiber.StatusFound {
		t.Fatalf("redirect status = %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != "/login" {
		t.Fatalf("redirect location = %q", got)
	}

	if status := doReq(t, app, "GET", "/drop", nil); status != fiber.StatusTeapot {
		t.Fatalf("drop status = %d", status)
	}

	if status := doReq(t, app, "GET", "/none", nil); status != fiber.StatusOK {
		t.Fatalf("unknown action status = %d", status)
	}
}

func TestConfigDefaultAppliesDefaultsAndOverrides(t *testing.T) {
	var consumer bytes.Buffer
	cfg := configDefault(Config{
		Directives:              strings.NewReader(`SecRuleEngine On`),
		Consumer:                &consumer,
		Block:                   true,
		InspectBody:             true,
		FailClosed:              true,
		LoggerIgnoreAllowEvents: true,
	})

	if !cfg.Block || !cfg.InspectBody || !cfg.FailClosed || !cfg.LoggerIgnoreAllowEvents {
		t.Fatalf("boolean options not applied: %+v", cfg)
	}
	if cfg.Consumer != &consumer {
		t.Fatal("consumer override was not applied")
	}
	if cfg.WAF == nil {
		t.Fatal("expected WAF to be initialized")
	}
}

func TestMiddleware_AllowRequest(t *testing.T) {
	app := testApp(t, Config{
		Directives: strings.NewReader(`SecRule ARGS:id "@streq attack" "id:1,phase:1,deny,status:403"`),
		Block:      true,
	})

	if status := doReq(t, app, "GET", "/?id=safe", nil); status != fiber.StatusOK {
		t.Fatalf("expected status 200, got %d", status)
	}
}

func TestMiddleware_BlockRequest(t *testing.T) {
	app := testApp(t, Config{
		Directives: strings.NewReader(`SecRule ARGS:id "@streq attack" "id:1,phase:1,deny,status:403"`),
		Block:      true,
	})

	if status := doReq(t, app, "GET", "/?id=attack", nil); status != fiber.StatusForbidden {
		t.Fatalf("expected status 403, got %d", status)
	}
}

func TestMiddleware_NextSkipsWAF(t *testing.T) {
	app := testApp(t, Config{
		Next:       func(*fiber.Ctx) bool { return true },
		Directives: strings.NewReader(`SecRule ARGS:id "@streq attack" "id:1,phase:1,deny,status:403"`),
		Block:      true,
	})

	if status := doReq(t, app, "GET", "/?id=attack", nil); status != fiber.StatusOK {
		t.Fatalf("expected skipped request status 200, got %d", status)
	}
}

func TestMiddleware_DetectOnlyAllowsAndLogs(t *testing.T) {
	var consumer bytes.Buffer
	app := testApp(t, Config{
		Directives: strings.NewReader(`SecRule ARGS:id "@streq attack" "id:1,phase:1,deny,status:403"`),
		Block:      false,
		Consumer:   &consumer,
	})

	if status := doReq(t, app, "GET", "/?id=attack", nil); status != fiber.StatusOK {
		t.Fatalf("expected detect-only request status 200, got %d", status)
	}
	if !strings.Contains(consumer.String(), "Detected with skipped action") {
		t.Fatalf("expected detection log, got %q", consumer.String())
	}
}

func TestMiddleware_LoggerIgnoreAllowEventsSkipsAllowedAuditLogs(t *testing.T) {
	var consumer bytes.Buffer
	app := testApp(t, Config{
		Directives:              strings.NewReader(`SecRule ARGS:id "@streq safe" "id:10,phase:1,pass,log,msg:'safe request matched'"`),
		Consumer:                &consumer,
		LoggerIgnoreAllowEvents: true,
	})

	if status := doReq(t, app, "GET", "/?id=safe", nil); status != fiber.StatusOK {
		t.Fatalf("expected allowed request status 200, got %d", status)
	}
	if got := consumer.String(); got != "" {
		t.Fatalf("expected allowed audit log to be ignored, got %q", got)
	}
}

func TestMiddleware_LoggerWritesAllowEventsWhenIgnoreDisabled(t *testing.T) {
	var consumer bytes.Buffer
	app := testApp(t, Config{
		Directives:              strings.NewReader(`SecRule ARGS:id "@streq safe" "id:10,phase:1,pass,log,msg:'safe request matched'"`),
		Consumer:                &consumer,
		LoggerIgnoreAllowEvents: false,
	})

	if status := doReq(t, app, "GET", "/?id=safe", nil); status != fiber.StatusOK {
		t.Fatalf("expected allowed request status 200, got %d", status)
	}

	var entry AuditLog
	if err := json.Unmarshal(bytes.TrimSpace(consumer.Bytes()), &entry); err != nil {
		t.Fatalf("expected JSON audit log, got %q: %v", consumer.String(), err)
	}
	if entry.Action != "Allow" {
		t.Fatalf("expected allow audit action, got %q", entry.Action)
	}
	if len(entry.MatchedRules) != 1 || entry.MatchedRules[0].ID != 10 {
		t.Fatalf("unexpected matched rules: %+v", entry.MatchedRules)
	}
}

func TestMiddleware_BodyInspectionBlocksRequestBody(t *testing.T) {
	for _, method := range []string{"POST", "PUT", "PATCH"} {
		t.Run(method, func(t *testing.T) {
			app := testApp(t, Config{
				Directives:  strings.NewReader("SecRequestBodyAccess On\nSecRule REQUEST_BODY \"@contains attack\" \"id:1,phase:2,deny,status:403\""),
				Block:       true,
				InspectBody: true,
			})

			if status := doReq(t, app, method, "/", strings.NewReader("id=attack")); status != fiber.StatusForbidden {
				t.Fatalf("expected body inspection status 403, got %d", status)
			}
		})
	}
}

func TestMiddleware_DisabledBodyInspectionSkipsPhaseTwo(t *testing.T) {
	app := testApp(t, Config{
		Directives:  strings.NewReader("SecRequestBodyAccess On\nSecRule REQUEST_BODY \"@contains attack\" \"id:1,phase:2,deny,status:403\""),
		Block:       true,
		InspectBody: false,
	})

	if status := doReq(t, app, "POST", "/", strings.NewReader("id=attack")); status != fiber.StatusOK {
		t.Fatalf("expected skipped body inspection status 200, got %d", status)
	}
}

func FuzzParseDirectives(f *testing.F) {
	f.Add("SecRuleEngine On")
	f.Add("")
	f.Add("\x00\xff arbitrary directives")

	f.Fuzz(func(t *testing.T, input string) {
		got, err := parseDirectives(strings.NewReader(input))
		if err != nil {
			t.Fatalf("strings.Reader should not fail: %v", err)
		}
		if got != input {
			t.Fatalf("parseDirectives changed input: got %q want %q", got, input)
		}
	})
}

func FuzzMiddleware(f *testing.F) {
	f.Add("GET", "safe", "")
	f.Add("GET", "attack", "")
	f.Add("POST", "safe", "id=attack")

	f.Fuzz(func(t *testing.T, method, id, body string) {
		if len(method) > 16 || len(id) > 256 || len(body) > 1024 {
			t.Skip()
		}
		switch method {
		case "GET", "POST", "PUT", "PATCH", "DELETE":
		default:
			method = "GET"
		}

		app := testApp(t, Config{
			Directives:  strings.NewReader(`SecRule ARGS:id "@streq attack" "id:1,phase:1,deny,status:403"`),
			Block:       true,
			InspectBody: true,
		})
		status := doReq(t, app, method, "/?id="+url.QueryEscape(id), strings.NewReader(body))
		if status < 100 || status > 599 {
			t.Fatalf("invalid HTTP status: %d", status)
		}
	})
}

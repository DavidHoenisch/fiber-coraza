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
	return doReqWithHeaders(t, app, method, target, body, nil)
}

func doReqWithHeaders(t *testing.T, app *fiber.App, method, target string, body io.Reader, headers map[string]string) int {
	t.Helper()
	req := httptest.NewRequest(method, target, body)
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for key, value := range headers {
		req.Header.Set(key, value)
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
		return handleIntervention(c, &types.Interruption{Action: "deny", Status: fiber.StatusTeapot, RuleID: 949110}, Config{})
	})
	app.Get("/redirect", func(c *fiber.Ctx) error {
		return handleIntervention(c, &types.Interruption{Action: "redirect", Status: fiber.StatusTemporaryRedirect, Data: "/login"}, Config{})
	})
	app.Get("/drop", func(c *fiber.Ctx) error {
		return handleIntervention(c, &types.Interruption{Action: "drop", Status: fiber.StatusTeapot}, Config{})
	})
	app.Get("/none", func(c *fiber.Ctx) error {
		if err := handleIntervention(c, &types.Interruption{Action: "pass", Status: fiber.StatusForbidden}, Config{}); err != nil {
			return err
		}
		return c.SendString("continued")
	})

	if status := doReq(t, app, "GET", "/deny", nil); status != fiber.StatusTeapot {
		t.Fatalf("deny status = %d", status)
	}

	resp, err := app.Test(httptest.NewRequest("GET", "/deny", nil))
	if err != nil {
		t.Fatalf("deny request failed: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read deny body: %v", err)
	}
	if strings.Contains(string(body), "Rule ") || strings.Contains(string(body), "949110") {
		t.Fatalf("deny body leaked rule details: %q", body)
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("deny body is not JSON: %q (%v)", body, err)
	}
	errObj, ok := payload["error"].(map[string]any)
	if !ok {
		t.Fatalf("deny body missing error object: %q", body)
	}
	if errObj["message"] != "Request could not be processed" {
		t.Fatalf("unexpected deny message: %#v", errObj["message"])
	}

	resp, err = app.Test(httptest.NewRequest("GET", "/redirect", nil))
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

func TestConfigDefaultAppliesClientIpOptions(t *testing.T) {
	defaultCfg := configDefault()
	if defaultCfg.ClientIpFromHeader {
		t.Fatal("expected ClientIpFromHeader default false")
	}
	if defaultCfg.ClientIpHeader != "X-Forwarded-By" {
		t.Fatalf("unexpected default ClientIpHeader: %q", defaultCfg.ClientIpHeader)
	}

	cfg := configDefault(Config{
		Directives:         strings.NewReader(`SecRuleEngine On`),
		ClientIpFromHeader: true,
		ClientIpHeader:     "X-Real-IP",
	})
	if !cfg.ClientIpFromHeader {
		t.Fatal("expected ClientIpFromHeader override")
	}
	if cfg.ClientIpHeader != "X-Real-IP" {
		t.Fatalf("unexpected ClientIpHeader override: %q", cfg.ClientIpHeader)
	}

	cfg = configDefault(Config{
		Directives:         strings.NewReader(`SecRuleEngine On`),
		ClientIpFromHeader: true,
	})
	if cfg.ClientIpHeader != "X-Forwarded-By" {
		t.Fatalf("expected default header when override empty: %q", cfg.ClientIpHeader)
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

func TestMiddleware_AuditLogUsesClientIpFromHeader(t *testing.T) {
	var consumer bytes.Buffer
	app := testApp(t, Config{
		Directives:              strings.NewReader(`SecRule ARGS:id "@streq safe" "id:10,phase:1,pass,log,msg:'safe request matched'"`),
		Consumer:                &consumer,
		LoggerIgnoreAllowEvents: false,
		ClientIpFromHeader:      true,
		ClientIpHeader:          "X-Real-IP",
	})

	if status := doReqWithHeaders(t, app, "GET", "/?id=safe", nil, map[string]string{
		"X-Real-IP": "203.0.113.10",
	}); status != fiber.StatusOK {
		t.Fatalf("expected allowed request status 200, got %d", status)
	}

	var entry AuditLog
	if err := json.Unmarshal(bytes.TrimSpace(consumer.Bytes()), &entry); err != nil {
		t.Fatalf("expected JSON audit log, got %q: %v", consumer.String(), err)
	}
	if entry.ClientIP != "203.0.113.10" {
		t.Fatalf("expected client IP from header, got %q", entry.ClientIP)
	}
}

func TestMiddleware_RemoteAddrRuleUsesClientIpFromHeader(t *testing.T) {
	app := testApp(t, Config{
		Directives:         strings.NewReader(`SecRule REMOTE_ADDR "@streq 203.0.113.10" "id:1,phase:1,deny,status:403"`),
		Block:              true,
		ClientIpFromHeader: true,
		ClientIpHeader:     "X-Real-IP",
	})

	if status := doReq(t, app, "GET", "/", nil); status != fiber.StatusOK {
		t.Fatalf("expected request without header to be allowed, got %d", status)
	}
	if status := doReqWithHeaders(t, app, "GET", "/", nil, map[string]string{
		"X-Real-IP": "203.0.113.10",
	}); status != fiber.StatusForbidden {
		t.Fatalf("expected request with matching header IP to be blocked, got %d", status)
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
	f.Add("GET", "safe", "", false, "X-Real-IP", "203.0.113.10")
	f.Add("GET", "attack", "", false, "", "")
	f.Add("POST", "safe", "id=attack", true, "X-Forwarded-By", "198.51.100.5")

	f.Fuzz(func(t *testing.T, method, id, body string, clientIpFromHeader bool, clientIpHeader, clientIpValue string) {
		if len(method) > 16 || len(id) > 256 || len(body) > 1024 || len(clientIpHeader) > 128 || len(clientIpValue) > 128 {
			t.Skip()
		}
		for _, s := range []string{clientIpHeader, clientIpValue} {
			if strings.ContainsFunc(s, func(r rune) bool { return r < 32 || r == 127 }) {
				t.Skip()
			}
		}
		switch method {
		case "GET", "POST", "PUT", "PATCH", "DELETE":
		default:
			method = "GET"
		}

		cfg := Config{
			Directives:  strings.NewReader(`SecRule ARGS:id "@streq attack" "id:1,phase:1,deny,status:403"`),
			Block:       true,
			InspectBody: true,
		}
		if clientIpFromHeader {
			cfg.ClientIpFromHeader = true
			if clientIpHeader != "" {
				cfg.ClientIpHeader = clientIpHeader
			}
		}

		app := testApp(t, cfg)
		headers := map[string]string{}
		if clientIpFromHeader && clientIpHeader != "" && clientIpValue != "" {
			headers[clientIpHeader] = clientIpValue
		}
		status := doReqWithHeaders(t, app, method, "/?id="+url.QueryEscape(id), strings.NewReader(body), headers)
		if status < 100 || status > 599 {
			t.Fatalf("invalid HTTP status: %d", status)
		}
	})
}

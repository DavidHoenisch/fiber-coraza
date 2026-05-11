package coraza

import (
	"bytes"
	"errors"
	"io"
	"log"
	"net/http/httptest"
	"strings"
	"testing"

	corazawaf "github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
	"github.com/gofiber/fiber/v3"
)

type mockWAF struct{ tx *mockTransaction }

func (w *mockWAF) NewTransaction() types.Transaction             { return w.tx }
func (w *mockWAF) NewTransactionWithID(string) types.Transaction { return w.tx }

var _ corazawaf.WAF = (*mockWAF)(nil)

type mockTransaction struct {
	requestHeaderIt  *types.Interruption
	readBodyIt       *types.Interruption
	readBodyErr      error
	processBodyIt    *types.Interruption
	processBodyErr   error
	matchedRules     []types.MatchedRule
	interrupted      bool
	loggingCalled    bool
	closed           bool
	closeErr         error
	connectionCalled bool
	clientPort       int
	serverPort       int
	responseCodes    []int
}

func (tx *mockTransaction) ProcessConnection(_ string, cPort int, _ string, sPort int) {
	tx.connectionCalled = true
	tx.clientPort = cPort
	tx.serverPort = sPort
}
func (tx *mockTransaction) ProcessURI(string, string, string)          {}
func (tx *mockTransaction) SetServerName(string)                       {}
func (tx *mockTransaction) AddRequestHeader(string, string)            {}
func (tx *mockTransaction) ProcessRequestHeaders() *types.Interruption { return tx.requestHeaderIt }
func (tx *mockTransaction) RequestBodyReader() (io.Reader, error)      { return strings.NewReader(""), nil }
func (tx *mockTransaction) AddGetRequestArgument(string, string)       {}
func (tx *mockTransaction) AddPostRequestArgument(string, string)      {}
func (tx *mockTransaction) AddPathRequestArgument(string, string)      {}
func (tx *mockTransaction) AddResponseArgument(string, string)         {}
func (tx *mockTransaction) ProcessRequestBody() (*types.Interruption, error) {
	return tx.processBodyIt, tx.processBodyErr
}
func (tx *mockTransaction) WriteRequestBody([]byte) (*types.Interruption, int, error) {
	return tx.readBodyIt, 0, tx.readBodyErr
}
func (tx *mockTransaction) ReadRequestBodyFrom(io.Reader) (*types.Interruption, int, error) {
	return tx.readBodyIt, 0, tx.readBodyErr
}
func (tx *mockTransaction) AddResponseHeader(string, string) {}
func (tx *mockTransaction) ProcessResponseHeaders(code int, _ string) *types.Interruption {
	tx.responseCodes = append(tx.responseCodes, code)
	return nil
}
func (tx *mockTransaction) ResponseBodyReader() (io.Reader, error)            { return strings.NewReader(""), nil }
func (tx *mockTransaction) ProcessResponseBody() (*types.Interruption, error) { return nil, nil }
func (tx *mockTransaction) WriteResponseBody([]byte) (*types.Interruption, int, error) {
	return nil, 0, nil
}
func (tx *mockTransaction) ReadResponseBodyFrom(io.Reader) (*types.Interruption, int, error) {
	return nil, 0, nil
}
func (tx *mockTransaction) ProcessLogging()                   { tx.loggingCalled = true }
func (tx *mockTransaction) IsRuleEngineOff() bool             { return false }
func (tx *mockTransaction) IsRequestBodyAccessible() bool     { return true }
func (tx *mockTransaction) IsResponseBodyAccessible() bool    { return true }
func (tx *mockTransaction) IsResponseBodyProcessable() bool   { return true }
func (tx *mockTransaction) IsInterrupted() bool               { return tx.interrupted }
func (tx *mockTransaction) Interruption() *types.Interruption { return nil }
func (tx *mockTransaction) MatchedRules() []types.MatchedRule { return tx.matchedRules }
func (tx *mockTransaction) DebugLogger() debuglog.Logger      { return debuglog.Noop() }
func (tx *mockTransaction) ID() string                        { return "tx-test-id" }
func (tx *mockTransaction) Close() error {
	tx.closed = true
	return tx.closeErr
}

var _ types.Transaction = (*mockTransaction)(nil)

type mockMatchedRule struct{}
type mockRuleMetadata struct{}

func (mockMatchedRule) Message() string                 { return "matched" }
func (mockMatchedRule) Data() string                    { return "attack" }
func (mockMatchedRule) URI() string                     { return "/" }
func (mockMatchedRule) TransactionID() string           { return "tx-test-id" }
func (mockMatchedRule) Disruptive() bool                { return true }
func (mockMatchedRule) ServerIPAddress() string         { return "" }
func (mockMatchedRule) ClientIPAddress() string         { return "127.0.0.1" }
func (mockMatchedRule) MatchedDatas() []types.MatchData { return nil }
func (mockMatchedRule) Rule() types.RuleMetadata        { return mockRuleMetadata{} }
func (mockMatchedRule) AuditLog() string                { return "audit" }
func (mockMatchedRule) ErrorLog() string                { return "error log" }
func (mockRuleMetadata) ID() int                        { return 99 }
func (mockRuleMetadata) File() string                   { return "test" }
func (mockRuleMetadata) Line() int                      { return 1 }
func (mockRuleMetadata) Revision() string               { return "" }
func (mockRuleMetadata) Severity() types.RuleSeverity   { return 0 }
func (mockRuleMetadata) Version() string                { return "" }
func (mockRuleMetadata) Tags() []string                 { return nil }
func (mockRuleMetadata) Maturity() int                  { return 0 }
func (mockRuleMetadata) Accuracy() int                  { return 0 }
func (mockRuleMetadata) Operator() string               { return "" }
func (mockRuleMetadata) Phase() types.RulePhase         { return 1 }
func (mockRuleMetadata) Raw() string                    { return "" }
func (mockRuleMetadata) SecMark() string                { return "" }

var _ variables.RuleVariable

func TestConfigDefaultNoArgs(t *testing.T) {
	cfg := configDefault()
	if cfg.WAF == nil || cfg.Consumer == nil {
		t.Fatalf("default config did not initialize WAF and consumer: %+v", cfg)
	}
}

func TestConfigDefaultPreservesCallback(t *testing.T) {
	cfg := configDefault(Config{
		Directives: strings.NewReader(`SecRuleEngine On`),
		Callback:   func(types.MatchedRule) {},
	})
	if cfg.Callback == nil {
		t.Fatal("expected callback to be preserved")
	}
}

func TestMiddleware_FailClosedReadBodyError(t *testing.T) {
	for _, tc := range []struct {
		name       string
		failClosed bool
		want       int
	}{
		{"closed", true, fiber.StatusInternalServerError},
		{"open", false, fiber.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx := &mockTransaction{readBodyErr: errors.New("read failed")}
			app := testApp(t, Config{WAF: &mockWAF{tx: tx}, InspectBody: true, FailClosed: tc.failClosed})
			if status := doReq(t, app, "POST", "/", strings.NewReader("body")); status != tc.want {
				t.Fatalf("status = %d, want %d", status, tc.want)
			}
		})
	}
}

func TestMiddleware_FailClosedProcessBodyError(t *testing.T) {
	for _, tc := range []struct {
		name       string
		failClosed bool
		want       int
	}{
		{"closed", true, fiber.StatusInternalServerError},
		{"open", false, fiber.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx := &mockTransaction{processBodyErr: errors.New("process failed")}
			app := testApp(t, Config{WAF: &mockWAF{tx: tx}, InspectBody: true, FailClosed: tc.failClosed})
			if status := doReq(t, app, "GET", "/", nil); status != tc.want {
				t.Fatalf("status = %d, want %d", status, tc.want)
			}
		})
	}
}

func TestMiddleware_MockTransactionLifecycleAndAuditLog(t *testing.T) {
	tx := &mockTransaction{matchedRules: []types.MatchedRule{mockMatchedRule{}}, interrupted: true}
	var consumer bytes.Buffer
	app := testApp(t, Config{WAF: &mockWAF{tx: tx}, Consumer: &consumer})

	if status := doReq(t, app, "GET", "/audit", nil); status != fiber.StatusOK {
		t.Fatalf("status = %d", status)
	}
	if !tx.loggingCalled || !tx.closed {
		t.Fatalf("transaction lifecycle not completed: logging=%v closed=%v", tx.loggingCalled, tx.closed)
	}
	if !tx.connectionCalled || tx.clientPort != 0 || tx.serverPort != 0 {
		t.Fatalf("connection args: called=%v clientPort=%d serverPort=%d", tx.connectionCalled, tx.clientPort, tx.serverPort)
	}
	if len(tx.responseCodes) != 1 || tx.responseCodes[0] != fiber.StatusOK {
		t.Fatalf("response codes = %#v", tx.responseCodes)
	}
	log := consumer.String()
	for _, want := range []string{`"transaction_id":"tx-test-id"`, `"action":"Block"`, `"id":99`, `"data":"attack"`} {
		if !strings.Contains(log, want) {
			t.Fatalf("audit log %q does not contain %s", log, want)
		}
	}
}

func TestMiddleware_ProcessResponseHeadersOnHandlerError(t *testing.T) {
	tx := &mockTransaction{}
	app := fiber.New()
	app.Use(NewCoraza(Config{WAF: &mockWAF{tx: tx}}))
	app.Get("/err", func(fiber.Ctx) error { return errors.New("handler failed") })

	_, _ = app.Test(httptest.NewRequest("GET", "/err", nil))
	if len(tx.responseCodes) != 1 || tx.responseCodes[0] != fiber.StatusInternalServerError {
		t.Fatalf("response codes = %#v", tx.responseCodes)
	}
}

func TestMiddleware_ReadBodyInterruption(t *testing.T) {
	tx := &mockTransaction{readBodyIt: &types.Interruption{Action: "deny", Status: fiber.StatusForbidden}}
	app := testApp(t, Config{WAF: &mockWAF{tx: tx}, InspectBody: true, FailClosed: true})
	if status := doReq(t, app, "POST", "/", strings.NewReader("body")); status != fiber.StatusForbidden {
		t.Fatalf("status = %d", status)
	}
}

func TestMiddleware_DoesNotReadBodyWhenInspectionDisabled(t *testing.T) {
	tx := &mockTransaction{readBodyErr: errors.New("must not read body")}
	app := testApp(t, Config{WAF: &mockWAF{tx: tx}, InspectBody: false, FailClosed: true})
	if status := doReq(t, app, "POST", "/", strings.NewReader("body")); status != fiber.StatusOK {
		t.Fatalf("status = %d", status)
	}
}

func TestMiddleware_DoesNotReadBodyForGet(t *testing.T) {
	tx := &mockTransaction{readBodyErr: errors.New("must not read body")}
	app := testApp(t, Config{WAF: &mockWAF{tx: tx}, InspectBody: true, FailClosed: true})
	if status := doReq(t, app, "GET", "/", strings.NewReader("body")); status != fiber.StatusOK {
		t.Fatalf("status = %d", status)
	}
}

func TestMiddleware_NextFalseDoesNotSkipWAF(t *testing.T) {
	tx := &mockTransaction{requestHeaderIt: &types.Interruption{Action: "deny", Status: fiber.StatusForbidden}}
	app := testApp(t, Config{WAF: &mockWAF{tx: tx}, Next: func(fiber.Ctx) bool { return false }, Block: true})
	if status := doReq(t, app, "GET", "/", nil); status != fiber.StatusForbidden {
		t.Fatalf("status = %d", status)
	}
}

func TestMiddleware_BlockWritesTrafficMatch(t *testing.T) {
	tx := &mockTransaction{requestHeaderIt: &types.Interruption{Action: "deny", Status: fiber.StatusForbidden, RuleID: 123}}
	var consumer bytes.Buffer
	app := testApp(t, Config{WAF: &mockWAF{tx: tx}, Consumer: &consumer, Block: true})
	if status := doReq(t, app, "GET", "/", nil); status != fiber.StatusForbidden {
		t.Fatalf("status = %d", status)
	}
	if !strings.Contains(consumer.String(), "[trafficMatch][123] Coraza Responded with: deny") {
		t.Fatalf("missing block log: %q", consumer.String())
	}
}

func TestMiddleware_LogsCloseError(t *testing.T) {
	tx := &mockTransaction{closeErr: errors.New("close boom")}
	var logs bytes.Buffer
	old := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(old)

	app := testApp(t, Config{WAF: &mockWAF{tx: tx}})
	_ = doReq(t, app, "GET", "/", nil)
	if !strings.Contains(logs.String(), "close boom") {
		t.Fatalf("missing close error log: %q", logs.String())
	}
}

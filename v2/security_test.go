package coraza

import (
	"io"
	"net/url"
	"os"
	"strings"
	"testing"
)

func TestMiddlewareRejectsOctalEscapedAttack(t *testing.T) {
	app := testApp(t, Config{
		Directives: strings.NewReader(`SecRuleEngine On
SecRule ARGS:q "@contains <script>" "id:990001,phase:2,t:none,t:jsDecode,deny,status:403"`),
		Block:       true,
		InspectBody: true,
		FailClosed:  true,
	})
	for _, tc := range []struct {
		name, value string
		want        int
	}{
		{"benign", "hello", 200},
		{"plain", "<script>", 403},
		{"octal", `<\163\143\162\151\160\164>`, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := doReq(t, app, "GET", "/?q="+url.QueryEscape(tc.value), nil); got != tc.want {
				t.Fatalf("status = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestMiddlewareEnforcesRequestSecurityBaseline(t *testing.T) {
	baseline, err := os.ReadFile("../request-security.conf")
	if err != nil {
		t.Fatal(err)
	}
	app := testApp(t, Config{
		Directives:  strings.NewReader("SecRuleEngine On\n" + string(baseline) + "\nSecArgumentsLimit 2\nSecRequestBodyJsonDepthLimit 8\n"),
		Block:       true,
		InspectBody: true,
		// The supplied rules must reject parser/limit errors themselves.
		FailClosed: false,
		Consumer:   io.Discard,
	})
	for _, tc := range []struct {
		name, method, target, contentType, body string
		want                                    int
	}{
		{"query at limit", "GET", "/?a=1&b=2", "", "", 200},
		{"query overflow", "GET", "/?a=1&b=2&c=3", "", "", 400},
		{"form at limit", "POST", "/", "application/x-www-form-urlencoded", "a=1&b=2", 200},
		{"form overflow", "POST", "/", "application/x-www-form-urlencoded", "a=1&b=2&c=3", 400},
		{"json at limit", "POST", "/", "application/json", `{"a":1,"b":2}`, 200},
		{"json overflow", "POST", "/", "application/json", `{"a":1,"b":2,"c":3}`, 400},
		{"json suffix overflow", "POST", "/", "application/problem+json", `{"a":1,"b":2,"c":3}`, 400},
		{"json depth exceeded", "POST", "/", "application/json", strings.Repeat(`{"x":`, 10) + "0" + strings.Repeat("}", 10), 400},
		{"truncated deep tail", "POST", "/", "application/json", `{"a":1,"b":2,"c":` + strings.Repeat("[", 32) + "0" + strings.Repeat("]", 32) + "}", 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var body io.Reader
			if tc.body != "" {
				body = strings.NewReader(tc.body)
			}
			if got := doReqWithHeaders(t, app, tc.method, tc.target, body, map[string]string{"Content-Type": tc.contentType}); got != tc.want {
				t.Fatalf("status = %d, want %d", got, tc.want)
			}
		})
	}
}

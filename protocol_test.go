package coraza

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/utils"
	"github.com/valyala/fasthttp"
)

// TestProtocolParsing_HTTP1_0 tests that HTTP/1.0 protocol is correctly parsed and passed to ProcessURI
func TestProtocolParsing_HTTP1_0(t *testing.T) {
	app := fiber.New()

	// Rule that checks the protocol variable
	rules := `
		SecRuleEngine On
		SecRule REQUEST_PROTOCOL "!@streq HTTP/1.0" "id:1001,phase:1,deny,status:403,msg:'Expected HTTP/1.0'"
	`

	app.Use(NewCoraza(Config{
		Directives: strings.NewReader(rules),
		Block:      true,
	}))

	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})

	// Create request with HTTP/1.0 protocol
	req := httptest.NewRequest("GET", "/", nil)
	req.Proto = "HTTP/1.0"
	req.ProtoMajor = 1
	req.ProtoMinor = 0

	resp, err := app.Test(req)
	utils.AssertEqual(t, nil, err)
	utils.AssertEqual(t, 200, resp.StatusCode, "HTTP/1.0 should be correctly parsed")
}

// TestProtocolParsing_HTTP1_1 tests that HTTP/1.1 protocol is correctly parsed and passed to ProcessURI
func TestProtocolParsing_HTTP1_1(t *testing.T) {
	app := fiber.New()

	// Rule that checks the protocol variable
	rules := `
		SecRuleEngine On
		SecRule REQUEST_PROTOCOL "!@streq HTTP/1.1" "id:1002,phase:1,deny,status:403,msg:'Expected HTTP/1.1'"
	`

	app.Use(NewCoraza(Config{
		Directives: strings.NewReader(rules),
		Block:      true,
	}))

	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})

	// Create request with HTTP/1.1 protocol (default)
	req := httptest.NewRequest("GET", "/", nil)
	req.Proto = "HTTP/1.1"
	req.ProtoMajor = 1
	req.ProtoMinor = 1

	resp, err := app.Test(req)
	utils.AssertEqual(t, nil, err)
	utils.AssertEqual(t, 200, resp.StatusCode, "HTTP/1.1 should be correctly parsed")
}

// TestProtocolParsing_HTTP2 tests that HTTP/2 protocol is correctly parsed and passed to ProcessURI
func TestProtocolParsing_HTTP2(t *testing.T) {
	app := fiber.New()

	// Rule that checks the protocol variable for HTTP/2
	rules := `
		SecRuleEngine On
		SecRule REQUEST_PROTOCOL "!@streq HTTP/2.0" "id:1003,phase:1,deny,status:403,msg:'Expected HTTP/2.0'"
	`

	app.Use(NewCoraza(Config{
		Directives: strings.NewReader(rules),
		Block:      true,
	}))

	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})

	// Create a custom fasthttp request with HTTP/2.0 protocol
	req := &fasthttp.Request{}
	req.SetRequestURI("/")
	req.Header.SetMethod("GET")
	req.Header.SetProtocol("HTTP/2.0")

	// Convert to fiber context
	fiberReq := httptest.NewRequest("GET", "/", nil)
	fiberReq.Proto = "HTTP/2.0"
	fiberReq.ProtoMajor = 2
	fiberReq.ProtoMinor = 0

	resp, err := app.Test(fiberReq)
	utils.AssertEqual(t, nil, err)
	utils.AssertEqual(t, 200, resp.StatusCode, "HTTP/2.0 should be correctly parsed")
}

// TestProtocolParsing_HTTP2_AlternateFormat tests HTTP/2 without the minor version
func TestProtocolParsing_HTTP2_AlternateFormat(t *testing.T) {
	app := fiber.New()

	// Rule that checks for HTTP/2 (some implementations may use "HTTP/2" instead of "HTTP/2.0")
	rules := `
		SecRuleEngine On
		SecRule REQUEST_PROTOCOL "!@rx ^HTTP/2" "id:1004,phase:1,deny,status:403,msg:'Expected HTTP/2'"
	`

	app.Use(NewCoraza(Config{
		Directives: strings.NewReader(rules),
		Block:      true,
	}))

	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})

	// Test with HTTP/2 (no minor version)
	req := httptest.NewRequest("GET", "/", nil)
	req.Proto = "HTTP/2"
	req.ProtoMajor = 2
	req.ProtoMinor = 0

	resp, err := app.Test(req)
	utils.AssertEqual(t, nil, err)
	utils.AssertEqual(t, 200, resp.StatusCode, "HTTP/2 should be correctly parsed")
}

// TestProtocolParsing_HTTP3 tests that HTTP/3 protocol is correctly parsed and passed to ProcessURI
func TestProtocolParsing_HTTP3(t *testing.T) {
	app := fiber.New()

	// Rule that checks the protocol variable for HTTP/3
	rules := `
		SecRuleEngine On
		SecRule REQUEST_PROTOCOL "!@streq HTTP/3.0" "id:1005,phase:1,deny,status:403,msg:'Expected HTTP/3.0'"
	`

	app.Use(NewCoraza(Config{
		Directives: strings.NewReader(rules),
		Block:      true,
	}))

	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})

	// Create request with HTTP/3.0 protocol
	req := httptest.NewRequest("GET", "/", nil)
	req.Proto = "HTTP/3.0"
	req.ProtoMajor = 3
	req.ProtoMinor = 0

	resp, err := app.Test(req)
	utils.AssertEqual(t, nil, err)
	utils.AssertEqual(t, 200, resp.StatusCode, "HTTP/3.0 should be correctly parsed")
}

// TestProtocolParsing_HTTP3_AlternateFormat tests HTTP/3 without the minor version
func TestProtocolParsing_HTTP3_AlternateFormat(t *testing.T) {
	app := fiber.New()

	// Rule that checks for HTTP/3 (some implementations may use "HTTP/3" instead of "HTTP/3.0")
	rules := `
		SecRuleEngine On
		SecRule REQUEST_PROTOCOL "!@rx ^HTTP/3" "id:1006,phase:1,deny,status:403,msg:'Expected HTTP/3'"
	`

	app.Use(NewCoraza(Config{
		Directives: strings.NewReader(rules),
		Block:      true,
	}))

	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})

	// Test with HTTP/3 (no minor version)
	req := httptest.NewRequest("GET", "/", nil)
	req.Proto = "HTTP/3"
	req.ProtoMajor = 3
	req.ProtoMinor = 0

	resp, err := app.Test(req)
	utils.AssertEqual(t, nil, err)
	utils.AssertEqual(t, 200, resp.StatusCode, "HTTP/3 should be correctly parsed")
}

// TestProtocolParsing_AllVersions tests multiple protocol versions in sequence
func TestProtocolParsing_AllVersions(t *testing.T) {
	protocols := []struct {
		proto       string
		protoMajor  int
		protoMinor  int
		expectedMsg string
	}{
		{"HTTP/1.0", 1, 0, "HTTP/1.0"},
		{"HTTP/1.1", 1, 1, "HTTP/1.1"},
		{"HTTP/2.0", 2, 0, "HTTP/2.0"},
		{"HTTP/2", 2, 0, "HTTP/2"},
		{"HTTP/3.0", 3, 0, "HTTP/3.0"},
		{"HTTP/3", 3, 0, "HTTP/3"},
	}

	for _, tc := range protocols {
		t.Run(fmt.Sprintf("Protocol_%s", tc.proto), func(t *testing.T) {
			app := fiber.New()

			// Rule that logs the protocol (doesn't block, just logs)
			rules := `
				SecRuleEngine On
				SecRule REQUEST_PROTOCOL ".*" "id:1100,phase:1,pass,log,msg:'Protocol detected: %{REQUEST_PROTOCOL}'"
			`

			app.Use(NewCoraza(Config{
				Directives: strings.NewReader(rules),
				Block:      false, // Don't block, just log
			}))

			app.Get("/", func(c *fiber.Ctx) error {
				return c.SendString("OK")
			})

			req := httptest.NewRequest("GET", "/", nil)
			req.Proto = tc.proto
			req.ProtoMajor = tc.protoMajor
			req.ProtoMinor = tc.protoMinor

			resp, err := app.Test(req)
			utils.AssertEqual(t, nil, err)
			utils.AssertEqual(t, 200, resp.StatusCode, fmt.Sprintf("%s should be accepted", tc.expectedMsg))
		})
	}
}

// TestProtocolParsing_BlockOldProtocols tests blocking old/insecure protocols
func TestProtocolParsing_BlockOldProtocols(t *testing.T) {
	app := fiber.New()

	// Rule that blocks HTTP/1.0 as it's considered outdated
	rules := `
		SecRuleEngine On
		SecRule REQUEST_PROTOCOL "@streq HTTP/1.0" "id:1200,phase:1,deny,status:426,msg:'HTTP/1.0 is not supported. Please upgrade to HTTP/1.1 or higher.'"
	`

	app.Use(NewCoraza(Config{
		Directives: strings.NewReader(rules),
		Block:      true,
	}))

	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})

	// Test that HTTP/1.0 is blocked
	reqOld := httptest.NewRequest("GET", "/", nil)
	reqOld.Proto = "HTTP/1.0"
	reqOld.ProtoMajor = 1
	reqOld.ProtoMinor = 0

	respOld, err := app.Test(reqOld)
	utils.AssertEqual(t, nil, err)
	utils.AssertEqual(t, 426, respOld.StatusCode, "HTTP/1.0 should be blocked with 426 Upgrade Required")

	// Test that HTTP/1.1 is allowed
	reqNew := httptest.NewRequest("GET", "/", nil)
	reqNew.Proto = "HTTP/1.1"
	reqNew.ProtoMajor = 1
	reqNew.ProtoMinor = 1

	respNew, err := app.Test(reqNew)
	utils.AssertEqual(t, nil, err)
	utils.AssertEqual(t, 200, respNew.StatusCode, "HTTP/1.1 should be allowed")
}

// TestProtocolParsing_RequireModernProtocols tests requiring HTTP/2 or HTTP/3
func TestProtocolParsing_RequireModernProtocols(t *testing.T) {
	app := fiber.New()

	// Rule that only allows HTTP/2 or HTTP/3 (matches HTTP/2.0 or HTTP/3.0)
	rules := `
		SecRuleEngine On
		SecRule REQUEST_PROTOCOL "!@rx ^HTTP/[23]\.?0?$" "id:1300,phase:1,deny,status:426,msg:'Only HTTP/2 or HTTP/3 are supported'"
	`

	app.Use(NewCoraza(Config{
		Directives: strings.NewReader(rules),
		Block:      true,
	}))

	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})

	// Test that HTTP/1.1 is blocked
	req11 := httptest.NewRequest("GET", "/", nil)
	req11.Proto = "HTTP/1.1"
	resp11, _ := app.Test(req11)
	utils.AssertEqual(t, 426, resp11.StatusCode, "HTTP/1.1 should be blocked")

	// Test that HTTP/2.0 is allowed
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.Proto = "HTTP/2.0"
	req2.ProtoMajor = 2
	req2.ProtoMinor = 0
	resp2, _ := app.Test(req2)
	utils.AssertEqual(t, 200, resp2.StatusCode, "HTTP/2.0 should be allowed")

	// Test that HTTP/3.0 is allowed
	req3 := httptest.NewRequest("GET", "/", nil)
	req3.Proto = "HTTP/3.0"
	req3.ProtoMajor = 3
	req3.ProtoMinor = 0
	resp3, _ := app.Test(req3)
	utils.AssertEqual(t, 200, resp3.StatusCode, "HTTP/3.0 should be allowed")
}

// TestProtocolParsing_InvalidProtocol tests handling of invalid/malformed protocols
func TestProtocolParsing_InvalidProtocol(t *testing.T) {
	app := fiber.New()

	// Rule that validates protocol format
	rules := `
		SecRuleEngine On
		SecRule REQUEST_PROTOCOL "!@rx ^HTTP/[0-9]\.[0-9]$" "id:1400,phase:1,deny,status:400,msg:'Invalid protocol format'"
	`

	app.Use(NewCoraza(Config{
		Directives: strings.NewReader(rules),
		Block:      true,
	}))

	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})

	// Test with valid protocol - should pass
	req := httptest.NewRequest("GET", "/", nil)
	req.Proto = "HTTP/1.1"

	resp, err := app.Test(req)
	utils.AssertEqual(t, nil, err)
	utils.AssertEqual(t, 200, resp.StatusCode, "Valid protocol should be accepted")
}

// TestProtocolParsing_Integration tests protocol in combination with other request data
func TestProtocolParsing_Integration(t *testing.T) {
	// Test 1: HTTP/1.1 without force_upgrade - should pass
	t.Run("HTTP1.1_NoUpgrade", func(t *testing.T) {
		app := fiber.New()
		rules := `
			SecRuleEngine On
			SecRule REQUEST_PROTOCOL "@rx ^HTTP/1\." "id:1500,phase:1,pass,setvar:tx.old_protocol=1"
			SecRule ARGS:force_upgrade "@eq 1" "id:1501,phase:1,chain,deny,status:426,msg:'Please upgrade to HTTP/2 or HTTP/3'"
				SecRule TX:old_protocol "@eq 1"
		`
		app.Use(NewCoraza(Config{
			Directives: strings.NewReader(rules),
			Block:      true,
		}))
		app.Get("/", func(c *fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		req.Proto = "HTTP/1.1"
		resp, _ := app.Test(req)
		utils.AssertEqual(t, 200, resp.StatusCode, "HTTP/1.1 without force_upgrade should pass")
	})

	// Test 2: HTTP/1.1 with force_upgrade - should block
	t.Run("HTTP1.1_WithUpgrade", func(t *testing.T) {
		app := fiber.New()
		rules := `
			SecRuleEngine On
			SecRule REQUEST_PROTOCOL "@rx ^HTTP/1\." "id:1500,phase:1,pass,setvar:tx.old_protocol=1"
			SecRule ARGS:force_upgrade "@eq 1" "id:1501,phase:1,chain,deny,status:426,msg:'Please upgrade to HTTP/2 or HTTP/3'"
				SecRule TX:old_protocol "@eq 1"
		`
		app.Use(NewCoraza(Config{
			Directives: strings.NewReader(rules),
			Block:      true,
		}))
		app.Get("/", func(c *fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/?force_upgrade=1", nil)
		req.Proto = "HTTP/1.1"
		resp, _ := app.Test(req)
		utils.AssertEqual(t, 426, resp.StatusCode, "HTTP/1.1 with force_upgrade should be blocked")
	})

	// Test 3: HTTP/2.0 with force_upgrade - should pass (protocol is modern)
	t.Run("HTTP2.0_WithUpgrade", func(t *testing.T) {
		app := fiber.New()
		rules := `
			SecRuleEngine On
			SecRule REQUEST_PROTOCOL "@rx ^HTTP/1\." "id:1500,phase:1,pass,setvar:tx.old_protocol=1"
			SecRule ARGS:force_upgrade "@eq 1" "id:1501,phase:1,chain,deny,status:426,msg:'Please upgrade to HTTP/2 or HTTP/3'"
				SecRule TX:old_protocol "@eq 1"
		`
		app.Use(NewCoraza(Config{
			Directives: strings.NewReader(rules),
			Block:      true,
		}))
		app.Get("/", func(c *fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/?force_upgrade=1", nil)
		req.Proto = "HTTP/2.0"
		req.ProtoMajor = 2
		req.ProtoMinor = 0
		resp, _ := app.Test(req)
		utils.AssertEqual(t, 200, resp.StatusCode, "HTTP/2.0 with force_upgrade should pass")
	})
}

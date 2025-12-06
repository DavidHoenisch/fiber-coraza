package coraza

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/utils"
)

// TestMiddleware_AllowRequest tests that a request matching NO rules passes through.
func TestMiddleware_AllowRequest(t *testing.T) {
	app := fiber.New()

	// Rule that shouldn't match a standard request
	// (Matches if arg 'id' equals 'attack')
	rules := `SecRule ARGS:id "@streq attack" "id:1,phase:1,deny,status:403"`

	app.Use(NewCoraza(Config{
		Directives: strings.NewReader(rules),
		Block:      true,
	}))

	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Hello, World!")
	})

	// Case 1: Safe Request
	req := httptest.NewRequest("GET", "/?id=safe", nil)
	resp, err := app.Test(req)
	utils.AssertEqual(t, nil, err)
	utils.AssertEqual(t, 200, resp.StatusCode)
}

// TestMiddleware_BlockRequest tests that a request matching a rule IS blocked.
func TestMiddleware_BlockRequest(t *testing.T) {
	app := fiber.New()

	// Rule that matches specific argument
	rules := `SecRule ARGS:id "@streq attack" "id:1,phase:1,deny,status:403"`

	app.Use(NewCoraza(Config{
		Directives: strings.NewReader(rules),
		Block:      true,
	}))

	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Should not be reached")
	})

	// Case 2: Malicious Request
	req := httptest.NewRequest("GET", "/?id=attack", nil)
	resp, err := app.Test(req)
	utils.AssertEqual(t, nil, err)
	utils.AssertEqual(t, 403, resp.StatusCode)
}

func TestMiddleware_Default_Pass(t *testing.T) {
	app := fiber.New()
	app.Use(NewCoraza())

	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Hello")
	})

	req := httptest.NewRequest("GET", "/", nil)
	resp, err := app.Test(req)

	utils.AssertEqual(t, nil, err)

	utils.AssertEqual(t, 200, resp.StatusCode)
}

// TestMiddleware_Next_Skip tests the 'Next' function to skip the middleware
func TestMiddleware_Next_Skip(t *testing.T) {
	app := fiber.New()

	// Rule that blocks everything
	rules := `SecRule REMOTE_ADDR "@rx .*" "id:1,phase:1,deny,status:403"`

	app.Use(NewCoraza(Config{
		Directives: strings.NewReader(rules),
		Block:      true,
		// Skip middleware if path is /skip
		Next: func(c *fiber.Ctx) bool {
			return c.Path() == "/skip"
		},
	}))

	app.Get("/skip", func(c *fiber.Ctx) error {
		return c.SendString("Skipped")
	})
	app.Get("/block", func(c *fiber.Ctx) error {
		return c.SendString("Blocked")
	})

	// Case 1: Should Skip
	reqSkip := httptest.NewRequest("GET", "/skip", nil)
	respSkip, _ := app.Test(reqSkip)
	utils.AssertEqual(t, 200, respSkip.StatusCode)

	// Case 2: Should Block
	reqBlock := httptest.NewRequest("GET", "/block", nil)
	respBlock, _ := app.Test(reqBlock)
	utils.AssertEqual(t, 403, respBlock.StatusCode)
}

package coraza

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

func TestMiddleware_AllowRequest(t *testing.T) {
	app := fiber.New()

	rules := `SecRule ARGS:id "@streq attack" "id:1,phase:1,deny,status:403"`

	app.Use(NewCoraza(Config{
		Directives: strings.NewReader(rules),
		Block:      true,
	}))

	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Hello, World!")
	})

	req := httptest.NewRequest("GET", "/?id=safe", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestMiddleware_BlockRequest(t *testing.T) {
	app := fiber.New()

	rules := `SecRule ARGS:id "@streq attack" "id:1,phase:1,deny,status:403"`

	app.Use(NewCoraza(Config{
		Directives: strings.NewReader(rules),
		Block:      true,
	}))

	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Should not be reached")
	})

	req := httptest.NewRequest("GET", "/?id=attack", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}

	if resp.StatusCode != 403 {
		t.Fatalf("expected status 403, got %d", resp.StatusCode)
	}
}

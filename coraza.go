package coraza

import (
	"fmt"

	"github.com/corazawaf/coraza/v3/types"
	"github.com/gofiber/fiber/v2"
)

func NewCoraza(config ...Config) fiber.Handler {
	cfg := configDefault(config...)

	return func(c *fiber.Ctx) error {
		if cfg.Next != nil && cfg.Next(c) {
			return c.Next()
		}

		if cfg.WAF == nil {
			return c.Next()
		}
		tx := cfg.WAF.NewTransaction()

		defer func() {
			tx.ProcessLogging()

			if err := tx.Close(); err != nil {
				// something
			}

		}()

		tx.ProcessConnection(c.IP(), 0, "", 0)

		tx.ProcessURI(c.OriginalURL(), c.Method(), c.Protocol())

		c.Request().Header.VisitAll(func(key, value []byte) { tx.AddRequestHeader(string(key), string(value)) })

		if it := tx.ProcessRequestHeaders(); it != nil {
			if !cfg.Block {
				cfg.Consumer.Write([]byte(fmt.Sprintf("[trafficMatch][%d] Detected with skipped action: %s",
					it.RuleID, it.Action)))
				return c.Next()
			}

			cfg.Consumer.Write([]byte(fmt.Sprintf("[trafficMatch][%d] Coraza Responded with: %s",
				it.RuleID, it.Action)))
			return handleIntervention(c, it)
		}

		err := c.Next()

		if err != nil {
			tx.ProcessResponseHeaders(500, "HTTP/1.1")
		} else {
			tx.ProcessResponseHeaders(c.Response().StatusCode(), "HTTP/1.1")
		}

		// Map response headers back to Coraza if you want response inspection
		// c.Response().Header.VisitAll(...)

		return err
	}
}

// handleIntervention tells Fiber what to do when Coraza says "Block"
func handleIntervention(c *fiber.Ctx, it *types.Interruption) error {
	switch it.Action {
	case "drop":
		c.Status(it.Status)
		return c.Context().Conn().Close()
	case "deny":
		return c.Status(it.Status).SendString("")
	case "redirect":
		c.Redirect(it.Data)

	}

	return nil
}

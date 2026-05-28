package coraza

import (
	"io"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/gofiber/fiber/v3"
)

func parseDirectives(directives io.Reader) (string, error) {
	b, err := io.ReadAll(directives)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

func createWAF(directives string, callback func(types.MatchedRule)) (coraza.WAF, error) {
	cfg := coraza.NewWAFConfig().WithDirectives(directives)

	if callback != nil {
		cfg = cfg.WithErrorCallback(callback)
	}

	return coraza.NewWAF(cfg)
}

func clientIP(c fiber.Ctx, cfg Config) string {
	if cfg.ClientIpFromHeader {
		if ip := c.Get(cfg.ClientIpHeader); ip != "" {
			return ip
		}
	}
	return c.IP()
}

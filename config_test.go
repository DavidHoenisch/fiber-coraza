package coraza

import (
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

func TestConfigDefault(t *testing.T) {
	// 1. Test pure default
	cfg := configDefault()

	if cfg.Next != nil {
		t.Error("Expected default Next to be nil")
	}
	if cfg.Block != false {
		t.Error("Expected default Block to be false")
	}
	if cfg.Consumer == nil {
		t.Error("Expected default Consumer to be set")
	}
	if cfg.WAF == nil {
		t.Error("Expected default WAF to be initialized")
	}

	// 2. Test user override
	customDirective := "SecRule REMOTE_ADDR \"@rx .*\" \"id:100,phase:1,pass,nolog\""
	userCfg := Config{
		Block:      true,
		Directives: strings.NewReader(customDirective),
		Next:       func(c *fiber.Ctx) bool { return true },
	}

	cfgOverride := configDefault(userCfg)

	if cfgOverride.Block != true {
		t.Error("Expected Block to be overridden to true")
	}
	if cfgOverride.Next == nil {
		t.Error("Expected Next to be overridden")
	}

	// // Verify the override worked by running the Next function
	// if !cfgOverride.Next() {
	// 	t.Error("Expected Next function to return true")
	// }
}

func TestConfig_CustomWAF(t *testing.T) {
	// Test that providing a pre-built WAF instance bypasses internal creation
	// We can't easily mock the WAF interface here without mocks,
	// but we can check if the field is preserved.

	// Note: In a real test, you might mock the coraza.WAF interface.
	// For now, we check if the config accepts it.
	userCfg := Config{
		// We leave WAF nil here to ensure the logic *creates* one if missing,
		// or if we had a mock, we'd pass it here.
	}

	cfg := configDefault(userCfg)
	if cfg.WAF == nil {
		t.Error("Expected WAF to be created if nil provided")
	}
}

package coraza

import (
	"io"
	"strings"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/gofiber/fiber/v2"
)

type Config struct {
	Next func(c fiber.Ctx) bool

	// block matched requests or just log them
	Block bool

	// defines a destination to log write events to.
	// As long as the consumer implements the io.Writer
	// interface any custom logger can be used
	Consumer io.Writer

	// Call back can be used in place of, or in addition to the
	// consumer
	Callback func(types.MatchedRule)

	// Rerectives to use.
	Directives io.Reader

	// coraza firewall instance
	WAF coraza.WAF
}

var ConfigDefault = Config{
	Next:       nil,
	Block:      false,
	Consumer:   nil,
	Directives: strings.NewReader(`SecRule REMOTE_ADDR "@rx .*" "id:1,phase:1,deny,status:403"`),
	WAF:        nil,
}

func configDefault(config ...Config) Config {
	cfg := ConfigDefault

	if len(config) > 0 {
		userCfg := config[0]
		if userCfg.Next != nil {
			cfg.Next = userCfg.Next
		}
		if userCfg.Block {
			cfg.Block = true
		}
		if userCfg.Consumer != nil {
			cfg.Consumer = userCfg.Consumer
		}
		if userCfg.Callback != nil {
			cfg.Callback = userCfg.Callback
		}
		if userCfg.Directives != nil {
			cfg.Directives = userCfg.Directives
		}
	}

	if cfg.Consumer == nil {
		defaultConsumer := DefaultConsumer{}
		cfg.Consumer = &defaultConsumer
	}

	if cfg.WAF == nil {
		directivesAsString, err := parseDirectives(cfg.Directives)
		if err != nil {
			return cfg
		}

		waf, err := createWAF(directivesAsString, cfg.Callback)
		if err != nil {
			return cfg
		}
		cfg.WAF = waf
	}

	return cfg
}

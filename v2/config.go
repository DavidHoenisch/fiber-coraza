package coraza

import (
	"io"
	"log"
	"strings"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/gofiber/fiber/v2"
)

type Config struct {
	Next func(c *fiber.Ctx) bool

	// Block matched requests or just log them
	Block bool

	// Defines a destination to log write events to.
	// As long as the consumer implements the io.Writer
	// interface any custom logger can be used
	Consumer io.Writer

	// Call back can be used in place of, or in addition to the
	// consumer
	Callback func(types.MatchedRule)

	// Rerectives to use.
	Directives io.Reader

	// Coraza firewall instance
	WAF coraza.WAF

	// Defines whether to perform full body inspection
	InspectBody bool

	// Defines what whether to fail closed when an error is encounetered during
	// the processing of a request
	FailClosed bool

	// Defines if the logger should ignore connections
	// that are allowed. This is useful for reducing the
	// amount of log data from the WAF...coraza can be very
	// noisy
	LoggerIgnoreAllowEvents bool
}

var ConfigDefault = Config{
	Next:                    nil,
	Block:                   false,
	Consumer:                nil,
	Directives:              strings.NewReader(`SecRule REMOTE_ADDR "@rx .*" "id:1,phase:1,deny,status:403"`),
	WAF:                     nil,
	InspectBody:             true,
	FailClosed:              true,
	LoggerIgnoreAllowEvents: true,
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
		if userCfg.WAF != nil {
			cfg.WAF = userCfg.WAF
		}
		cfg.InspectBody = userCfg.InspectBody
		cfg.FailClosed = userCfg.FailClosed
		cfg.LoggerIgnoreAllowEvents = userCfg.LoggerIgnoreAllowEvents
	}

	if cfg.Consumer == nil {
		defaultConsumer := DefaultConsumer{}
		cfg.Consumer = &defaultConsumer
	}

	if cfg.WAF == nil {
		directivesAsString, err := parseDirectives(cfg.Directives)
		if err != nil {
			log.Fatalf("CORAZA FATAL: Error parsing directives: %v", err)
		}

		waf, err := createWAF(directivesAsString, cfg.Callback)
		if err != nil {
			log.Fatalf("CORAZA FATAL: Failed to initialize WAF: %v", err)
		}
		cfg.WAF = waf
		log.Println("CORAZA: WAF initialized successfully")
	}

	return cfg
}

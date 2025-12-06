package coraza

import (
	"fmt"
	"io"
	"log/slog"

	"github.com/corazawaf/coraza/v3"
	// txhttp "github.com/corazawaf/coraza/v3/http"
	"github.com/corazawaf/coraza/v3/types"
)

func parseDirectives(directives io.Reader) (string, error) {
	b, err := io.ReadAll(directives)
	if err != nil {
		return "", nil
	}

	return string(b), nil

}

func createWAF(directives string, callback func(types.MatchedRule)) (coraza.WAF, error) {
	cfg := coraza.NewWAFConfig().
		WithDirectives(directives)

	// Only add callback if it exists
	if callback != nil {
		cfg = cfg.WithErrorCallback(callback)
	}

	return coraza.NewWAF(cfg)
}

// Log Consumer Setup
type LogConsumer struct {
	out io.Writer
}

func NewConsumer(dest io.Writer) *LogConsumer {
	return &LogConsumer{
		out: dest,
	}
}

func (c *LogConsumer) Log(message string) {
	fmt.Fprintln(c.out, message)
}

// Default Consumer Setup
type DefaultConsumer struct {
	callback func(error types.MatchedRule)
}

func (d *DefaultConsumer) Write(p []byte) (n int, err error) {
	slog.Info(string(p))
	return len(p), nil
}

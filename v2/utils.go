package coraza

import (
	"io"

	"github.com/corazawaf/coraza/v3"
	// txhttp "github.com/corazawaf/coraza/v3/http"
	"github.com/corazawaf/coraza/v3/types"
)

func parseDirectives(directives io.Reader) (string, error) {
	b, err := io.ReadAll(directives)
	if err != nil {
		return "", err
	}

	return string(b), nil

}

func createWAF(directives string, callback func(types.MatchedRule)) (coraza.WAF, error) {
	cfg := coraza.NewWAFConfig().
		WithDirectives(directives)

	if callback != nil {
		cfg = cfg.WithErrorCallback(callback)
	}

	return coraza.NewWAF(cfg)
}

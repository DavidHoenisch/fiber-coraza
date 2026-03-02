package coraza

import (
	"fmt"
	"io"
	"log/slog"
)

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
	out io.Writer
}

func (d *DefaultConsumer) Write(p []byte) (n int, err error) {
	slog.Info(string(p))
	return len(p), nil
}

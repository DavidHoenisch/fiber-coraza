# Fiber-Coraza


⚠️Work in progress and not production ready ⚠️

A high-performance, design-first [Coraza WAF](https://coraza.io) middleware for
[Go Fiber](https://gofiber.io).

`fiber-coraza` brings the power of the OWASP Core Rule Set (CRS) and the coraza
WAD to Fiber. It is designed to be  developer-friendly, offering type-safe
configuration and powerful logging flexibility.

## Features

  * **⚡ Native Performance:** Bypasses `adaptor.HTTPHandler` to map Fiber's `fasthttp` context directly to Coraza transactions.
  * **🔍 Hybrid Logging:** Combines Fiber's fast request access with Coraza's rule logic to produce structured JSON logs with zero extra allocations.
  * **📦 Portable Rules:** Accepts generic `io.Reader` for directives, allowing rules to be compiled directly into your binary using `//go:embed`.
  * **🔌 Plug-and-Play Consumers:** Use any `io.Writer` as a log destination—no complex plugin registration required.

## Installation

```bash
go get github.com/DavidHoenisch/fiber-coraza
```

## Quick Start

```go
package main

import (
	"strings"
	"github.com/gofiber/fiber/v2"
	"github.com/DavidHoenisch/fiber-coraza"
)

func main() {
	app := fiber.New()

	// Basic configuration with a simple rule
	app.Use(coraza.NewCoraza(coraza.Config{
		// Directives can be a string reader, a file, or an embedded FS
		Directives: strings.NewReader(`
			SecRuleEngine On
			SecRule REMOTE_ADDR "@rx .*" "id:1,phase:1,deny,status:403"
		`),
		Block: true,
	}))

	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Hello, Secure World!")
	})

	app.Listen(":3000")
}
```

## Design Philosophy

### 1\. The `io.Reader` Advantage (Embedding Rules)

Unlike other WAF implementations that demand file paths (which break in Docker containers or compiled binaries), `fiber-coraza` accepts an `io.Reader` for its directives.

This allows you to use Go's `embed` package to compile your WAF rules **inside your binary**. You can ship a single executable with no external config dependencies.

**Example: Embedding OWASP CRS**

```go
package main

import (
	"embed"
	"io/fs"
	"github.com/DavidHoenisch/fiber-coraza"
)

//go:embed coraza.conf crs-setup.conf rules/*.conf
var rulesFS embed.FS

func main() {
	// Create a combined reader or open a specific file from the embedded FS
	f, _ := rulesFS.Open("coraza.conf") 
	
	app.Use(coraza.NewCoraza(coraza.Config{
		Directives: f, // Fiber-Coraza reads directly from the binary
	}))
}
```

### 2\. Hybrid Logging & Consumers

Standard Coraza logging requires registering global plugins, which makes unit
testing and custom integrations difficult.

`fiber-coraza` introduces the **Consumer** pattern. A Consumer is simply any
struct that implements `io.Writer`.

  * **Structured Data:** The middleware automatically constructs a clean JSON object containing the timestamp, client IP, method, and matched rules.
  * **Hybrid Approach:** It pulls request data (IP, URI) directly from Fiber (fast) and security decision data from Coraza.
  * **JSON Output:** The data sent to your consumer looks like this:

<!-- end list -->

```json
{
  "timestamp": "2023-10-27T10:00:00Z",
  "client_ip": "192.168.1.50",
  "request_uri": "/login",
  "action": "Block",
  "matched_rules": [
    { "id": 941100, "message": "XSS Attack Detected", "data": "<script>" }
  ]
}
```

## Configuration

| Field | Type | Description |
| :--- | :--- | :--- |
| `Directives` | `io.Reader` | Source of the Seclang configuration (Rules). |
| `Block` | `bool` | If `true`, stops the request on intervention. If `false`, logs but allows traffic. |
| `Consumer` | `io.Writer` | Destination for audit logs. Defaults to `os.Stdout`. |
| `Next` | `func(*Ctx) bool` | Filter to skip the middleware (e.g., for health check endpoints). |
| `Callback` | `func(types.MatchedRule)` | Optional low-level callback for Coraza error events. |
| `WAF` | `coraza.WAF` | Optional pre-configured WAF instance. If provided, `Directives` is ignored. |
| `InspectBody` | `bool` | If `true`, inspects the request body. Defaults to `true`. |
| `FailClosed` | `bool` | If `true`, returns 500 on internal errors (safe). If `false`, allows request (bypass). Defaults to `true`. |

## Custom Consumer Examples

Because the Consumer is just an `io.Writer`, you can easily send logs to files,
external services, or test buffers.

### 1\. File Logging

Write logs to a local file for rotation or later analysis.

```go
file, _ := os.OpenFile("waf.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)

app.Use(coraza.NewCoraza(coraza.Config{
    Consumer: file, // Logs are now written to waf.log
    // ...
}))
```

### 2\. The "Slack" Consumer (Advanced)

Since `Write` receives a byte slice of JSON, you can unmarshal it and send
alerts to external systems like Slack, Discord, or Datadog.

```go
type SlackAlerter struct {
    WebhookURL string
}

// Implement io.Writer
func (s *SlackAlerter) Write(p []byte) (n int, err error) {
    // 1. Parse the log entry to check severity
    var logEntry coraza.AuditLog
    json.Unmarshal(p, &logEntry)

    // 2. Only alert on BLOCKS
    if logEntry.Action == "Block" {
        msg := fmt.Sprintf("🚨 WAF Blocked IP %s on %s", logEntry.ClientIP, logEntry.RequestURI)
        // ... logic to POST msg to s.WebhookURL ...
    }
    
    return len(p), nil
}

// Usage
app.Use(coraza.NewCoraza(coraza.Config{
    Consumer: &SlackAlerter{WebhookURL: "https://hooks.slack.com/..."},
}))
```

### 3\. Unit Testing (Spy)

Use a `bytes.Buffer` to capture logs in your tests to assert that attacks are being detected.

```go
func TestWAF(t *testing.T) {
    logSpy := new(bytes.Buffer)
    
    app.Use(coraza.NewCoraza(coraza.Config{
        Consumer: logSpy,
        // ...
    }))
    
    // ... make request ...
    
    if !strings.Contains(logSpy.String(), "Block") {
        t.Error("Expected attack to be blocked and logged")
    }
}
```

## License

MIT

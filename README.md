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

## Essential WAF Directives

To get the most out of Coraza, you need to configure essential directives in your rule set. Here are the critical settings:

### Request Body Inspection (Forms & JSON)

**Why it's critical:** Without these directives, Coraza won't inspect POST bodies, leaving a massive security gap for attackers to exploit.

```
# Enable request body access - REQUIRED for POST/PUT/PATCH inspection
SecRequestBodyAccess On

# Maximum request body size (13MB default)
SecRequestBodyLimit 13107200

# In-memory limit before streaming to disk
SecRequestBodyInMemoryLimit 131072

# What to do when body exceeds limit
SecRequestBodyLimitAction Reject
```

### Form Data Parsing

**Automatic for URL-encoded forms:** When `Content-Type: application/x-www-form-urlencoded` is detected, Coraza automatically parses form fields into the `ARGS_POST` variable.

```
# Example rule checking form data
SecRule ARGS_POST:username "@contains admin" \
    "id:1001,phase:2,deny,status:403,msg:'Admin username detected'"
```

### JSON Request Body Parsing

**Enable JSON processing:** Add this rule to parse JSON payloads and populate `ARGS_POST` with dot-notation keys:

```
# Enable JSON body processor for application/json
SecRule REQUEST_HEADERS:Content-Type "^application/json" \
    "id:200001,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"

# Support for +json MIME types (e.g., application/vnd.api+json)
SecRule REQUEST_HEADERS:Content-Type "^application/[a-z0-9.-]+[+]json" \
    "id:200006,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"
```

**How JSON is parsed:**
- Input: `{"user": {"id": 123, "role": "admin"}, "tags": ["a", "b"]}`
- Variables created:
  - `ARGS_POST:json.user.id` = "123"
  - `ARGS_POST:json.user.role` = "admin"
  - `ARGS_POST:json.tags.0` = "a"
  - `ARGS_POST:json.tags.1` = "b"

### XML Request Body Parsing

```
# Enable XML body processor for XML content types
SecRule REQUEST_HEADERS:Content-Type "^(?:application(?:/soap\+|/)|text/)xml" \
    "id:200000,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"
```

### Body Processing Error Handling

```
# Deny requests with body processing errors (prevents evasion)
SecRule REQBODY_ERROR "!@eq 0" \
    "id:200002,phase:2,t:none,log,deny,status:400,\
    msg:'Failed to parse request body',\
    logdata:'%{reqbody_error_msg}',severity:2"

# Strict multipart validation
SecRule MULTIPART_STRICT_ERROR "!@eq 0" \
    "id:200003,phase:2,t:none,log,deny,status:400,\
    msg:'Multipart request body failed strict validation'"
```

### Rule Engine Modes

```
# DetectionOnly: Log attacks but don't block (testing mode)
SecRuleEngine DetectionOnly

# On: Actively block attacks (production mode)
SecRuleEngine On

# Off: Disable WAF completely
SecRuleEngine Off
```

### Response Body Inspection (Optional)

```
# Enable response body inspection
SecResponseBodyAccess On

# Which response types to inspect
SecResponseBodyMimeType text/plain text/html text/xml application/json

# Response body size limit (512KB)
SecResponseBodyLimit 524288

# What to do when response exceeds limit
SecResponseBodyLimitAction ProcessPartial
```

### Complete Minimal Configuration

Here's a production-ready baseline configuration:

```go
app.Use(coraza.NewCoraza(coraza.Config{
    Directives: strings.NewReader(`
        # Rule engine
        SecRuleEngine On

        # Request body settings
        SecRequestBodyAccess On
        SecRequestBodyLimit 13107200
        SecRequestBodyInMemoryLimit 131072
        SecRequestBodyLimitAction Reject

        # Enable JSON parsing
        SecRule REQUEST_HEADERS:Content-Type "^application/json" \
            "id:200001,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"

        # Enable XML parsing
        SecRule REQUEST_HEADERS:Content-Type "^(?:application(?:/soap\+|/)|text/)xml" \
            "id:200000,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"

        # Body processing error handling
        SecRule REQBODY_ERROR "!@eq 0" \
            "id:200002,phase:2,t:none,log,deny,status:400,\
            msg:'Failed to parse request body'"

        # Example security rules
        SecRule ARGS "@rx (?i:(union.*select|select.*from|insert.*into))" \
            "id:300001,phase:2,deny,status:403,msg:'SQL Injection Detected'"

        SecRule ARGS "@rx (?i:(<script|javascript:|onerror=))" \
            "id:300002,phase:2,deny,status:403,msg:'XSS Attack Detected'"
    `),
    Block: true,
    InspectBody: true,
    FailClosed: true,
}))
```

### Using OWASP Core Rule Set (CRS)

For production deployments, use the [OWASP Core Rule Set](https://coreruleset.org/):

```bash
# Download CRS
wget https://github.com/coreruleset/coreruleset/archive/v4.0.0.tar.gz
tar -xzf v4.0.0.tar.gz
```

```go
//go:embed coreruleset-4.0.0/crs-setup.conf.example
//go:embed coreruleset-4.0.0/rules/*.conf
var crsFS embed.FS

// Load CRS rules
setupFile, _ := crsFS.Open("coreruleset-4.0.0/crs-setup.conf.example")
// Combine with your custom rules and pass to Directives
```

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

## Contributing

Whether you're fixing bugs, adding features, improving documentation, or writing tests, your help is appreciated.

### Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/fiber-coraza.git
   cd fiber-coraza
   ```
3. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

### Development Setup

```bash
# Install dependencies
go mod download

# Run tests
go test -v ./...

# Run tests with coverage
go test -v -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### Contribution Guidelines

#### Code Quality

- **Write tests** for all new features and bug fixes
- **Maintain test coverage** - aim for >80% coverage on new code
- **Follow Go conventions** - run `go fmt` and `go vet` before committing
- **Keep it simple** - avoid over-engineering; prefer clear, maintainable code
- **Document public APIs** - add godoc comments for exported functions and types

#### Testing Requirements

All pull requests must include:

1. **Unit tests** demonstrating the feature or fix works
2. **Test coverage** for happy paths and error cases
3. **Integration tests** if modifying middleware behavior
4. **Security tests** if touching WAF rule processing

Example test structure:
```go
func TestNewFeature(t *testing.T) {
    app := fiber.New()

    app.Use(NewCoraza(Config{
        Directives: strings.NewReader(`/* your rules */`),
        Block: true,
    }))

    // Test safe request
    req := httptest.NewRequest("GET", "/test", nil)
    resp, err := app.Test(req)
    utils.AssertEqual(t, nil, err)
    utils.AssertEqual(t, 200, resp.StatusCode)
}
```

#### Commit Messages

Follow conventional commits format:

```
type(scope): short description

Longer description if needed.

Fixes #issue-number
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `test`: Adding or updating tests
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `chore`: Maintenance tasks

Examples:
```
feat(middleware): add support for response body inspection
fix(logging): prevent race condition in audit log writer
docs(readme): add JSON parsing configuration examples
test(body): add SQL injection detection tests
```

### Pull Request Process

1. **Update documentation** if you're changing behavior or adding features
2. **Add yourself to contributors** if it's your first contribution
3. **Ensure all tests pass**: `go test ./...`
4. **Create a pull request** with a clear description of changes
5. **Respond to review feedback** promptly

### Areas We Need Help With

- 🧪 **More test coverage** - especially edge cases and error scenarios
- 📚 **Documentation improvements** - tutorials, examples, use cases
- 🔍 **Security testing** - fuzzing, penetration testing, security audits
- 🚀 **Performance optimization** - benchmarking and profiling
- 🌐 **OWASP CRS integration** - better examples and helpers
- 🐛 **Bug fixes** - check our [issues](https://github.com/DavidHoenisch/fiber-coraza/issues)

### Reporting Issues

When reporting bugs, please include:

- Go version (`go version`)
- Fiber version
- Coraza version
- Minimal reproduction code
- Expected vs actual behavior
- Any relevant logs or error messages

### Questions or Ideas?

- 💬 **Open a discussion** for questions or feature proposals
- 🐛 **Open an issue** for bug reports
- 💡 **Open a PR** for contributions

## License

MIT

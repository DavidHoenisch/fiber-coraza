package coraza

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/utils"
)

// TestFormData_URLEncoded_SafeRequest tests that safe form data passes through
func TestFormData_URLEncoded_SafeRequest(t *testing.T) {
	app := fiber.New()

	rules := `
		SecRuleEngine On
		SecRequestBodyAccess On
		SecRule ARGS_POST:username "@contains admin" "id:1001,phase:2,deny,status:403,msg:'Admin username detected'"
	`

	app.Use(NewCoraza(Config{
		Directives:  strings.NewReader(rules),
		Block:       true,
		InspectBody: true,
	}))

	app.Post("/login", func(c *fiber.Ctx) error {
		return c.SendString("Login successful")
	})

	req := httptest.NewRequest("POST", "/login", strings.NewReader("username=john&password=secret123"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := app.Test(req)

	utils.AssertEqual(t, nil, err)
	utils.AssertEqual(t, 200, resp.StatusCode)
}

// TestFormData_URLEncoded_BlockMalicious tests that malicious form data is blocked
func TestFormData_URLEncoded_BlockMalicious(t *testing.T) {
	app := fiber.New()

	rules := `
		SecRuleEngine On
		SecRequestBodyAccess On
		SecRule ARGS_POST:username "@contains admin" "id:1002,phase:2,deny,status:403,msg:'Admin username detected'"
	`

	app.Use(NewCoraza(Config{
		Directives:  strings.NewReader(rules),
		Block:       true,
		InspectBody: true,
	}))

	app.Post("/login", func(c *fiber.Ctx) error {
		return c.SendString("Should not be reached")
	})

	req := httptest.NewRequest("POST", "/login", strings.NewReader("username=admin&password=password123"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := app.Test(req)

	utils.AssertEqual(t, nil, err)
	utils.AssertEqual(t, 403, resp.StatusCode)
}

// TestFormData_SQLInjection_Detected tests that SQL injection in form data is detected and blocked
func TestFormData_SQLInjection_Detected(t *testing.T) {
	app := fiber.New()

	// Common SQL injection detection rule
	rules := `
		SecRuleEngine On
		SecRequestBodyAccess On
		SecRule ARGS_POST "@rx (?i:(union.*select|select.*from|insert.*into|delete.*from|drop.*table|' or '.*=|' or 1=1|admin'--|\d+.*or.*\d+=))" "id:2001,phase:2,deny,status:403,msg:'SQL Injection Detected in POST parameter'"
	`

	app.Use(NewCoraza(Config{
		Directives:  strings.NewReader(rules),
		Block:       true,
		InspectBody: true,
	}))

	app.Post("/search", func(c *fiber.Ctx) error {
		return c.SendString("Should not be reached")
	})

	testCases := []struct {
		name    string
		payload string
	}{
		{
			name:    "Classic OR 1=1",
			payload: "query=' OR '1'='1",
		},
		{
			name:    "UNION SELECT",
			payload: "id=1 UNION SELECT username,password FROM users",
		},
		{
			name:    "SQL Comment Injection",
			payload: "username=admin'--",
		},
		{
			name:    "Stacked Queries",
			payload: "id=1; DROP TABLE users",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/search", strings.NewReader(tc.payload))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			resp, err := app.Test(req)

			utils.AssertEqual(t, nil, err)
			utils.AssertEqual(t, 403, resp.StatusCode, "Expected SQLi to be blocked")
		})
	}
}

// TestJSON_SafeRequest tests that safe JSON payloads pass through
func TestJSON_SafeRequest(t *testing.T) {
	app := fiber.New()

	rules := `
		SecRuleEngine On
		SecRequestBodyAccess On
		SecRule REQUEST_HEADERS:Content-Type "^application/json" "id:3000,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"
		SecRule ARGS_POST:json.username "@contains admin" "id:3001,phase:2,deny,status:403,msg:'Admin username detected in JSON'"
	`

	app.Use(NewCoraza(Config{
		Directives:  strings.NewReader(rules),
		Block:       true,
		InspectBody: true,
	}))

	app.Post("/api/login", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "success"})
	})

	jsonPayload := `{"username": "john", "password": "secret123"}`
	req := httptest.NewRequest("POST", "/api/login", strings.NewReader(jsonPayload))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)

	utils.AssertEqual(t, nil, err)
	utils.AssertEqual(t, 200, resp.StatusCode)
}

// TestJSON_BlockMalicious tests that malicious JSON payloads are blocked
func TestJSON_BlockMalicious(t *testing.T) {
	app := fiber.New()

	rules := `
		SecRuleEngine On
		SecRequestBodyAccess On
		SecRule REQUEST_HEADERS:Content-Type "^application/json" "id:3100,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"
		SecRule ARGS_POST:json.username "@contains admin" "id:3101,phase:2,deny,status:403,msg:'Admin username detected in JSON'"
	`

	app.Use(NewCoraza(Config{
		Directives:  strings.NewReader(rules),
		Block:       true,
		InspectBody: true,
	}))

	app.Post("/api/login", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "Should not be reached"})
	})

	jsonPayload := `{"username": "admin", "password": "password123"}`
	req := httptest.NewRequest("POST", "/api/login", strings.NewReader(jsonPayload))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)

	utils.AssertEqual(t, nil, err)
	utils.AssertEqual(t, 403, resp.StatusCode)
}

// TestJSON_SQLInjection_Detected tests that SQL injection in JSON payloads is detected and blocked
func TestJSON_SQLInjection_Detected(t *testing.T) {
	app := fiber.New()

	rules := `
		SecRuleEngine On
		SecRequestBodyAccess On
		SecRule REQUEST_HEADERS:Content-Type "^application/json" "id:3200,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"
		SecRule ARGS_POST "@rx (?i:(union.*select|select.*from|insert.*into|delete.*from|drop.*table|' or '.*=|' or 1=1|admin'--|\d+.*or.*\d+=))" "id:3201,phase:2,deny,status:403,msg:'SQL Injection Detected in JSON parameter'"
	`

	app.Use(NewCoraza(Config{
		Directives:  strings.NewReader(rules),
		Block:       true,
		InspectBody: true,
	}))

	app.Post("/api/search", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "Should not be reached"})
	})

	testCases := []struct {
		name    string
		payload string
	}{
		{
			name:    "SQLi in username field",
			payload: `{"username": "admin' OR '1'='1", "password": "test"}`,
		},
		{
			name:    "SQLi in search query",
			payload: `{"search": "test' UNION SELECT * FROM users--"}`,
		},
		{
			name:    "SQLi in nested object",
			payload: `{"user": {"id": "1' OR '1'='1", "name": "test"}}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/api/search", strings.NewReader(tc.payload))
			req.Header.Set("Content-Type", "application/json")
			resp, err := app.Test(req)

			utils.AssertEqual(t, nil, err)
			utils.AssertEqual(t, 403, resp.StatusCode, "Expected SQLi in JSON to be blocked")
		})
	}
}

// TestJSON_NestedObjects tests that nested JSON objects are properly inspected
func TestJSON_NestedObjects(t *testing.T) {
	app := fiber.New()

	rules := `
		SecRuleEngine On
		SecRequestBodyAccess On
		SecRule REQUEST_HEADERS:Content-Type "^application/json" "id:3300,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"
		SecRule ARGS_POST:json.profile.role "@streq superadmin" "id:3301,phase:2,deny,status:403,msg:'Superadmin role not allowed'"
	`

	app.Use(NewCoraza(Config{
		Directives:  strings.NewReader(rules),
		Block:       true,
		InspectBody: true,
	}))

	app.Post("/api/user", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "created"})
	})

	// Safe nested JSON
	safePayload := `{"username": "john", "profile": {"role": "user", "age": 25}}`
	req1 := httptest.NewRequest("POST", "/api/user", strings.NewReader(safePayload))
	req1.Header.Set("Content-Type", "application/json")
	resp1, err1 := app.Test(req1)

	utils.AssertEqual(t, nil, err1)
	utils.AssertEqual(t, 200, resp1.StatusCode, "Safe nested JSON should pass")

	// Malicious nested JSON
	maliciousPayload := `{"username": "hacker", "profile": {"role": "superadmin", "age": 30}}`
	req2 := httptest.NewRequest("POST", "/api/user", strings.NewReader(maliciousPayload))
	req2.Header.Set("Content-Type", "application/json")
	resp2, err2 := app.Test(req2)

	utils.AssertEqual(t, nil, err2)
	utils.AssertEqual(t, 403, resp2.StatusCode, "Malicious nested JSON should be blocked")
}

// TestJSON_Arrays tests that JSON arrays are properly inspected
func TestJSON_Arrays(t *testing.T) {
	app := fiber.New()

	rules := `
		SecRuleEngine On
		SecRequestBodyAccess On
		SecRule REQUEST_HEADERS:Content-Type "^application/json" "id:3400,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"
		SecRule ARGS_POST:json.tags.0 "@streq malicious" "id:3401,phase:2,deny,status:403,msg:'Malicious tag detected'"
	`

	app.Use(NewCoraza(Config{
		Directives:  strings.NewReader(rules),
		Block:       true,
		InspectBody: true,
	}))

	app.Post("/api/post", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "created"})
	})

	// Safe array
	safePayload := `{"title": "My Post", "tags": ["news", "tech"]}`
	req1 := httptest.NewRequest("POST", "/api/post", strings.NewReader(safePayload))
	req1.Header.Set("Content-Type", "application/json")
	resp1, err1 := app.Test(req1)

	utils.AssertEqual(t, nil, err1)
	utils.AssertEqual(t, 200, resp1.StatusCode, "Safe array should pass")

	// Malicious array
	maliciousPayload := `{"title": "Bad Post", "tags": ["malicious", "spam"]}`
	req2 := httptest.NewRequest("POST", "/api/post", strings.NewReader(maliciousPayload))
	req2.Header.Set("Content-Type", "application/json")
	resp2, err2 := app.Test(req2)

	utils.AssertEqual(t, nil, err2)
	utils.AssertEqual(t, 403, resp2.StatusCode, "Malicious array should be blocked")
}

// TestXSS_Detection tests that XSS attacks are detected in form data
func TestXSS_Detection(t *testing.T) {
	app := fiber.New()

	rules := `
		SecRuleEngine On
		SecRequestBodyAccess On
		SecRule ARGS_POST "@rx (?i:<script|javascript:|onerror=|onload=|<iframe)" "id:4001,phase:2,deny,status:403,msg:'XSS Attack Detected'"
	`

	app.Use(NewCoraza(Config{
		Directives:  strings.NewReader(rules),
		Block:       true,
		InspectBody: true,
	}))

	app.Post("/comment", func(c *fiber.Ctx) error {
		return c.SendString("Should not be reached")
	})

	testCases := []struct {
		name    string
		payload string
	}{
		{
			name:    "Script tag injection",
			payload: "comment=<script>alert('XSS')</script>",
		},
		{
			name:    "Event handler injection",
			payload: "comment=<img src=x onerror=alert('XSS')>",
		},
		{
			name:    "JavaScript protocol",
			payload: "url=javascript:alert('XSS')",
		},
		{
			name:    "Iframe injection",
			payload: "content=<iframe src='evil.com'>",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/comment", strings.NewReader(tc.payload))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			resp, err := app.Test(req)

			utils.AssertEqual(t, nil, err)
			utils.AssertEqual(t, 403, resp.StatusCode, "Expected XSS to be blocked")
		})
	}
}

// TestMultipleFields_FormData tests inspection of multiple form fields
func TestMultipleFields_FormData(t *testing.T) {
	app := fiber.New()

	rules := `
		SecRuleEngine On
		SecRequestBodyAccess On
		SecRule ARGS_POST:email "@rx (?i:admin@|root@)" "id:5001,phase:2,deny,status:403,msg:'Privileged email detected'"
		SecRule ARGS_POST:password "@rx ^.{1,7}$" "id:5002,phase:2,deny,status:400,msg:'Password too short'"
	`

	app.Use(NewCoraza(Config{
		Directives:  strings.NewReader(rules),
		Block:       true,
		InspectBody: true,
	}))

	app.Post("/register", func(c *fiber.Ctx) error {
		return c.SendString("Registration successful")
	})

	// Test 1: Valid registration
	req1 := httptest.NewRequest("POST", "/register", strings.NewReader("username=john&email=john@example.com&password=securepass123"))
	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp1, _ := app.Test(req1)
	utils.AssertEqual(t, 200, resp1.StatusCode, "Valid registration should pass")

	// Test 2: Admin email blocked
	req2 := httptest.NewRequest("POST", "/register", strings.NewReader("username=hacker&email=admin@example.com&password=securepass123"))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp2, _ := app.Test(req2)
	utils.AssertEqual(t, 403, resp2.StatusCode, "Admin email should be blocked")

	// Test 3: Short password blocked
	req3 := httptest.NewRequest("POST", "/register", strings.NewReader("username=john&email=john@example.com&password=short"))
	req3.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp3, _ := app.Test(req3)
	utils.AssertEqual(t, 400, resp3.StatusCode, "Short password should be blocked")
}

// TestPUT_PATCH_Methods tests that body inspection works for PUT and PATCH methods
func TestPUT_PATCH_Methods(t *testing.T) {
	app := fiber.New()

	rules := `
		SecRuleEngine On
		SecRequestBodyAccess On
		SecRule ARGS_POST:role "@streq admin" "id:6001,phase:2,deny,status:403,msg:'Admin role modification not allowed'"
	`

	app.Use(NewCoraza(Config{
		Directives:  strings.NewReader(rules),
		Block:       true,
		InspectBody: true,
	}))

	app.Put("/user/:id", func(c *fiber.Ctx) error {
		return c.SendString("Updated")
	})

	app.Patch("/user/:id", func(c *fiber.Ctx) error {
		return c.SendString("Patched")
	})

	// Test PUT with safe data
	req1 := httptest.NewRequest("PUT", "/user/123", strings.NewReader("role=user"))
	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp1, _ := app.Test(req1)
	utils.AssertEqual(t, 200, resp1.StatusCode, "Safe PUT should pass")

	// Test PUT with malicious data
	req2 := httptest.NewRequest("PUT", "/user/123", strings.NewReader("role=admin"))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp2, _ := app.Test(req2)
	utils.AssertEqual(t, 403, resp2.StatusCode, "Malicious PUT should be blocked")

	// Test PATCH with safe data
	req3 := httptest.NewRequest("PATCH", "/user/123", strings.NewReader("role=user"))
	req3.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp3, _ := app.Test(req3)
	utils.AssertEqual(t, 200, resp3.StatusCode, "Safe PATCH should pass")

	// Test PATCH with malicious data
	req4 := httptest.NewRequest("PATCH", "/user/123", strings.NewReader("role=admin"))
	req4.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp4, _ := app.Test(req4)
	utils.AssertEqual(t, 403, resp4.StatusCode, "Malicious PATCH should be blocked")
}

// TestBodyLimit_Rejected tests that oversized bodies trigger rejection
func TestBodyLimit_Rejected(t *testing.T) {
	app := fiber.New()

	rules := `
		SecRuleEngine On
		SecRequestBodyAccess On
		SecRequestBodyLimit 10
		SecRequestBodyLimitAction Reject
	`

	app.Use(NewCoraza(Config{
		Directives:  strings.NewReader(rules),
		Block:       true,
		InspectBody: true,
	}))

	app.Post("/upload", func(c *fiber.Ctx) error {
		return c.SendString("Uploaded")
	})

	// Send body larger than limit to trigger rejection
	largeBody := strings.Repeat("A", 1000)
	req := httptest.NewRequest("POST", "/upload", strings.NewReader(largeBody))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := app.Test(req)

	utils.AssertEqual(t, nil, err)
	// Coraza returns 413 (Request Entity Too Large) when body limit is exceeded
	utils.AssertEqual(t, 413, resp.StatusCode, "Should reject oversized body")
}

// TestBodyLimit_ProcessPartial tests that oversized bodies can be partially processed
func TestBodyLimit_ProcessPartial(t *testing.T) {
	app := fiber.New()

	rules := `
		SecRuleEngine On
		SecRequestBodyAccess On
		SecRequestBodyLimit 50
		SecRequestBodyLimitAction ProcessPartial
	`

	app.Use(NewCoraza(Config{
		Directives:  strings.NewReader(rules),
		Block:       true,
		InspectBody: true,
	}))

	app.Post("/upload", func(c *fiber.Ctx) error {
		return c.SendString("Uploaded")
	})

	// Send body larger than limit but with ProcessPartial action
	largeBody := strings.Repeat("A", 1000)
	req := httptest.NewRequest("POST", "/upload", strings.NewReader(largeBody))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := app.Test(req)

	utils.AssertEqual(t, nil, err)
	// With ProcessPartial, the request should be allowed (first 50 bytes are processed)
	utils.AssertEqual(t, 200, resp.StatusCode, "Should process partial body and allow request")
}

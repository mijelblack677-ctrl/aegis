package activescan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/mijelblack677-ctrl/aegis/internal/modules"
	"github.com/mijelblack677-ctrl/aegis/internal/output"
)

type NoSQLiFuzzer struct {
	payloads []map[string]interface{}
}

func NewNoSQLiFuzzer() *NoSQLiFuzzer {
	return &NoSQLiFuzzer{
		payloads: []map[string]interface{}{
			{"$ne": ""},
			{"$gt": ""},
			{"$regex": ".*"},
			{"$exists": true},
			{"$where": "1"},
			{"$or": []interface{}{map[string]interface{}{"$eq": "admin"}, map[string]interface{}{"$regex": ".*"}}},
			{"username": map[string]interface{}{"$ne": nil}, "password": map[string]interface{}{"$ne": nil}},
			{"$where": "sleep(5000)"},
		},
	}
}

func (n *NoSQLiFuzzer) Name() string    { return "nosqli_fuzzer" }
func (n *NoSQLiFuzzer) IsPassive() bool { return false }

func (n *NoSQLiFuzzer) Run(pair *modules.RequestResponsePair) ([]*output.Vulnerability, error) {
	var vulns []*output.Vulnerability

	ct := pair.Request.Header.Get("Content-Type")
	if !strings.Contains(ct, "json") {
		return vulns, nil
	}

	if pair.RequestBody == nil {
		return vulns, nil
	}

	// Parse original JSON
	var originalData map[string]interface{}
	if err := json.Unmarshal(pair.RequestBody, &originalData); err != nil {
		return vulns, nil
	}

	urlStr := pair.Request.URL.String()
	client := &http.Client{}

	// Get baseline
	baselineReq, _ := http.NewRequest(pair.Request.Method, urlStr, bytes.NewReader(pair.RequestBody))
	copyHeaders(pair.Request, baselineReq)
	baselineResp, err := client.Do(baselineReq)
	if err != nil {
		return vulns, nil
	}
	baselineBody, _ := io.ReadAll(baselineResp.Body)
	baselineResp.Body.Close()

	// Test NoSQL injections
	for _, payload := range n.payloads {
		// Try injecting payload at each parameter
		for key := range originalData {
			testData := make(map[string]interface{})
			for k, v := range originalData {
				if k == key {
					testData[k] = payload
				} else {
					testData[k] = v
				}
			}

			testBody, _ := json.Marshal(testData)
			testReq, _ := http.NewRequest(pair.Request.Method, urlStr, bytes.NewReader(testBody))
			copyHeaders(pair.Request, testReq)

			testResp, err := client.Do(testReq)
			if err != nil {
				continue
			}
			testBody2, _ := io.ReadAll(testResp.Body)
			testResp.Body.Close()

			// Detect anomalies
			if len(testBody2) != len(baselineBody) && testResp.StatusCode < 500 {
				vulns = append(vulns, &output.Vulnerability{
					Name:        "NoSQL Injection Detected",
					Description: fmt.Sprintf("Parameter '%s' appears vulnerable to NoSQL injection. Payload type: $%s", key, getPayloadType(payload)),
					Severity:    output.SeverityCritical,
					URL:         urlStr,
					Method:      pair.Request.Method,
					Parameter:   key,
					Evidence: output.Evidence{
						Request:        string(testBody),
						ProofOfConcept: fmt.Sprintf("Inject NoSQL operator in '%s' parameter", key),
					},
					Remediation: "Sanitize user input and use an ODM/ORM with proper input validation.",
					Tags:        []string{"nosqli", "injection", "critical", "goldmine"},
				})
				return vulns, nil
			}
		}
	}

	return vulns, nil
}

func copyHeaders(src *http.Request, dst *http.Request) {
	for key, values := range src.Header {
		for _, v := range values {
			dst.Header.Add(key, v)
		}
	}
}

func getPayloadType(payload map[string]interface{}) string {
	for k := range payload {
		if strings.HasPrefix(k, "$") {
			return k
		}
	}
	return "unknown"
}

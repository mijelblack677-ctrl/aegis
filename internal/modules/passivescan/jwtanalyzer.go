package passivescan

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mijelblack677-ctrl/aegis/internal/modules"
	"github.com/mijelblack677-ctrl/aegis/internal/output"
)

type JWTAnalyzer struct{}

func NewJWTAnalyzer() *JWTAnalyzer {
	return &JWTAnalyzer{}
}

func (j *JWTAnalyzer) Name() string    { return "jwt_analyzer" }
func (j *JWTAnalyzer) IsPassive() bool { return true }

func (j *JWTAnalyzer) Run(pair *modules.RequestResponsePair) ([]*output.Vulnerability, error) {
	var vulns []*output.Vulnerability

	// Check Authorization header
	authHeader := pair.Request.Header.Get("Authorization")
	if authHeader == "" && pair.Response != nil {
		authHeader = pair.Response.Header.Get("Authorization")
	}

	var jwtToken string
	if strings.HasPrefix(authHeader, "Bearer ") {
		jwtToken = strings.TrimPrefix(authHeader, "Bearer ")
	} else if pair.ResponseBody != nil && len(pair.ResponseBody) > 20 {
		jwtToken = extractJWTFromBody(string(pair.ResponseBody))
	}

	if jwtToken == "" || !isJWT(jwtToken) {
		return vulns, nil
	}

	parts := strings.Split(jwtToken, ".")
	if len(parts) < 3 {
		return vulns, nil
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return vulns, nil
	}
	var header map[string]interface{}
	json.Unmarshal(headerJSON, &header)

	url := pair.Request.URL.String()

	if alg, ok := header["alg"]; ok && alg == "none" {
		vulns = append(vulns, &output.Vulnerability{
			Name:        "JWT Algorithm None Attack",
			Description: "JWT uses 'alg: none' which allows signature bypass.",
			Severity:    output.SeverityCritical,
			URL:         url,
			Evidence: output.Evidence{
				ProofOfConcept: fmt.Sprintf("JWT Header: %s", string(headerJSON)),
			},
			Remediation: "Reject tokens with 'alg: none'.",
			Tags:        []string{"jwt", "algorithm-none", "critical", "goldmine"},
		})
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return vulns, nil
	}
	var payload map[string]interface{}
	json.Unmarshal(payloadJSON, &payload)

	sensitiveFields := []string{"password", "ssn", "credit_card", "secret", "api_key"}
	for _, field := range sensitiveFields {
		if _, exists := payload[field]; exists {
			vulns = append(vulns, &output.Vulnerability{
				Name:        fmt.Sprintf("Sensitive Data in JWT: %s", field),
				Description: fmt.Sprintf("JWT payload contains sensitive field '%s'. JWTs are encoded, not encrypted.", field),
				Severity:    output.SeverityHigh,
				URL:         url,
				Evidence: output.Evidence{
					ProofOfConcept: fmt.Sprintf("JWT payload contains: %s", field),
				},
				Remediation: "Never store sensitive data in JWT payloads.",
				Tags:        []string{"jwt", "sensitive-data-exposure"},
			})
		}
	}

	return vulns, nil
}

func isJWT(token string) bool {
	parts := strings.Split(token, ".")
	return len(parts) == 3 && len(token) > 20
}

func extractJWTFromBody(body string) string {
	if len(body) < 20 {
		return ""
	}
	// Look for JWT pattern safely
	maxLen := len(body) - 20
	for i := 0; i < maxLen; i++ {
		end := i + 50
		if end > len(body) {
			end = len(body)
		}
		substr := body[i:end]
		if strings.Count(substr, ".") >= 2 {
			// Found potential JWT, extract the full token
			candidate := body[i:]
			for j, c := range candidate {
				if c == ' ' || c == '\n' || c == '\r' || c == '\t' || c == '"' || c == '\'' || c == ',' {
					candidate = candidate[:j]
					break
				}
			}
			if isJWT(candidate) {
				return candidate
			}
		}
	}
	return ""
}

package engine

import (
	"strings"

	"github.com/mijelblack677-ctrl/aegis/internal/output"
)

type SeverityScorer struct{}

func NewSeverityScorer() *SeverityScorer {
	return &SeverityScorer{}
}

// AdjustSeverity modifies severity based on context
func (s *SeverityScorer) AdjustSeverity(vuln *output.Vulnerability, url, responseBody string) output.Severity {
	severity := vuln.Severity

	// Check if secret is in API response (data) vs source code
	if strings.Contains(vuln.Name, "Hardcoded Secret") {
		if strings.Contains(url, "/api/") && isJSONResponse(responseBody) {
			// Secrets in API responses are data leakage, still critical but different context
			severity = output.SeverityHigh
		}
	}

	// Elevate XSS severity if HttpOnly is missing
	if strings.Contains(vuln.Name, "XSS") && severity == output.SeverityMedium {
		if strings.Contains(strings.ToLower(responseBody), "httponly") == false {
			severity = output.SeverityHigh // XSS + no HttpOnly = session theft possible
		}
	}

	// Elevate SQLi severity on login pages
	if strings.Contains(vuln.Name, "SQL Injection") && isLoginEndpoint(url, "") {
		severity = output.SeverityCritical
	}

	// Downgrade missing security headers on static files
	if strings.Contains(vuln.Name, "Missing Security Header") {
		if strings.HasSuffix(url, ".js") || strings.HasSuffix(url, ".css") || 
		   strings.HasSuffix(url, ".png") || strings.HasSuffix(url, ".jpg") {
			severity = output.SeverityInfo
		}
	}

	// Elevate IDOR that leaks sensitive data
	if strings.Contains(vuln.Name, "IDOR") {
		if strings.Contains(responseBody, "ssn") || strings.Contains(responseBody, "api_key") ||
		   strings.Contains(responseBody, "password") || strings.Contains(responseBody, "secret") {
			severity = output.SeverityCritical
		}
	}

	return severity
}

func isJSONResponse(body string) bool {
	trimmed := strings.TrimSpace(body)
	return strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")
}

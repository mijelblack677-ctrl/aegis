package passivescan

import (
	"fmt"
	"strings"

	"github.com/mijelblack677-ctrl/aegis/internal/modules"
	"github.com/mijelblack677-ctrl/aegis/internal/output"
)

type HeaderAnalyzer struct{}

func NewHeaderAnalyzer() *HeaderAnalyzer {
	return &HeaderAnalyzer{}
}

func (ha *HeaderAnalyzer) Name() string    { return "header_analyzer" }
func (ha *HeaderAnalyzer) IsPassive() bool { return true }

func (ha *HeaderAnalyzer) Run(pair *modules.RequestResponsePair) ([]*output.Vulnerability, error) {
	var vulns []*output.Vulnerability

	if pair.Response == nil {
		return vulns, nil
	}

	url := pair.Request.URL.String()
	headers := pair.Response.Header

	securityHeaders := map[string]string{
		"X-Frame-Options":                   "Protects against clickjacking attacks",
		"X-Content-Type-Options":            "Prevents MIME type sniffing",
		"Content-Security-Policy":           "Mitigates XSS and data injection attacks",
		"Strict-Transport-Security":         "Enforces HTTPS connections",
		"Referrer-Policy":                   "Controls referrer information",
		"Permissions-Policy":                "Controls browser features",
	}

	for header, description := range securityHeaders {
		if headers.Get(header) == "" {
			vulns = append(vulns, &output.Vulnerability{
				Name:        fmt.Sprintf("Missing Security Header: %s", header),
				Description: description,
				Severity:    output.SeverityLow,
				URL:         url,
				Evidence: output.Evidence{
					ProofOfConcept: fmt.Sprintf("Header %s not present", header),
				},
				Remediation: fmt.Sprintf("Add the %s header to all responses.", header),
				Tags:        []string{"security-headers", "missing-header"},
			})
		}
	}

	serverHeader := headers.Get("Server")
	if serverHeader != "" {
		vulns = append(vulns, &output.Vulnerability{
			Name:        "Server Information Disclosure",
			Description: fmt.Sprintf("Server reveals: %s", serverHeader),
			Severity:    output.SeverityInfo,
			URL:         url,
			Evidence: output.Evidence{
				ProofOfConcept: fmt.Sprintf("Server: %s", serverHeader),
			},
			Remediation: "Remove or obfuscate the Server header.",
			Tags:        []string{"information-disclosure"},
		})
	}

	origin := headers.Get("Access-Control-Allow-Origin")
	if origin == "*" {
		vulns = append(vulns, &output.Vulnerability{
			Name:        "CORS Misconfiguration: Wildcard Origin",
			Description: "The server allows requests from any origin.",
			Severity:    output.SeverityHigh,
			URL:         url,
			Evidence: output.Evidence{
				ProofOfConcept: "Access-Control-Allow-Origin: *",
			},
			Remediation: "Restrict allowed origins to trusted domains.",
			Tags:        []string{"cors", "misconfiguration"},
		})
	}

	if origin != "" && origin != "*" && strings.Contains(origin, pair.Request.Host) {
		vulns = append(vulns, &output.Vulnerability{
			Name:        "CORS Origin Reflection Detected",
			Description: fmt.Sprintf("Server reflects Origin: %s", origin),
			Severity:    output.SeverityMedium,
			URL:         url,
			Evidence: output.Evidence{
				ProofOfConcept: fmt.Sprintf("Access-Control-Allow-Origin: %s", origin),
			},
			Remediation: "Use a whitelist of allowed origins.",
			Tags:        []string{"cors", "origin-reflection"},
		})
	}

	return vulns, nil
}

package passivescan

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/mijelblack677-ctrl/aegis/internal/modules"
	"github.com/mijelblack677-ctrl/aegis/internal/output"
)

type EndpointAnalyzer struct {
	apiPatterns []string
}

func NewEndpointAnalyzer() *EndpointAnalyzer {
	return &EndpointAnalyzer{
		apiPatterns: []string{
			"/api/",
			"/graphql",
			"/swagger",
			"/openapi",
			"/v1/",
			"/v2/",
			"/rest/",
		},
	}
}

func (ea *EndpointAnalyzer) Name() string    { return "endpoint_analyzer" }
func (ea *EndpointAnalyzer) IsPassive() bool { return true }

func (ea *EndpointAnalyzer) Run(pair *modules.RequestResponsePair) ([]*output.Vulnerability, error) {
	var vulns []*output.Vulnerability
	
	if pair.ParsedData == nil {
		return vulns, nil
	}
	
	urlStr := pair.Request.URL.String()
	
	// Analyze discovered endpoints
	for _, endpoint := range pair.ParsedData.Endpoints {
		vulns = append(vulns, ea.analyzeEndpoint(endpoint, urlStr)...)
	}
	
	// Check if current URL is an API endpoint
	vulns = append(vulns, ea.analyzeEndpoint(urlStr, urlStr)...)
	
	return vulns, nil
}

func (ea *EndpointAnalyzer) analyzeEndpoint(endpoint, sourceURL string) []*output.Vulnerability {
	var vulns []*output.Vulnerability
	
	// Check for API endpoint exposure
	for _, pattern := range ea.apiPatterns {
		if strings.Contains(strings.ToLower(endpoint), pattern) {
			vulns = append(vulns, &output.Vulnerability{
				Name:        fmt.Sprintf("API Endpoint Discovered: %s", endpoint),
				Description: fmt.Sprintf("An API endpoint matching pattern '%s' was discovered. This may expose sensitive functionality.", pattern),
				Severity:    output.SeverityInfo,
				URL:         sourceURL,
				Evidence: output.Evidence{
					ProofOfConcept: fmt.Sprintf("Discovered endpoint: %s", endpoint),
				},
				Remediation: "Ensure API endpoints are properly authenticated and authorized.",
				Tags:        []string{"api-endpoint", "discovery"},
			})
		}
	}
	
	// Check for sensitive file extensions
	sensitiveExts := []string{".json", ".xml", ".yaml", ".yml", ".env", ".config", ".bak", ".backup", ".sql", ".db"}
	for _, ext := range sensitiveExts {
		if strings.HasSuffix(strings.ToLower(endpoint), ext) {
			vulns = append(vulns, &output.Vulnerability{
				Name:        fmt.Sprintf("Potentially Sensitive File Extension: %s", endpoint),
				Description: fmt.Sprintf("An endpoint with sensitive extension '%s' was found.", ext),
				Severity:    output.SeverityMedium,
				URL:         sourceURL,
				Evidence: output.Evidence{
					ProofOfConcept: fmt.Sprintf("Sensitive extension: %s", endpoint),
				},
				Remediation: "Remove or protect files with sensitive extensions from public access.",
				Tags:        []string{"sensitive-file", "discovery"},
			})
		}
	}
	
	// Check for debug endpoints
	debugPatterns := []string{"/debug", "/test", "/dev", "/staging", "/admin", "/console", "/phpinfo", "/info"}
	for _, pattern := range debugPatterns {
		if strings.Contains(strings.ToLower(endpoint), pattern) {
			vulns = append(vulns, &output.Vulnerability{
				Name:        fmt.Sprintf("Debug/Admin Endpoint Found: %s", endpoint),
				Description: fmt.Sprintf("A debug or administrative endpoint was discovered: %s", endpoint),
				Severity:    output.SeverityMedium,
				URL:         sourceURL,
				Evidence: output.Evidence{
					ProofOfConcept: fmt.Sprintf("Debug endpoint: %s", endpoint),
				},
				Remediation: "Remove debug endpoints from production or protect them with strong authentication.",
				Tags:        []string{"debug-endpoint", "exposure"},
			})
		}
	}
	
	// Parse the endpoint for sensitive query parameters
	if parsedURL, err := url.Parse(endpoint); err == nil {
		for param := range parsedURL.Query() {
			sensitiveParams := []string{"token", "key", "secret", "password", "auth", "api_key", "apikey", "access_token"}
			for _, sensitive := range sensitiveParams {
				if strings.EqualFold(param, sensitive) {
					vulns = append(vulns, &output.Vulnerability{
						Name:        fmt.Sprintf("Sensitive Parameter in URL: %s", param),
						Description: fmt.Sprintf("The parameter '%s' appears in the URL. This could expose sensitive data in logs and referrer headers.", param),
						Severity:    output.SeverityMedium,
						URL:         sourceURL,
						Parameter:   param,
						Evidence: output.Evidence{
							ProofOfConcept: fmt.Sprintf("Parameter %s found in URL: %s", param, endpoint),
						},
						Remediation: "Use POST method for sensitive parameters and never include them in URLs.",
						Tags:        []string{"sensitive-parameter", "information-disclosure"},
					})
				}
			}
		}
	}
	
	return vulns
}
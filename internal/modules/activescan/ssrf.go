package activescan

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/mijelblack677-ctrl/aegis/internal/modules"
	"github.com/mijelblack677-ctrl/aegis/internal/output"
)

type SSRFDetector struct {
	ssrfTargets []string
}

func NewSSRFDetector() *SSRFDetector {
	return &SSRFDetector{
		ssrfTargets: []string{
			"http://169.254.169.254/latest/meta-data/",
			"http://metadata.google.internal/",
			"http://127.0.0.1:22",
			"http://localhost:8080/",
			"file:///etc/passwd",
			"http://0.0.0.0/",
			"http://[::1]:22",
		},
	}
}

func (s *SSRFDetector) Name() string    { return "ssrf_detector" }
func (s *SSRFDetector) IsPassive() bool { return false }

func (s *SSRFDetector) Run(pair *modules.RequestResponsePair) ([]*output.Vulnerability, error) {
	var vulns []*output.Vulnerability

	// Only test requests with parameters
	queryParams := pair.Request.URL.Query()
	if len(queryParams) == 0 && pair.RequestBody == nil {
		return vulns, nil
	}

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	urlStr := pair.Request.URL.String()

	// Test query parameters for SSRF
	for param := range queryParams {
		if isURLParameter(param) {
			for _, target := range s.ssrfTargets {
				newURL := replaceQueryParam(urlStr, param, target)
				req, _ := http.NewRequest(pair.Request.Method, newURL, nil)
				copyHeaders(pair.Request, req)

				resp, err := client.Do(req)
				if err != nil {
					continue
				}
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()

				if s.isSSRFResponse(resp.StatusCode, string(body)) {
					vulns = append(vulns, &output.Vulnerability{
						Name:        fmt.Sprintf("SSRF via Parameter: %s", param),
						Description: fmt.Sprintf("The parameter '%s' appears vulnerable to SSRF. Target '%s' was reachable.", param, target),
						Severity:    output.SeverityCritical,
						URL:         urlStr,
						Parameter:   param,
						Evidence: output.Evidence{
							ProofOfConcept: fmt.Sprintf("curl '%s'", newURL),
						},
						Remediation: "Implement URL whitelisting or block requests to internal/private IP addresses.",
						Tags:        []string{"ssrf", "server-side-request-forgery", "goldmine"},
					})
				}
			}
		}
	}

	return vulns, nil
}

func isURLParameter(param string) bool {
	urlParams := []string{"url", "uri", "path", "file", "document", "folder", "root",
		"src", "href", "action", "link", "resource", "target", "redirect", "return",
		"callback", "webhook", "proxy"}
	param = strings.ToLower(param)
	for _, p := range urlParams {
		if strings.Contains(param, p) {
			return true
		}
	}
	return false
}

func replaceQueryParam(rawURL, param, newValue string) string {
	parsed, _ := url.Parse(rawURL)
	q := parsed.Query()
	q.Set(param, newValue)
	parsed.RawQuery = q.Encode()
	return parsed.String()
}

func (s *SSRFDetector) isSSRFResponse(statusCode int, body string) bool {
	// AWS metadata
	if strings.Contains(body, "ami-id") || strings.Contains(body, "instance-id") {
		return true
	}
	// Response indicating internal access
	if statusCode == 200 && (strings.Contains(body, "root:") || strings.Contains(body, "SSH-2.0")) {
		return true
	}
	return false
}

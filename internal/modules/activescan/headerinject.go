package activescan

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/mijelblack677-ctrl/aegis/internal/modules"
	"github.com/mijelblack677-ctrl/aegis/internal/output"
)

type HeaderInjection struct{}

func NewHeaderInjection() *HeaderInjection {
	return &HeaderInjection{}
}

func (hi *HeaderInjection) Name() string    { return "header_injection" }
func (hi *HeaderInjection) IsPassive() bool { return false }

func (hi *HeaderInjection) Run(pair *modules.RequestResponsePair) ([]*output.Vulnerability, error) {
	var vulns []*output.Vulnerability

	urlStr := pair.Request.URL.String()
	client := &http.Client{}

	// Test Host header injection
	maliciousHosts := []string{
		"evil.com",
		"127.0.0.1",
		"localhost",
	}

	for _, host := range maliciousHosts {
		req, _ := http.NewRequest(pair.Request.Method, urlStr, nil)
		copyHeaders(pair.Request, req)
		req.Host = host

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		bodyStr := string(body)

		// Check if the host is reflected in the response
		if strings.Contains(bodyStr, host) {
			// Check for password reset link with reflected host
			if strings.Contains(strings.ToLower(bodyStr), "reset") ||
				strings.Contains(strings.ToLower(bodyStr), "token=") ||
				strings.Contains(strings.ToLower(bodyStr), "link") {
				vulns = append(vulns, &output.Vulnerability{
					Name:        "Host Header Injection (Password Reset Poisoning)",
					Description: fmt.Sprintf("Host header '%s' reflected in response containing reset/token. This enables password reset poisoning attacks.", host),
					Severity:    output.SeverityCritical,
					URL:         urlStr,
					Evidence: output.Evidence{
						Request:        fmt.Sprintf("Host: %s", host),
						ProofOfConcept: fmt.Sprintf("curl -H 'Host: %s' '%s'", host, urlStr),
					},
					Remediation: "Use a whitelist of allowed hostnames or configure your web server to use absolute URLs with the correct host.",
					Tags:        []string{"host-header-injection", "password-reset-poisoning", "goldmine"},
				})
			}
		}
	}

	// Test for CRLF injection in headers
	crlfPayloads := []string{
		"value\r\nSet-Cookie: injected=yes",
		"value\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<script>alert(1)</script>",
	}

	for _, payload := range crlfPayloads {
		req, _ := http.NewRequest(pair.Request.Method, urlStr, nil)
		copyHeaders(pair.Request, req)
		req.Header.Set("X-Custom-Injected", payload)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if strings.Contains(string(body), "injected=yes") || resp.Header.Get("Injected") != "" {
			vulns = append(vulns, &output.Vulnerability{
				Name:        "HTTP Header CRLF Injection",
				Description: "CRLF injection in HTTP headers detected. This can lead to response splitting and cookie injection.",
				Severity:    output.SeverityHigh,
				URL:         urlStr,
				Evidence: output.Evidence{
					Request: fmt.Sprintf("Header with CRLF: %s", payload),
				},
				Remediation: "Strip CR and LF characters from user-supplied input in HTTP headers.",
				Tags:        []string{"crlf-injection", "response-splitting"},
			})
		}
	}

	return vulns, nil
}

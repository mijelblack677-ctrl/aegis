package activescan

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mijelblack677-ctrl/aegis/internal/modules"
	"github.com/mijelblack677-ctrl/aegis/internal/output"
)

type CommandInjection struct {
	timePayloads []string
	echoPayloads []string
}

func NewCommandInjection() *CommandInjection {
	return &CommandInjection{
		timePayloads: []string{
			"; sleep 3 #",
			"| sleep 3",
			"` sleep 3 `",
			"$(sleep 3)",
			"|| sleep 3",
			"&& sleep 3",
		},
		echoPayloads: []string{
			"; echo AEGIS_TEST_12345",
			"| echo AEGIS_TEST_12345",
			"` echo AEGIS_TEST_12345 `",
		},
	}
}

func (ci *CommandInjection) Name() string    { return "command_injection" }
func (ci *CommandInjection) IsPassive() bool { return false }

func (ci *CommandInjection) Run(pair *modules.RequestResponsePair) ([]*output.Vulnerability, error) {
	var vulns []*output.Vulnerability

	queryParams := pair.Request.URL.Query()
	if len(queryParams) == 0 {
		return vulns, nil
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	urlStr := pair.Request.URL.String()

	for param := range queryParams {
		// Test time-based injection
		for _, payload := range ci.timePayloads {
			newURL := replaceQueryParam(urlStr, param, url.QueryEscape(payload))
			req, _ := http.NewRequest(pair.Request.Method, newURL, nil)
			copyHeaders(pair.Request, req)

			start := time.Now()
			resp, err := client.Do(req)
			elapsed := time.Since(start)
			if resp != nil {
				resp.Body.Close()
			}

			if err == nil && elapsed > 2*time.Second {
				vulns = append(vulns, &output.Vulnerability{
					Name:        fmt.Sprintf("Command Injection (Time-based) in Parameter: %s", param),
					Description: fmt.Sprintf("Time-based command injection detected. Response delayed by %v.", elapsed),
					Severity:    output.SeverityCritical,
					URL:         urlStr,
					Parameter:   param,
					Evidence: output.Evidence{
						ProofOfConcept: fmt.Sprintf("curl '%s'", newURL),
					},
					Remediation: "Never pass user input to system commands. Use parameterized APIs instead.",
					Tags:        []string{"command-injection", "rce", "critical", "goldmine"},
				})
				return vulns, nil
			}
		}

		// Test echo-based injection
		for _, payload := range ci.echoPayloads {
			newURL := replaceQueryParam(urlStr, param, url.QueryEscape(payload))
			req, _ := http.NewRequest(pair.Request.Method, newURL, nil)
			copyHeaders(pair.Request, req)

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			if strings.Contains(string(body), "AEGIS_TEST_12345") {
				vulns = append(vulns, &output.Vulnerability{
					Name:        fmt.Sprintf("Command Injection (Echo-based) in Parameter: %s", param),
					Description: "Command injection confirmed via echo output in response.",
					Severity:    output.SeverityCritical,
					URL:         urlStr,
					Parameter:   param,
					Evidence: output.Evidence{
						ProofOfConcept: fmt.Sprintf("curl '%s'", newURL),
					},
					Remediation: "Sanitize all user input. Never execute user input as shell commands.",
					Tags:        []string{"command-injection", "rce", "critical", "goldmine"},
				})
				return vulns, nil
			}
		}
	}

	return vulns, nil
}

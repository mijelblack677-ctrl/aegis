package activescan

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/mijelblack677-ctrl/aegis/internal/modules"
	"github.com/mijelblack677-ctrl/aegis/internal/output"
)

type IDORHunter struct {
	idRegex *regexp.Regexp
}

func NewIDORHunter() *IDORHunter {
	return &IDORHunter{
		idRegex: regexp.MustCompile(`/(\d+)/`),
	}
}

func (i *IDORHunter) Name() string    { return "idor_hunter" }
func (i *IDORHunter) IsPassive() bool { return false }

func (i *IDORHunter) Run(pair *modules.RequestResponsePair) ([]*output.Vulnerability, error) {
	var vulns []*output.Vulnerability

	// Find numeric IDs in URL path
	matches := i.idRegex.FindAllStringSubmatch(pair.Request.URL.Path, -1)
	if len(matches) == 0 {
		return vulns, nil
	}

	urlStr := pair.Request.URL.String()
	client := &http.Client{}

	// Get baseline response
	baselineReq, _ := http.NewRequest(pair.Request.Method, urlStr, nil)
	copyHeaders(pair.Request, baselineReq)
	baselineResp, err := client.Do(baselineReq)
	if err != nil {
		return vulns, nil
	}
	baselineBody, _ := io.ReadAll(baselineResp.Body)
	baselineResp.Body.Close()

	if baselineResp.StatusCode != 200 {
		return vulns, nil
	}

	// Try adjacent IDs
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		idStr := match[1]
		id, err := strconv.Atoi(idStr)
		if err != nil {
			continue
		}

		// Test ID+1 and ID-1
		for _, testID := range []int{id + 1, id - 1, 1, 0} {
			if testID < 0 {
				continue
			}
			newPath := strings.Replace(pair.Request.URL.Path, "/"+idStr+"/", "/"+strconv.Itoa(testID)+"/", 1)
			newURL := strings.Replace(urlStr, pair.Request.URL.Path, newPath, 1)

			testReq, _ := http.NewRequest(pair.Request.Method, newURL, nil)
			copyHeaders(pair.Request, testReq)

			testResp, err := client.Do(testReq)
			if err != nil {
				continue
			}
			testBody, _ := io.ReadAll(testResp.Body)
			testResp.Body.Close()

			// IDOR detected if different user's data returned
			if testResp.StatusCode == 200 && len(testBody) > 0 &&
				string(testBody) != string(baselineBody) &&
				!strings.Contains(string(testBody), "error") &&
				!strings.Contains(string(testBody), "unauthorized") {
				vulns = append(vulns, &output.Vulnerability{
					Name:        fmt.Sprintf("IDOR: User Data Accessible via ID %d", testID),
					Description: fmt.Sprintf("Changing ID from %s to %d returned different data, suggesting Insecure Direct Object Reference.", idStr, testID),
					Severity:    output.SeverityCritical,
					URL:         newURL,
					Method:      pair.Request.Method,
					Parameter:   "ID in URL path",
					Evidence: output.Evidence{
						ProofOfConcept: fmt.Sprintf("curl '%s' returns other user's data", newURL),
					},
					Remediation: "Implement proper authorization checks. Never rely solely on object IDs for access control.",
					Tags:        []string{"idor", "authorization", "critical", "goldmine"},
				})
				return vulns, nil
			}
		}
	}

	return vulns, nil
}

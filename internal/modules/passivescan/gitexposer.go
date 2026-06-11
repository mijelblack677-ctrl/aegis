package passivescan

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/mijelblack677-ctrl/aegis/internal/modules"
	"github.com/mijelblack677-ctrl/aegis/internal/output"
)

type GitExposer struct {
	sensitiveFiles []string
}

func NewGitExposer() *GitExposer {
	return &GitExposer{
		sensitiveFiles: []string{
			".git/HEAD",
			".git/config",
			".env",
			".env.backup",
			".env.production",
			"config.json",
			"config.yaml",
			"database.yml",
			"wp-config.php",
			".DS_Store",
			"Dockerfile",
			"package.json",
			"docker-compose.yml",
		},
	}
}

func (ge *GitExposer) Name() string    { return "git_exposer" }
func (ge *GitExposer) IsPassive() bool { return false }

func (ge *GitExposer) Run(pair *modules.RequestResponsePair) ([]*output.Vulnerability, error) {
	var vulns []*output.Vulnerability

	baseURL := getBaseURL(pair.Request.URL.String())

	for _, file := range ge.sensitiveFiles {
		targetURL := fmt.Sprintf("%s/%s", strings.TrimRight(baseURL, "/"), file)

		req, err := http.NewRequest("GET", targetURL, nil)
		if err != nil {
			continue
		}

		if pair.Request != nil {
			for _, cookie := range pair.Request.Cookies() {
				req.AddCookie(cookie)
			}
		}

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 {
			vulns = append(vulns, &output.Vulnerability{
				Name:        fmt.Sprintf("Sensitive File Exposed: %s", file),
				Description: fmt.Sprintf("The file '%s' is accessible.", file),
				Severity:    output.SeverityCritical,
				URL:         targetURL,
				Method:      "GET",
				Evidence: output.Evidence{
					ProofOfConcept: fmt.Sprintf("curl '%s'", targetURL),
				},
				Remediation: fmt.Sprintf("Deny access to '%s'.", file),
				Tags:        []string{"sensitive-file-exposure", "goldmine"},
			})
		}
		resp.Body.Close()
	}

	return vulns, nil
}

func getBaseURL(fullURL string) string {
	parts := strings.SplitN(fullURL, "/", 4)
	if len(parts) >= 3 {
		return strings.Join(parts[:3], "/")
	}
	return fullURL
}

package passivescan

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/mijelblack677-ctrl/aegis/internal/modules"
	"github.com/mijelblack677-ctrl/aegis/internal/output"
)

type CookieAnalyzer struct{}

func NewCookieAnalyzer() *CookieAnalyzer {
	return &CookieAnalyzer{}
}

func (ca *CookieAnalyzer) Name() string    { return "cookie_analyzer" }
func (ca *CookieAnalyzer) IsPassive() bool { return true }

func (ca *CookieAnalyzer) Run(pair *modules.RequestResponsePair) ([]*output.Vulnerability, error) {
	var vulns []*output.Vulnerability

	if pair.Response == nil {
		return vulns, nil
	}

	cookies := pair.Response.Cookies()
	for _, cookie := range cookies {
		vulns = append(vulns, ca.analyzeCookie(cookie, pair.Request.URL.String())...)
	}

	return vulns, nil
}

func (ca *CookieAnalyzer) analyzeCookie(cookie *http.Cookie, url string) []*output.Vulnerability {
	var vulns []*output.Vulnerability

	if !cookie.Secure {
		vulns = append(vulns, &output.Vulnerability{
			Name:        fmt.Sprintf("Cookie Missing Secure Flag: %s", cookie.Name),
			Description: "The secure flag is not set on this cookie.",
			Severity:    output.SeverityMedium,
			URL:         url,
			Evidence: output.Evidence{
				ProofOfConcept: fmt.Sprintf("Cookie: %s; Secure flag: false", cookie.Name),
			},
			Remediation: "Set the 'Secure' flag on all cookies containing sensitive information.",
			Tags:        []string{"cookie-security", "missing-secure-flag"},
		})
	}

	if !cookie.HttpOnly {
		vulns = append(vulns, &output.Vulnerability{
			Name:        fmt.Sprintf("Cookie Missing HttpOnly Flag: %s", cookie.Name),
			Description: "The HttpOnly flag is not set.",
			Severity:    output.SeverityMedium,
			URL:         url,
			Evidence: output.Evidence{
				ProofOfConcept: fmt.Sprintf("Cookie: %s; HttpOnly flag: false", cookie.Name),
			},
			Remediation: "Set the 'HttpOnly' flag on all cookies.",
			Tags:        []string{"cookie-security", "missing-httponly-flag"},
		})
	}

	if cookie.SameSite == http.SameSiteDefaultMode {
		vulns = append(vulns, &output.Vulnerability{
			Name:        fmt.Sprintf("Cookie Missing SameSite Attribute: %s", cookie.Name),
			Description: "The SameSite attribute is not set.",
			Severity:    output.SeverityLow,
			URL:         url,
			Evidence: output.Evidence{
				ProofOfConcept: fmt.Sprintf("Cookie: %s; SameSite: not set", cookie.Name),
			},
			Remediation: "Set the 'SameSite' attribute to 'Lax' or 'Strict'.",
			Tags:        []string{"cookie-security", "missing-samesite"},
		})
	}

	if strings.Contains(strings.ToLower(cookie.Name), "session") && cookie.Value == "" {
		// empty session
	}

	return vulns
}

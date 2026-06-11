package passivescan

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/mijelblack677-ctrl/aegis/internal/modules"
	"github.com/mijelblack677-ctrl/aegis/internal/output"
)

type TechFingerprinter struct {
	techPatterns map[string][]string
}

func NewTechFingerprinter() *TechFingerprinter {
	return &TechFingerprinter{
		techPatterns: map[string][]string{
			"React":    {`react\.development\.js`, `react\.production\.min\.js`, `__REACT_DEVTOOLS_GLOBAL_HOOK__`},
			"Angular":  {`angular\.js`, `angular\.min\.js`, `ng-version=`},
			"Vue.js":   {`vue\.js`, `vue\.min\.js`, `__VUE_DEVTOOLS_GLOBAL_HOOK__`},
			"jQuery":   {`jquery[.-][0-9]`, `jQuery v`},
			"Bootstrap": {`bootstrap\.min\.css`, `bootstrap\.css`},
			"WordPress": {`wp-content`, `wp-includes`, `wp-json`},
			"Drupal":    {`drupal\.js`, `misc/drupal`},
			"Laravel":   {`laravel_session`, `XSRF-TOKEN`},
			"Django":    {`csrftoken`, `django\.`},
			"ASP.NET":   {`__VIEWSTATE`, `__EVENTVALIDATION`, `aspnetcore`},
			"PHP":       {`PHPSESSID`, `\.php`},
			"Node.js":   {`x-powered-by: express`, `connect.sid`},
			"Nginx":     {`server: nginx`},
			"Apache":    {`server: apache`},
			"Cloudflare": {`cf-ray`, `__cfduid`},
			"AWS":       {`x-amz-`, `aws-`},
		},
	}
}

func (tf *TechFingerprinter) Name() string    { return "tech_fingerprinter" }
func (tf *TechFingerprinter) IsPassive() bool { return true }

func (tf *TechFingerprinter) Run(pair *modules.RequestResponsePair) ([]*output.Vulnerability, error) {
	var vulns []*output.Vulnerability
	
	if pair.Response == nil {
		return vulns, nil
	}
	
	bodyStr := string(pair.ResponseBody)
	headersStr := formatHeaders(pair.Response.Header)
	contentToCheck := strings.ToLower(bodyStr + " " + headersStr)
	
	foundTechs := []string{}
	
	for tech, patterns := range tf.techPatterns {
		for _, pattern := range patterns {
			matched, _ := regexp.MatchString(strings.ToLower(pattern), contentToCheck)
			if matched {
				foundTechs = append(foundTechs, tech)
				break
			}
		}
	}
	
	if len(foundTechs) > 0 {
		vulns = append(vulns, &output.Vulnerability{
			Name:        fmt.Sprintf("Technology Fingerprint: %s", strings.Join(foundTechs, ", ")),
			Description: fmt.Sprintf("The application appears to use: %s. This information helps in understanding the attack surface.", strings.Join(foundTechs, ", ")),
			Severity:    output.SeverityInfo,
			URL:         pair.Request.URL.String(),
			Evidence: output.Evidence{
				ProofOfConcept: fmt.Sprintf("Detected technologies: %s", strings.Join(foundTechs, ", ")),
			},
			Remediation: "No remediation needed, but be aware that attackers can fingerprint your technology stack.",
			Tags:        []string{"fingerprint", "technology-detection"},
		})
	}
	
	return vulns, nil
}

func formatHeaders(headers http.Header) string {
	var result string
	for key, values := range headers {
		for _, value := range values {
			result += fmt.Sprintf("%s: %s\n", key, value)
		}
	}
	return result
}
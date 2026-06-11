package passivescan

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/mijelblack677-ctrl/aegis/internal/modules"
	"github.com/mijelblack677-ctrl/aegis/internal/output"
)

type XSSDetector struct {
	reflectedParamRegex *regexp.Regexp
	dangerousFunctions   []string
}

func NewXSSDetector() *XSSDetector {
	return &XSSDetector{
		dangerousFunctions: []string{
			"innerHTML",
			"outerHTML",
			"document.write(",
			"document.writeln(",
			"eval(",
			"setTimeout(",
			"setInterval(",
			"new Function(",
			"$.html(",
			"jQuery.html(",
		},
	}
}

func (xd *XSSDetector) Name() string    { return "xss_detector" }
func (xd *XSSDetector) IsPassive() bool { return true }

func (xd *XSSDetector) Run(pair *modules.RequestResponsePair) ([]*output.Vulnerability, error) {
	var vulns []*output.Vulnerability
	
	if pair.Response == nil || pair.ResponseBody == nil {
		return vulns, nil
	}
	
	url := pair.Request.URL.String()
	bodyStr := string(pair.ResponseBody)
	
	// Check for reflected parameters in response
	vulns = append(vulns, xd.checkReflectedParams(pair)...)
	
	// Check for dangerous JavaScript patterns
	vulns = append(vulns, xd.checkDangerousJS(bodyStr, url)...)
	
	// Check for potential DOM-based XSS
	vulns = append(vulns, xd.checkDOMXSS(bodyStr, url)...)
	
	return vulns, nil
}

func (xd *XSSDetector) checkReflectedParams(pair *modules.RequestResponsePair) []*output.Vulnerability {
	var vulns []*output.Vulnerability
	
	queryParams := pair.Request.URL.Query()
	bodyStr := string(pair.ResponseBody)
	
	for param, values := range queryParams {
		for _, value := range values {
			if value == "" {
				continue
			}
			// Check if the parameter value is reflected in the response
			if strings.Contains(bodyStr, value) {
				// Check if it's reflected without encoding
				encodedValue := url.QueryEscape(value)
				if !strings.Contains(bodyStr, encodedValue) && strings.Contains(bodyStr, value) {
					vulns = append(vulns, &output.Vulnerability{
						Name:        fmt.Sprintf("Potential Reflected XSS in Parameter: %s", param),
						Description: fmt.Sprintf("The parameter '%s' value is reflected in the response without proper encoding. This could allow Cross-Site Scripting attacks.", param),
						Severity:    output.SeverityHigh,
						URL:         pair.Request.URL.String(),
						Parameter:   param,
						Evidence: output.Evidence{
							ProofOfConcept: fmt.Sprintf("Parameter %s=%s is reflected in response", param, value),
						},
						Remediation: "Implement proper output encoding for all user-supplied input and use Content-Security-Policy headers.",
						Tags:        []string{"xss", "reflected", "potential"},
					})
				}
			}
		}
	}
	
	return vulns
}

func (xd *XSSDetector) checkDangerousJS(body, url string) []*output.Vulnerability {
	var vulns []*output.Vulnerability
	
	for _, funcName := range xd.dangerousFunctions {
		if strings.Contains(body, funcName) {
			vulns = append(vulns, &output.Vulnerability{
				Name:        fmt.Sprintf("Potentially Dangerous JavaScript Function: %s", funcName),
				Description: fmt.Sprintf("The function '%s' is used in the response. If it handles user input, it could lead to DOM-based XSS.", funcName),
				Severity:    output.SeverityMedium,
				URL:         url,
				Evidence: output.Evidence{
					ProofOfConcept: fmt.Sprintf("Found dangerous function: %s", funcName),
				},
				Remediation: "Avoid using dangerous functions with user input. Use safer alternatives like textContent instead of innerHTML.",
				Tags:        []string{"xss", "dom", "dangerous-js"},
			})
		}
	}
	
	return vulns
}

func (xd *XSSDetector) checkDOMXSS(body, url string) []*output.Vulnerability {
	var vulns []*output.Vulnerability
	
	// Check for common DOM XSS sinks
	sinks := []string{
		"location.hash",
		"location.href",
		"document.URL",
		"document.documentURI",
		"document.URLUnencoded",
		"document.baseURI",
		"document.referrer",
		"window.name",
	}
	
	for _, sink := range sinks {
		if strings.Contains(body, sink) {
			// Check if it's used in an unsafe way
			for _, dangerous := range xd.dangerousFunctions {
				if strings.Contains(body, dangerous) {
					vulns = append(vulns, &output.Vulnerability{
						Name:        fmt.Sprintf("Potential DOM-based XSS via %s", sink),
						Description: fmt.Sprintf("The source '%s' is used in the JavaScript. Combined with '%s', this could lead to DOM-based XSS.", sink, dangerous),
						Severity:    output.SeverityHigh,
						URL:         url,
						Evidence: output.Evidence{
							ProofOfConcept: fmt.Sprintf("Source: %s, Sink: %s", sink, dangerous),
						},
						Remediation: "Sanitize all data from client-side sources before using it in dangerous sinks.",
						Tags:        []string{"xss", "dom", "source-sink"},
					})
				}
			}
		}
	}
	
	return vulns
}
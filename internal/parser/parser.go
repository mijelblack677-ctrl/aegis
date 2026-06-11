package parser

import (
	"regexp"
	"strings"

	"github.com/mijelblack677-ctrl/aegis/pkg/utils"
)

type ParseResult struct {
	Endpoints []string
	Secrets   []Secret
	Comments  []string
}

type Secret struct {
	Type   string
	Value  string
	Source string
	Line   int
}

var (
	endpointRegex = regexp.MustCompile(`(?i)(?:"|'|\x60)((?:https?://|//)[^"'\x60 ]+|(?:/|\.\./|\./)[a-zA-Z0-9_\-\./]{2,}/[a-zA-Z0-9_\-\./]+|(?:[a-zA-Z0-9_\-\./]+\.(?:json|xml|yaml|yml|env|config|bak|backup|sql|db|log|txt|php|aspx|jsp|do|action))(?:[?a-zA-Z0-9_\-\.=&]*))(?:"|'|\x60)`)
	commentRegex  = regexp.MustCompile(`(?s)(?://.*|/\*.*?\*/|<!--.*?-->)`)
)

func Parse(filename string, body []byte, contentType string) *ParseResult {
	result := &ParseResult{}
	contentStr := string(body)

	result.Endpoints = extractEndpoints(contentStr)
	
	if strings.Contains(contentType, "javascript") || 
	   strings.Contains(contentType, "json") || 
	   strings.Contains(contentType, "html") {
		result.Secrets = findSecrets(filename, contentStr)
	}
	
	result.Comments = extractComments(contentStr)
	
	return result
}

func extractEndpoints(content string) []string {
	matches := endpointRegex.FindAllStringSubmatch(content, -1)
	var endpoints []string
	seen := make(map[string]bool)
	for _, match := range matches {
		if len(match) > 1 {
			ep := match[1]
			if !seen[ep] {
				seen[ep] = true
				endpoints = append(endpoints, ep)
			}
		}
	}
	return endpoints
}

func extractComments(content string) []string {
	return commentRegex.FindAllString(content, -1)
}

func findSecrets(filename, content string) []Secret {
	var secrets []Secret
	
	highConfPatterns := map[string]*regexp.Regexp{
		"AWS Access Key ID":     regexp.MustCompile(`(?:AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`),
		"AWS Secret Key":        regexp.MustCompile(`(?i)aws(.{0,20})?(?:secret|pwd|password|key).{0,30}?['"]([0-9a-zA-Z/+]{40})['"]`),
		"Google API Key":        regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
		"GitHub Token":          regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}`),
		"GitHub OAuth":          regexp.MustCompile(`gho_[0-9a-zA-Z]{36}`),
		"Generic API Key":       regexp.MustCompile(`(?i)(?:api[_-]?key|apikey|api).{0,20}?['"]([0-9a-zA-Z\-_+/]{20,})['"]`),
		"Generic Secret":        regexp.MustCompile(`(?i)(?:secret|token|key|password|pwd|auth).{0,20}?['"]([0-9a-zA-Z\-_+/]{20,})['"]`),
		"JWT Token":             regexp.MustCompile(`eyJ[a-zA-Z0-9]{10,}\.[a-zA-Z0-9]{10,}\.[a-zA-Z0-9\-_]{10,}`),
		"Private Key":           regexp.MustCompile(`-----BEGIN (?:RSA |EC )?PRIVATE KEY-----`),
	}
	
	for name, re := range highConfPatterns {
		matches := re.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			secretVal := match[0]
			if len(match) > 1 {
				secretVal = match[len(match)-1]
			}
			if utils.ShannonEntropy(secretVal) > 3.5 || strings.Contains(name, "Private Key") {
				secrets = append(secrets, Secret{
					Type:   name,
					Value:  secretVal,
					Source: filename,
				})
			}
		}
	}
	
	return secrets
}
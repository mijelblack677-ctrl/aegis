package activescan

import (
	"net/url"
	"strings"
)

// WAFBypass provides encoding variations to evade WAF rules
type WAFBypass struct{}

func NewWAFBypass() *WAFBypass {
	return &WAFBypass{}
}

// EncodePayload generates WAF evasion variants of a payload
func (w *WAFBypass) EncodePayload(payload string) []string {
	variants := []string{payload}
	
	// URL encoding
	variants = append(variants, url.QueryEscape(payload))
	
	// Double URL encoding
	variants = append(variants, url.QueryEscape(url.QueryEscape(payload)))
	
	// Unicode encoding
	variants = append(variants, toUnicode(payload))
	
	// Case variation for SQL keywords
	if strings.Contains(strings.ToLower(payload), "select") {
		variants = append(variants, 
			strings.Replace(payload, "SELECT", "SeLeCt", -1),
			strings.Replace(payload, "select", "sel%00ect", -1),
		)
	}
	
	// Comment injection for SQLi
	if strings.Contains(payload, " ") {
		variants = append(variants, 
			strings.Replace(payload, " ", "/**/", -1),
			strings.Replace(payload, " ", "+", -1),
			strings.Replace(payload, " ", "%09", -1),
		)
	}
	
	// Null byte injection
	variants = append(variants, strings.Replace(payload, "'", "%00'", -1))
	
	// Alternative operators
	variants = append(variants,
		strings.Replace(payload, "=", " LIKE ", -1),
		strings.Replace(payload, "'='", "'!='", -1),
	)
	
	return variants
}

func toUnicode(s string) string {
	var result strings.Builder
	for _, r := range s {
		result.WriteString("\\u")
		result.WriteString(strings.ToLower(string([]rune{r})))
	}
	return result.String()
}

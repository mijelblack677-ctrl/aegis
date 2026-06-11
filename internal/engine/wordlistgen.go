package engine

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

type WordlistGenerator struct {
	patterns map[string]int
	words    map[string]int
}

func NewWordlistGenerator() *WordlistGenerator {
	return &WordlistGenerator{
		patterns: make(map[string]int),
		words:    make(map[string]int),
	}
}

func (wg *WordlistGenerator) AnalyzeEndpoint(endpoint string) {
	// Tokenize the URL path
	parts := strings.Split(strings.Trim(endpoint, "/"), "/")
	for _, part := range parts {
		if part == "" {
			continue
		}
		
		// Detect patterns
		switch {
		case isNumeric(part):
			wg.patterns["{NUMERIC_ID}"]++
		case isUUID(part):
			wg.patterns["{UUID}"]++
		case isSlug(part):
			wg.patterns["{SLUG}"]++
		case isDate(part):
			wg.patterns["{DATE}"]++
		case isHexHash(part):
			wg.patterns["{HASH}"]++
		case isEmail(part):
			wg.patterns["{EMAIL}"]++
		default:
			wg.words[part]++
		}
	}
	
	// Also analyze query parameters
	if idx := strings.Index(endpoint, "?"); idx > 0 {
		queryString := endpoint[idx+1:]
		params := strings.Split(queryString, "&")
		for _, param := range params {
			parts := strings.SplitN(param, "=", 2)
			if len(parts) > 0 {
				wg.words[parts[0]]++
			}
		}
	}
}

// GenerateWordlist returns suggested words and patterns for fuzzing
func (wg *WordlistGenerator) GenerateWordlist() []string {
	var suggestions []string
	
	suggestions = append(suggestions, "\n=== Endpoint Pattern Analysis ===")
	suggestions = append(suggestions, "Detected URL patterns:")
	
	// Sort patterns by frequency
	type pattern struct {
		name  string
		count int
	}
	var sortedPatterns []pattern
	for k, v := range wg.patterns {
		sortedPatterns = append(sortedPatterns, pattern{k, v})
	}
	sort.Slice(sortedPatterns, func(i, j int) bool {
		return sortedPatterns[i].count > sortedPatterns[j].count
	})
	
	for _, p := range sortedPatterns {
		suggestions = append(suggestions, fmt.Sprintf("  %s (found %d times)", p.name, p.count))
	}
	
	suggestions = append(suggestions, "\nSuggested wordlist entries:")
	
	// Sort words by frequency
	type word struct {
		name  string
		count int
	}
	var sortedWords []word
	for k, v := range wg.words {
		sortedWords = append(sortedWords, word{k, v})
	}
	sort.Slice(sortedWords, func(i, j int) bool {
		return sortedWords[i].count > sortedWords[j].count
	})
	
	for i, w := range sortedWords {
		if i >= 20 {
			break
		}
		suggestions = append(suggestions, fmt.Sprintf("  %s", w.name))
	}
	
	return suggestions
}

func isNumeric(s string) bool {
	re := regexp.MustCompile(`^\d+$`)
	return re.MatchString(s)
}

func isUUID(s string) bool {
	re := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	return re.MatchString(strings.ToLower(s))
}

func isSlug(s string) bool {
	re := regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	return re.MatchString(s) && strings.Contains(s, "-")
}

func isDate(s string) bool {
	re := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	return re.MatchString(s)
}

func isHexHash(s string) bool {
	re := regexp.MustCompile(`^[a-f0-9]{32,64}$`)
	return re.MatchString(strings.ToLower(s))
}

func isEmail(s string) bool {
	re := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return re.MatchString(s)
}

package engine

import (
	"regexp"
	"strings"
	"sync"
)

type ScopeManager struct {
	includePatterns []*regexp.Regexp
	excludePatterns []*regexp.Regexp
	inScopeHosts    map[string]bool
	outScopeHosts   map[string]bool
	mu              sync.RWMutex
	enabled         bool
}

func NewScopeManager() *ScopeManager {
	return &ScopeManager{
		inScopeHosts:  make(map[string]bool),
		outScopeHosts: make(map[string]bool),
		enabled:       false,
	}
}

// AddInclude adds a host or pattern to include in scope
func (sm *ScopeManager) AddInclude(pattern string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.enabled = true
	
	if isRegexPattern(pattern) {
		re, err := regexp.Compile(pattern)
		if err == nil {
			sm.includePatterns = append(sm.includePatterns, re)
		}
	} else {
		sm.inScopeHosts[pattern] = true
	}
}

// AddExclude adds a host or pattern to exclude from scope
func (sm *ScopeManager) AddExclude(pattern string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	if isRegexPattern(pattern) {
		re, err := regexp.Compile(pattern)
		if err == nil {
			sm.excludePatterns = append(sm.excludePatterns, re)
		}
	} else {
		sm.outScopeHosts[pattern] = true
	}
}

// IsInScope checks if a URL should be scanned
func (sm *ScopeManager) IsInScope(url string) bool {
	if !sm.enabled {
		return true // If scope not configured, scan everything
	}
	
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	
	// Check exclusions first
	for host := range sm.outScopeHosts {
		if strings.Contains(url, host) {
			return false
		}
	}
	for _, re := range sm.excludePatterns {
		if re.MatchString(url) {
			return false
		}
	}
	
	// If no inclusions defined, allow everything not excluded
	if len(sm.inScopeHosts) == 0 && len(sm.includePatterns) == 0 {
		return true
	}
	
	// Check inclusions
	for host := range sm.inScopeHosts {
		if strings.Contains(url, host) {
			return true
		}
	}
	for _, re := range sm.includePatterns {
		if re.MatchString(url) {
			return true
		}
	}
	
	return false
}

// GetScope returns current scope configuration
func (sm *ScopeManager) GetScope() (includes, excludes []string) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	
	for host := range sm.inScopeHosts {
		includes = append(includes, host)
	}
	for _, re := range sm.includePatterns {
		includes = append(includes, re.String())
	}
	for host := range sm.outScopeHosts {
		excludes = append(excludes, host)
	}
	for _, re := range sm.excludePatterns {
		excludes = append(excludes, re.String())
	}
	return
}

func isRegexPattern(s string) bool {
	return strings.ContainsAny(s, ".*+?^$[]{}()|\\")
}

// CommonOutOfScopeHosts returns hosts that should typically be excluded
func CommonOutOfScopeHosts() []string {
	return []string{
		"google.com",
		"gstatic.com",
		"googleapis.com",
		"mozilla.com",
		"firefox.com",
		"microsoft.com",
		"office.com",
		"apple.com",
		"icloud.com",
		"facebook.com",
		"twitter.com",
		"youtube.com",
		"cloudflare.com",
		"amazonaws.com",
		"cdn.",
		"static.",
		"assets.",
		"fonts.",
		"analytics.",
		"tracking.",
		"pixel.",
		"telemetry.",
		"metrics.",
	}
}

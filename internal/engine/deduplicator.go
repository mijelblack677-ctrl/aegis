package engine

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"sync"
)

type Deduplicator struct {
	seen    map[string]bool
	mu      sync.RWMutex
}

func NewDeduplicator() *Deduplicator {
	return &Deduplicator{
		seen: make(map[string]bool),
	}
}

// IsDuplicate checks if a vulnerability has already been reported
// Uses a combination of vulnerability type + URL + parameter for dedup
func (d *Deduplicator) IsDuplicate(vulnType, url, parameter, evidence string) bool {
	key := d.generateKey(vulnType, url, parameter, evidence)
	
	d.mu.RLock()
	if d.seen[key] {
		d.mu.RUnlock()
		return true
	}
	d.mu.RUnlock()
	
	d.mu.Lock()
	d.seen[key] = true
	d.mu.Unlock()
	
	return false
}

func (d *Deduplicator) generateKey(vulnType, url, parameter, evidence string) string {
	// Normalize URL - strip query params for dedup purposes
	normalizedURL := strings.Split(url, "?")[0]
	
	// Create a unique fingerprint
	fingerprint := fmt.Sprintf("%s|%s|%s|%s", vulnType, normalizedURL, parameter, d.hashEvidence(evidence))
	hash := sha256.Sum256([]byte(fingerprint))
	return fmt.Sprintf("%x", hash[:16])
}

func (d *Deduplicator) hashEvidence(evidence string) string {
	if len(evidence) > 100 {
		evidence = evidence[:100]
	}
	hash := sha256.Sum256([]byte(evidence))
	return fmt.Sprintf("%x", hash[:8])
}

func (d *Deduplicator) Reset() {
	d.mu.Lock()
	d.seen = make(map[string]bool)
	d.mu.Unlock()
}

func (d *Deduplicator) Count() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.seen)
}

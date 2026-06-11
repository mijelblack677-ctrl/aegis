package engine

import (
	"sync"
	"time"
)

type RateLimiter struct {
	hostDelays   map[string]time.Time
	mu           sync.Mutex
	minDelay     time.Duration
	maxParallel  int
	activeHosts  map[string]int
}

func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		hostDelays:  make(map[string]time.Time),
		minDelay:    100 * time.Millisecond, // Minimum 100ms between requests to same host
		maxParallel: 3,                      // Max 3 concurrent requests per host
		activeHosts: make(map[string]int),
	}
}

// Wait blocks until it's safe to send another request to the given host
func (rl *RateLimiter) Wait(host string) {
	rl.mu.Lock()
	
	// Check last request time
	if lastRequest, ok := rl.hostDelays[host]; ok {
		elapsed := time.Since(lastRequest)
		if elapsed < rl.minDelay {
			rl.mu.Unlock()
			time.Sleep(rl.minDelay - elapsed)
			rl.mu.Lock()
		}
	}
	
	// Update last request time
	rl.hostDelays[host] = time.Now()
	rl.mu.Unlock()
}

// ReserveSlot reserves a concurrent slot for a host
func (rl *RateLimiter) ReserveSlot(host string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	if rl.activeHosts[host] >= rl.maxParallel {
		return false
	}
	rl.activeHosts[host]++
	return true
}

// ReleaseSlot releases a concurrent slot
func (rl *RateLimiter) ReleaseSlot(host string) {
	rl.mu.Lock()
	if rl.activeHosts[host] > 0 {
		rl.activeHosts[host]--
	}
	rl.mu.Unlock()
}

// SetRateLimit adjusts the rate limiting parameters
func (rl *RateLimiter) SetRateLimit(minDelay time.Duration, maxParallel int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.minDelay = minDelay
	rl.maxParallel = maxParallel
}

package engine

import (
	"crypto/md5"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/mijelblack677-ctrl/aegis/internal/modules"
	"github.com/mijelblack677-ctrl/aegis/internal/modules/activescan"
	"github.com/mijelblack677-ctrl/aegis/internal/modules/passivescan"
	"github.com/mijelblack677-ctrl/aegis/internal/output"
)

type Engine struct {
	modules         []modules.Module
	report          *output.Report
	endpointStore   map[string]*modules.RequestResponsePair
	dedupHashes     map[string]bool
	cookieStore     map[string][]*http.Cookie
	mu              sync.RWMutex
	wg              sync.WaitGroup
	activeScanQueue chan *modules.RequestResponsePair
	deduplicator    *Deduplicator
	scorer          *SeverityScorer
	sessions        *SessionContainer
	rateLimiter     *RateLimiter
	stats           *ScanStats
}

type ScanStats struct {
	RequestsProcessed int
	ActiveScansRun    int
	Vulnerabilities   int
	StartTime         time.Time
}

func NewEngine() *Engine {
	e := &Engine{
		report:          output.NewReport(),
		endpointStore:   make(map[string]*modules.RequestResponsePair),
		dedupHashes:     make(map[string]bool),
		cookieStore:     make(map[string][]*http.Cookie),
		activeScanQueue: make(chan *modules.RequestResponsePair, 2000),
		deduplicator:    NewDeduplicator(),
		scorer:          NewSeverityScorer(),
		sessions:        NewSessionContainer(),
		rateLimiter:     NewRateLimiter(),
		stats:           &ScanStats{StartTime: time.Now()},
	}

	// PASSIVE modules (always run)
	e.modules = append(e.modules,
		passivescan.NewSecretFinder(),
		passivescan.NewGitExposer(),
		passivescan.NewEndpointAnalyzer(),
		passivescan.NewCookieAnalyzer(),
		passivescan.NewHeaderAnalyzer(),
		passivescan.NewXSSDetector(),
		passivescan.NewTechFingerprinter(),
		passivescan.NewJWTAnalyzer(),
	)

	// ACTIVE modules (run on interesting endpoints)
	e.modules = append(e.modules,
		activescan.NewLoginSQLiFuzzer(),
		activescan.NewAdvancedLoginSQLiFuzzer(),
		activescan.NewNoSQLiFuzzer(),
		activescan.NewForbiddenBypasser(),
		activescan.NewHeaderInjection(),
		activescan.NewSSRFDetector(),
		activescan.NewIDORHunter(),
		activescan.NewCommandInjection(),
	)

	// Start active scanning workers
	for i := 0; i < 10; i++ {
		go e.activeScanWorker()
	}

	// Start stats reporter
	go e.statsReporter()

	return e
}

func (e *Engine) statsReporter() {
	ticker := time.NewTicker(30 * time.Second)
	for range ticker.C {
		elapsed := time.Since(e.stats.StartTime).Round(time.Second)
		log.Printf("[STATS] Requests: %d | Active Scans: %d | Vulns Found: %d | Runtime: %v",
			e.stats.RequestsProcessed, e.stats.ActiveScansRun, e.stats.Vulnerabilities, elapsed)
	}
}

func (e *Engine) ProcessTransaction(pair *modules.RequestResponsePair) {
	// Skip duplicate URLs for passive scanning
	hash := e.hashTransaction(pair)
	e.mu.RLock()
	if e.dedupHashes[hash] {
		e.mu.RUnlock()
		return
	}
	e.mu.RUnlock()

	e.mu.Lock()
	e.dedupHashes[hash] = true
	e.stats.RequestsProcessed++
	e.mu.Unlock()

	// Store endpoint
	e.storeEndpoint(pair)

	// Capture session information
	role := DetectRoleFromURL(pair.Request.URL.String())
	if pair.Request.Header.Get("Cookie") != "" || pair.Request.Header.Get("Authorization") != "" {
		e.sessions.CaptureSessionFromRequest(role, pair.Request)
	}
	if pair.Response != nil && len(pair.Response.Cookies()) > 0 {
		e.sessions.CaptureSession(role, pair.Response)
	}

	// Get response body for analysis
	var responseBody string
	if pair.ResponseBody != nil {
		responseBody = string(pair.ResponseBody)
	}

	// Run passive modules
	e.wg.Add(1)
	go func(p *modules.RequestResponsePair, respBody string) {
		defer e.wg.Done()
		for _, m := range e.modules {
			if !m.IsPassive() {
				continue
			}
			vulns, err := m.Run(p)
			if err != nil {
				continue
			}
			for _, v := range vulns {
				// Deduplicate findings
				if e.deduplicator.IsDuplicate(v.Name, v.URL, v.Parameter, v.Evidence.ProofOfConcept) {
					continue
				}
				v.ID = uuid.New().String()
				v.Timestamp = time.Now()
				// Adjust severity based on context
				v.Severity = e.scorer.AdjustSeverity(v, v.URL, respBody)
				e.mu.Lock()
				e.report.AddVulnerability(v)
				e.stats.Vulnerabilities++
				e.mu.Unlock()
				log.Printf("[!] %s: %s (%s)", v.Severity.String(), v.Name, v.URL)
			}
		}
	}(pair, responseBody)

	// Queue for active scanning
	if e.isInterestingForActiveScan(pair) {
		select {
		case e.activeScanQueue <- pair:
		default:
		}
	}
}

func (e *Engine) activeScanWorker() {
	for pair := range e.activeScanQueue {
		e.mu.Lock()
		e.stats.ActiveScansRun++
		e.mu.Unlock()

		// Extract host for rate limiting
		host := pair.Request.URL.Host
		e.rateLimiter.Wait(host)

		// Get response body
		var responseBody string
		if pair.ResponseBody != nil {
			responseBody = string(pair.ResponseBody)
		}

		for _, m := range e.modules {
			if m.IsPassive() {
				continue
			}
			vulns, err := m.Run(pair)
			if err != nil {
				continue
			}
			for _, v := range vulns {
				// Deduplicate
				if e.deduplicator.IsDuplicate(v.Name, v.URL, v.Parameter, v.Evidence.ProofOfConcept) {
					continue
				}
				v.ID = uuid.New().String()
				v.Timestamp = time.Now()
				v.Severity = e.scorer.AdjustSeverity(v, v.URL, responseBody)
				e.mu.Lock()
				e.report.AddVulnerability(v)
				e.stats.Vulnerabilities++
				e.mu.Unlock()
				log.Printf("[!] %s: %s (%s)", v.Severity.String(), v.Name, v.URL)
			}
		}
		e.rateLimiter.ReleaseSlot(host)
	}
}

func (e *Engine) WaitAndGenerateReport() *output.Report {
	close(e.activeScanQueue)
	e.wg.Wait()
	
	elapsed := time.Since(e.stats.StartTime).Round(time.Second)
	log.Printf("[+] Scan complete in %v", elapsed)
	log.Printf("[+] Total requests processed: %d", e.stats.RequestsProcessed)
	log.Printf("[+] Active scans performed: %d", e.stats.ActiveScansRun)
	log.Printf("[+] Total vulnerabilities: %d", e.stats.Vulnerabilities)
	
	return e.report
}

func (e *Engine) hashTransaction(pair *modules.RequestResponsePair) string {
	u := pair.Request.URL.String()
	method := pair.Request.Method
	return fmt.Sprintf("%x", md5.Sum([]byte(method+u)))
}

func (e *Engine) storeEndpoint(pair *modules.RequestResponsePair) {
	e.mu.Lock()
	defer e.mu.Unlock()
	key := pair.Request.URL.String()
	e.endpointStore[key] = pair
}

func (e *Engine) isInterestingForActiveScan(pair *modules.RequestResponsePair) bool {
	// Query parameters = interesting
	if pair.Request.URL.RawQuery != "" {
		return true
	}
	// POST/PUT/PATCH = interesting
	if pair.Request.Method == "POST" || pair.Request.Method == "PUT" || pair.Request.Method == "PATCH" {
		return true
	}
	// JSON/XML responses = interesting
	if pair.Response != nil {
		ct := pair.Response.Header.Get("Content-Type")
		if strings.Contains(ct, "json") || strings.Contains(ct, "xml") {
			return true
		}
	}
	// 403/401 = interesting (for bypass modules)
	if pair.Response != nil && (pair.Response.StatusCode == 403 || pair.Response.StatusCode == 401) {
		return true
	}
	// Login/auth endpoints = interesting
	if isLoginEndpoint(pair.Request.URL.String(), pair.Request.URL.Path) {
		return true
	}
	return false
}

// Export for use by scorer
func isLoginEndpoint(urlStr, path string) bool {
	patterns := []string{"/login", "/signin", "/auth", "/authenticate", "/token", "/oauth"}
	urlLower := strings.ToLower(urlStr)
	for _, p := range patterns {
		if strings.Contains(urlLower, p) {
			return true
		}
	}
	return false
}

func (e *Engine) GetSessions() *SessionContainer {
	return e.sessions
}

func (e *Engine) GetStats() *ScanStats {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.stats
}

func (e *Engine) GetDiscoveredEndpoints() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var endpoints []string
	for k := range e.endpointStore {
		endpoints = append(endpoints, k)
	}
	return endpoints
}

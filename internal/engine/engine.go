package engine

import (
	"crypto/md5"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/mijelblack677-ctrl/aegis/internal/modules"
	"github.com/mijelblack677-ctrl/aegis/internal/modules/passivescan"
	"github.com/mijelblack677-ctrl/aegis/internal/modules/activescan"
	"github.com/mijelblack677-ctrl/aegis/internal/output"
	"github.com/google/uuid"
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
	wordlistManager *WordlistManager
}

func NewEngine() *Engine {
	e := &Engine{
		report:          output.NewReport(),
		endpointStore:   make(map[string]*modules.RequestResponsePair),
		dedupHashes:     make(map[string]bool),
		cookieStore:     make(map[string][]*http.Cookie),
		activeScanQueue: make(chan *modules.RequestResponsePair, 1000),
		wordlistManager: NewWordlistManager(),
	}

	// Register all passive modules
	e.modules = append(e.modules,
		passivescan.NewSecretFinder(),
		passivescan.NewGitExposer(),
		passivescan.NewEndpointAnalyzer(),
		passivescan.NewCookieAnalyzer(),
		passivescan.NewHeaderAnalyzer(),
		passivescan.NewXSSDetector(),
		passivescan.NewTechFingerprinter(),
	)

	// Start active scanning workers
	for i := 0; i < 5; i++ {
		go e.activeScanWorker()
	}

	return e
}

func (e *Engine) ProcessTransaction(pair *modules.RequestResponsePair) {
	// Skip duplicate transactions
	hash := e.hashTransaction(pair)
	e.mu.RLock()
	if e.dedupHashes[hash] {
		e.mu.RUnlock()
		return
	}
	e.mu.RUnlock()

	e.mu.Lock()
	e.dedupHashes[hash] = true
	e.mu.Unlock()

	// Store endpoint for pattern analysis
	e.storeEndpoint(pair)

	// Run passive analysis immediately
	e.wg.Add(1)
	go func(p *modules.RequestResponsePair) {
		defer e.wg.Done()
		for _, m := range e.modules {
			if !m.IsPassive() {
				continue
			}
			vulns, err := m.Run(p)
			if err != nil {
				log.Printf("[-] Module %s error: %v", m.Name(), err)
				continue
			}
			for _, v := range vulns {
				v.ID = uuid.New().String()
				v.Timestamp = time.Now()
				e.mu.Lock()
				e.report.AddVulnerability(v)
				e.mu.Unlock()
				log.Printf("[!] %s: %s (%s)", v.Severity.String(), v.Name, v.URL)
			}
		}
	}(pair)

	// Queue for active scanning if it's an interesting endpoint
	if e.isInterestingForActiveScan(pair) {
		select {
		case e.activeScanQueue <- pair:
		default:
			// Queue full, drop
		}
	}
}

func (e *Engine) activeScanWorker() {
	for pair := range e.activeScanQueue {
		// Run active modules like SQLi, command injection, etc.
		for _, m := range e.modules {
			if m.IsPassive() {
				continue
			}
			vulns, err := m.Run(pair)
			if err != nil {
				log.Printf("[-] Active module %s error: %v", m.Name(), err)
				continue
			}
			for _, v := range vulns {
				e.mu.Lock()
				e.report.AddVulnerability(v)
				e.mu.Unlock()
			}
		}
	}
}

func (e *Engine) WaitAndGenerateReport() *output.Report {
	close(e.activeScanQueue)
	e.wg.Wait()
	return e.report
}

func (e *Engine) hashTransaction(pair *modules.RequestResponsePair) string {
	url := pair.Request.URL.String()
	method := pair.Request.Method
	return fmt.Sprintf("%x", md5.Sum([]byte(method+url)))
}

func (e *Engine) storeEndpoint(pair *modules.RequestResponsePair) {
	e.mu.Lock()
	defer e.mu.Unlock()
	
	url := pair.Request.URL.String()
	e.endpointStore[url] = pair
	
	// Analyze endpoint pattern
	e.wordlistManager.AnalyzePattern(url)
}

func (e *Engine) isInterestingForActiveScan(pair *modules.RequestResponsePair) bool {
	// Check if URL has parameters (query string or body)
	if pair.Request.URL.RawQuery != "" {
		return true
	}
	if pair.Request.Method == "POST" || pair.Request.Method == "PUT" {
		return true
	}
	// Check if response suggests database interaction
	if pair.Response != nil {
		ct := pair.Response.Header.Get("Content-Type")
		if strings.Contains(ct, "json") || strings.Contains(ct, "xml") {
			return true
		}
	}
	return false
}

type WordlistManager struct {
	patterns map[string]int
	suggestions []string
}

func NewWordlistManager() *WordlistManager {
	return &WordlistManager{
		patterns: make(map[string]int),
	}
}

func (wm *WordlistManager) AnalyzePattern(url string) {
	// Extract tokens from URL
	parts := strings.Split(strings.Trim(url, "/"), "/")
	for _, part := range parts {
		// Identify patterns like IDs, slugs, dates
		if isNumeric(part) {
			wm.patterns["{id}"]++
		} else if isUUID(part) {
			wm.patterns["{uuid}"]++
		} else if isSlug(part) {
			wm.patterns["{slug}"]++
		}
	}
}

func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func isUUID(s string) bool {
	return len(s) == 36 && strings.Count(s, "-") == 4
}

func isSlug(s string) bool {
	return strings.Contains(s, "-") && !strings.Contains(s, ".")
}
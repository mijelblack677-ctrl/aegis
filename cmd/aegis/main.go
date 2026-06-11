package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/mijelblack677-ctrl/aegis/internal/engine"
	"github.com/mijelblack677-ctrl/aegis/internal/proxy"
	"github.com/mijelblack677-ctrl/aegis/internal/output"
)

func main() {
	var (
		proxyPort   = flag.Int("port", 8080, "Proxy listening port")
		outputFile  = flag.String("output", "aegis_report.json", "Output JSON report file")
		htmlReport  = flag.String("html", "", "Output HTML report file")
		certDir     = flag.String("cert-dir", "./aegis-certs", "Directory for TLS certificates")
		wordlistOut = flag.String("wordlist", "", "Output file for generated wordlist")
		configFile  = flag.String("config", "", "Configuration file (JSON)")
		scopeFile   = flag.String("scope", "", "Scope file: list of include/exclude hosts")
		profile     = flag.String("profile", "balanced", "Scan profile: fast, balanced, deep")
	)
	flag.Parse()

	log.SetFlags(log.LstdFlags)
	
	printBanner()
	
	// Load configuration
	var config *engine.AegisConfig
	if *configFile != "" {
		var err error
		config, err = engine.LoadConfig(*configFile)
		if err != nil {
			log.Fatalf("[-] Failed to load config: %v", err)
		}
		log.Printf("[+] Loaded configuration from %s", *configFile)
	} else {
		config = &engine.AegisConfig{
			ProxyPort:  *proxyPort,
			OutputFile: *outputFile,
			HTMLReport: *htmlReport,
			WordlistOut: *wordlistOut,
			CertDir:    *certDir,
			ScanProfile: *profile,
		}
	}

	// Initialize engine with scope
	eng := engine.NewEngine()
	
	// Setup scope
	scope := engine.NewScopeManager()
	
	// Always exclude common noise domains
	for _, host := range engine.CommonOutOfScopeHosts() {
		scope.AddExclude(host)
	}
	
	// Add user-defined scope
	if *scopeFile != "" {
		if err := loadScopeFile(*scopeFile, scope); err != nil {
			log.Printf("[-] Failed to load scope file: %v", err)
		}
	}
	
	if config.Scope.Includes != nil {
		for _, inc := range config.Scope.Includes {
			scope.AddInclude(inc)
		}
	}
	if config.Scope.Excludes != nil {
		for _, exc := range config.Scope.Excludes {
			scope.AddExclude(exc)
		}
	}
	
	eng.SetScope(scope)
	
	// Apply rate limits from config
	if config.RateLimit.MinDelayMs > 0 {
		eng.SetRateLimit(time.Duration(config.RateLimit.MinDelayMs)*time.Millisecond, config.RateLimit.MaxParallel)
	}

	// Create proxy
	proxyServer, err := proxy.New(eng, config.CertDir, config.ProxyPort)
	if err != nil {
		log.Fatalf("[-] Failed to create proxy: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		log.Println("\n[+] Shutting down gracefully...")
		cancel()
		proxyServer.Shutdown(ctx)
	}()

	// Start proxy
	go func() {
		if err := proxyServer.Start(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[-] Proxy error: %v", err)
		}
	}()

	printStartupInfo(config)

	<-ctx.Done()
	time.Sleep(3 * time.Second)

	// Generate reports
	report := eng.WaitAndGenerateReport()
	
	if err := output.SaveReport(report, config.OutputFile); err != nil {
		log.Printf("[-] Failed to save JSON report: %v", err)
	} else {
		log.Printf("[+] JSON report saved to %s", config.OutputFile)
	}

	fmt.Println(report.PrintSummary())

	if config.HTMLReport != "" {
		if err := output.GenerateHTMLReport(report, config.HTMLReport); err != nil {
			log.Printf("[-] Failed to generate HTML report: %v", err)
		} else {
			log.Printf("[+] HTML report saved to %s", config.HTMLReport)
		}
	}

	if config.WordlistOut != "" {
		wg := engine.NewWordlistGenerator()
		for _, endpoint := range eng.GetDiscoveredEndpoints() {
			wg.AnalyzeEndpoint(endpoint)
		}
		suggestions := wg.GenerateWordlist()
		if err := os.WriteFile(config.WordlistOut, []byte(strings.Join(suggestions, "\n")), 0644); err != nil {
			log.Printf("[-] Failed to save wordlist: %v", err)
		} else {
			log.Printf("[+] Wordlist saved to %s", config.WordlistOut)
		}
	}

	stats := eng.GetStats()
	log.Printf("[+] Scan complete: %d requests | %d scans | %d vulns | scope: %d endpoints",
		stats.RequestsProcessed, stats.ActiveScansRun, stats.Vulnerabilities, len(eng.GetDiscoveredEndpoints()))
}

func loadScopeFile(filename string, scope *engine.ScopeManager) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "!") {
			scope.AddExclude(strings.TrimPrefix(line, "!"))
		} else {
			scope.AddInclude(line)
		}
	}
	return nil
}

func printBanner() {
	log.Println(strings.Repeat("=", 55))
	log.Println("  🛡️  AEGIS - Advanced Web Vulnerability Hunter")
	log.Println(strings.Repeat("=", 55))
}

func printStartupInfo(config *engine.AegisConfig) {
	log.Printf("[+] Proxy: 127.0.0.1:%d", config.ProxyPort)
	log.Printf("[+] Profile: %s", config.ScanProfile)
	log.Printf("[+] CA Cert: %s/ca.crt", config.CertDir)
	log.Println("[+] Configure browser proxy and start browsing")
	log.Println("[+] Press Ctrl+C to generate report")
	log.Println(strings.Repeat("=", 55))
}

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
		htmlReport  = flag.String("html", "", "Output HTML report file (optional)")
		certDir     = flag.String("cert-dir", "./aegis-certs", "Directory for TLS certificates")
		wordlistOut = flag.String("wordlist", "", "Output file for generated wordlist (optional)")
	)
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println(strings.Repeat("=", 55))
	log.Println("  🛡️  AEGIS - Advanced Web Vulnerability Hunter")
	log.Println(strings.Repeat("=", 55))
	log.Printf("[+] Starting proxy on port %d", *proxyPort)

	eng := engine.NewEngine()

	proxyServer, err := proxy.New(eng, *certDir, *proxyPort)
	if err != nil {
		log.Fatalf("[-] Failed to create proxy: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		log.Println("\n[+] Shutting down gracefully...")
		cancel()
		proxyServer.Shutdown(ctx)
	}()

	go func() {
		if err := proxyServer.Start(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[-] Proxy error: %v", err)
		}
	}()

	log.Printf("[+] Aegis MITM Proxy listening on :%d", *proxyPort)
	log.Printf("[+] Install CA from %s/ca.crt into your browser", *certDir)
	log.Printf("[+] Configure browser proxy to 127.0.0.1:%d", *proxyPort)
	log.Println("[+] Start browsing — vulnerabilities detected in real-time")
	log.Println("[+] Press Ctrl+C to generate final report")
	log.Println(strings.Repeat("=", 55))

	<-ctx.Done()
	time.Sleep(3 * time.Second)

	report := eng.WaitAndGenerateReport()

	// Save JSON report
	if err := output.SaveReport(report, *outputFile); err != nil {
		log.Printf("[-] Failed to save JSON report: %v", err)
	} else {
		log.Printf("[+] JSON report saved to %s", *outputFile)
	}

	// Print summary
	fmt.Println(report.PrintSummary())

	// Generate HTML report
	if *htmlReport != "" {
		if err := output.GenerateHTMLReport(report, *htmlReport); err != nil {
			log.Printf("[-] Failed to generate HTML report: %v", err)
		} else {
			log.Printf("[+] HTML report saved to %s", *htmlReport)
		}
	}

	// Generate wordlist
	if *wordlistOut != "" {
		wg := engine.NewWordlistGenerator()
		for _, endpoint := range eng.GetDiscoveredEndpoints() {
			wg.AnalyzeEndpoint(endpoint)
		}
		suggestions := wg.GenerateWordlist()
		wordlistData := strings.Join(suggestions, "\n")
		if err := os.WriteFile(*wordlistOut, []byte(wordlistData), 0644); err != nil {
			log.Printf("[-] Failed to save wordlist: %v", err)
		} else {
			log.Printf("[+] Wordlist saved to %s", *wordlistOut)
		}
	}

	// Print scan stats
	stats := eng.GetStats()
	log.Printf("[+] Scan Stats: %d requests | %d active scans | %d vulns found",
		stats.RequestsProcessed, stats.ActiveScansRun, stats.Vulnerabilities)
}

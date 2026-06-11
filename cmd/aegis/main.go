package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mijelblack677-ctrl/aegis/internal/engine"
	"github.com/mijelblack677-ctrl/aegis/internal/proxy"
	"github.com/mijelblack677-ctrl/aegis/internal/output"
)

func main() {
	var (
		proxyPort  = flag.Int("port", 8080, "Proxy listening port")
		outputFile = flag.String("output", "aegis_report.json", "Output report file")
		certDir    = flag.String("cert-dir", "./aegis-certs", "Directory for dynamically generated TLS certificates")
	)
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("[+] Aegis - Advanced Web Application Vulnerability Hunter")
	log.Printf("[+] Starting proxy on port %d", *proxyPort)

	// Initialize the central engine with all modules
	eng := engine.NewEngine()
	
	// Create and configure the proxy
	proxyServer, err := proxy.New(eng, *certDir, *proxyPort)
	if err != nil {
		log.Fatalf("[-] Failed to create proxy: %v", err)
	}

	// Setup graceful shutdown
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

	// Start the proxy
	go func() {
		if err := proxyServer.Start(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[-] Proxy error: %v", err)
		}
	}()

	log.Printf("[+] Aegis proxy running on :%d", *proxyPort)
	log.Println("[+] Configure your browser to use this proxy and start browsing")
	log.Println("[+] Press Ctrl+C to stop and generate the report")

	// Wait for shutdown signal
	<-ctx.Done()
	time.Sleep(2 * time.Second) // Allow final transactions to process

	// Generate and save final report
	report := eng.WaitAndGenerateReport()
	if err := output.SaveReport(report, *outputFile); err != nil {
		log.Fatalf("[-] Failed to save report: %v", err)
	}
	
	fmt.Println(report.PrintSummary())
	log.Printf("[+] Report saved to %s", *outputFile)
}
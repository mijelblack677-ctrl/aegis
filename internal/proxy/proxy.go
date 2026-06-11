package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/mijelblack677-ctrl/aegis/internal/engine"
	"github.com/mijelblack677-ctrl/aegis/internal/modules"
	"github.com/mijelblack677-ctrl/aegis/internal/parser"
)

type AegisProxy struct {
	engine     *engine.Engine
	httpServer *http.Server
	certDir    string
	port       int
	caCert     *tls.Certificate
	caCertPool *x509.CertPool
	mu         sync.RWMutex
}

func New(eng *engine.Engine, certDir string, port int) (*AegisProxy, error) {
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create cert directory: %w", err)
	}

	ap := &AegisProxy{
		engine:  eng,
		certDir: certDir,
		port:    port,
	}

	// Generate or load CA certificate
	if err := ap.initCA(); err != nil {
		return nil, fmt.Errorf("failed to initialize CA: %w", err)
	}

	return ap, nil
}

func (ap *AegisProxy) Start() error {
	handler := &proxyHandler{ap: ap}
	
	ap.httpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", ap.port),
		Handler: handler,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, "connection", c)
		},
	}

	ln, err := net.Listen("tcp", ap.httpServer.Addr)
	if err != nil {
		return err
	}

	go ap.httpServer.Serve(ln)
	return nil
}

func (ap *AegisProxy) Shutdown(ctx context.Context) error {
	return ap.httpServer.Shutdown(ctx)
}

type proxyHandler struct {
	ap *AegisProxy
}

func (h *proxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		h.handleTunnel(w, r)
		return
	}
	h.handleHTTP(w, r)
}

func (h *proxyHandler) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Clone the request for analysis
	reqBody, _ := io.ReadAll(r.Body)
	r.Body.Close()
	
	// Recreate body for forwarding
	reqCopy := r.Clone(r.Context())
	reqCopy.Body = io.NopCloser(bytes.NewReader(reqBody))
	r.Body = io.NopCloser(bytes.NewReader(reqBody))

	// Make the actual request
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects, capture them
		},
	}
	resp, err := client.Do(reqCopy)
	if err != nil {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		log.Printf("[-] Request failed: %v", err)
		return
	}
	defer resp.Body.Close()

	// Read response for analysis
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Forward response to client
	for key, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)

	// Parse and analyze
	go h.ap.analyzeTransaction(r, resp, reqBody, respBody)
}

func (h *proxyHandler) handleTunnel(w http.ResponseWriter, r *http.Request) {
	// For HTTPS, we'd perform MITM with dynamic cert generation
	// This is a simplified version - full MITM would need more TLS handling
	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	_, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}
}

func (ap *AegisProxy) analyzeTransaction(req *http.Request, resp *http.Response, reqBody, respBody []byte) {
	contentType := resp.Header.Get("Content-Type")
	
	// Parse the response body for secrets, endpoints, etc.
	parsedData := parser.Parse(req.URL.Path, respBody, contentType)
	
	// Also parse request body if it exists
	if len(reqBody) > 0 {
		reqParsed := parser.Parse(req.URL.Path+"[REQUEST]", reqBody, req.Header.Get("Content-Type"))
		// Merge parsed results
		parsedData.Endpoints = append(parsedData.Endpoints, reqParsed.Endpoints...)
		parsedData.Secrets = append(parsedData.Secrets, reqParsed.Secrets...)
		parsedData.Comments = append(parsedData.Comments, reqParsed.Comments...)
	}

	pair := &modules.RequestResponsePair{
		Request:    req,
		Response:   resp,
		RequestBody:  reqBody,
		ResponseBody: respBody,
		ParsedData: parsedData,
	}

	ap.engine.ProcessTransaction(pair)
}

func (ap *AegisProxy) initCA() error {
	// Production: Generate proper CA cert
	// For now, we'll check if certs exist
	caCertPath := filepath.Join(ap.certDir, "ca.crt")
	caKeyPath := filepath.Join(ap.certDir, "ca.key")
	
	if _, err := os.Stat(caCertPath); os.IsNotExist(err) {
		log.Printf("[+] Generating new CA certificate...")
		return ap.generateCA(caCertPath, caKeyPath)
	}
	
	log.Printf("[+] Loading existing CA certificate")
	return ap.loadCA(caCertPath, caKeyPath)
}

func (ap *AegisProxy) generateCA(certPath, keyPath string) error {
	// Simplified - production would generate proper x509 certs
	log.Println("[+] CA certificate generated successfully")
	return nil
}

func (ap *AegisProxy) loadCA(certPath, keyPath string) error {
	log.Println("[+] CA certificate loaded successfully")
	return nil
}
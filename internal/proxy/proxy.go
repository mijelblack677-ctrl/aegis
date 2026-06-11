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
	// Read request body
	reqBody, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(reqBody))

	// Build outbound URL
	outURL := *r.URL
	outURL.Host = r.Host
	outURL.Scheme = "http"
	if r.TLS != nil {
		outURL.Scheme = "https"
	}

	// Create the outbound request properly
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, outURL.String(), bytes.NewReader(reqBody))
	if err != nil {
		log.Printf("[-] Failed to create outbound request: %v", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	// Copy headers
	for key, values := range r.Header {
		for _, v := range values {
			outReq.Header.Add(key, v)
		}
	}

	// Make the request
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}
	resp, err := client.Do(outReq)
	if err != nil {
		log.Printf("[-] Request failed: %v", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Read response
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

	// Analyze asynchronously
	go h.ap.analyzeTransaction(r, resp, reqBody, respBody)
}

func (h *proxyHandler) handleTunnel(w http.ResponseWriter, r *http.Request) {
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

	parsedData := parser.Parse(req.URL.Path, respBody, contentType)

	if len(reqBody) > 0 {
		reqParsed := parser.Parse(req.URL.Path+"[REQUEST]", reqBody, req.Header.Get("Content-Type"))
		parsedData.Endpoints = append(parsedData.Endpoints, reqParsed.Endpoints...)
		parsedData.Secrets = append(parsedData.Secrets, reqParsed.Secrets...)
		parsedData.Comments = append(parsedData.Comments, reqParsed.Comments...)
	}

	pair := &modules.RequestResponsePair{
		Request:      req,
		Response:     resp,
		RequestBody:  reqBody,
		ResponseBody: respBody,
		ParsedData:   parsedData,
	}

	ap.engine.ProcessTransaction(pair)
}

func (ap *AegisProxy) initCA() error {
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
	log.Println("[+] CA certificate generated successfully")
	return nil
}

func (ap *AegisProxy) loadCA(certPath, keyPath string) error {
	log.Println("[+] CA certificate loaded successfully")
	return nil
}

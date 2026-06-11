package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/mijelblack677-ctrl/aegis/internal/engine"
	"github.com/mijelblack677-ctrl/aegis/internal/modules"
	"github.com/mijelblack677-ctrl/aegis/internal/parser"
)

type AegisProxy struct {
	engine     *engine.Engine
	httpServer *http.Server
	certDir    string
	port       int
	caCert     *x509.Certificate
	caKey      crypto.PrivateKey
	certCache  map[string]*tls.Certificate
	mu         sync.RWMutex
}

func New(eng *engine.Engine, certDir string, port int) (*AegisProxy, error) {
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create cert directory: %w", err)
	}

	ap := &AegisProxy{
		engine:    eng,
		certDir:   certDir,
		port:      port,
		certCache: make(map[string]*tls.Certificate),
	}

	if err := ap.initCA(); err != nil {
		return nil, fmt.Errorf("failed to initialize CA: %w", err)
	}

	return ap, nil
}

func (ap *AegisProxy) Start() error {
	ap.httpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", ap.port),
		Handler: http.HandlerFunc(ap.handleRequest),
	}

	ln, err := net.Listen("tcp", ap.httpServer.Addr)
	if err != nil {
		return err
	}

	log.Printf("[+] Aegis MITM Proxy listening on :%d", ap.port)
	log.Printf("[+] Install the CA certificate from %s/ca.crt into your browser", ap.certDir)
	go ap.httpServer.Serve(ln)
	return nil
}

func (ap *AegisProxy) Shutdown(ctx context.Context) error {
	return ap.httpServer.Shutdown(ctx)
}

func (ap *AegisProxy) handleRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		ap.handleConnect(w, r)
		return
	}
	ap.handleHTTP(w, r)
}

func (ap *AegisProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	host := r.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = host + ":443"
	}

	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	cert, err := ap.getCert(host)
	if err != nil {
		log.Printf("[-] Failed to generate cert for %s: %v", host, err)
		clientConn.Close()
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS12,
	}

	tlsClientConn := tls.Server(clientConn, tlsConfig)
	defer tlsClientConn.Close()

	if err := tlsClientConn.Handshake(); err != nil {
		log.Printf("[-] TLS handshake failed for %s: %v", host, err)
		return
	}

	tlsServerConn, err := tls.Dial("tcp", host, &tls.Config{
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		log.Printf("[-] Failed to connect to %s: %v", host, err)
		return
	}
	defer tlsServerConn.Close()

	// Pipe data bidirectionally while reading HTTP requests
	go ap.pipeAndAnalyze(tlsClientConn, tlsServerConn, host)
	io.Copy(tlsServerConn, tlsClientConn)
}

func (ap *AegisProxy) pipeAndAnalyze(clientConn *tls.Conn, serverConn *tls.Conn, host string) {
	reader := bufio.NewReader(clientConn)
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}

		req.URL.Scheme = "https"
		req.URL.Host = host
		req.RequestURI = ""

		var reqBody []byte
		if req.Body != nil {
			reqBody, _ = io.ReadAll(req.Body)
			req.Body.Close()
			req.Body = io.NopCloser(bytes.NewReader(reqBody))
		}

		// Forward to real server
		resp, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			log.Printf("[-] Failed to forward request: %v", err)
			return
		}

		var respBody []byte
		if resp.Body != nil {
			respBody, _ = io.ReadAll(resp.Body)
			resp.Body.Close()
			resp.Body = io.NopCloser(bytes.NewReader(respBody))
		}

		// Write response back to client
		resp.Write(serverConn)

		// Analyze
		go ap.analyzeTransaction(req, resp, reqBody, respBody)
	}
}

func (ap *AegisProxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	reqBody, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(reqBody))

	outURL := *r.URL
	outURL.Host = r.Host
	if outURL.Scheme == "" {
		outURL.Scheme = "http"
	}

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, outURL.String(), bytes.NewReader(reqBody))
	if err != nil {
		log.Printf("[-] Failed to create outbound request: %v", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	for key, values := range r.Header {
		for _, v := range values {
			outReq.Header.Add(key, v)
		}
	}

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(outReq)
	if err != nil {
		log.Printf("[-] Request failed: %v", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	for key, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)

	go ap.analyzeTransaction(r, resp, reqBody, respBody)
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

	if certData, err := os.ReadFile(caCertPath); err == nil {
		keyData, err := os.ReadFile(caKeyPath)
		if err != nil {
			return err
		}
		return ap.loadCA(certData, keyData)
	}

	log.Printf("[+] Generating new Aegis CA certificate...")

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate CA key: %w", err)
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "Aegis CA",
			Organization: []string{"Aegis Web Security Tool"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create CA cert: %w", err)
	}

	caCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return err
	}

	ap.caCert = caCert
	ap.caKey = caKey

	certOut, _ := os.Create(caCertPath)
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	certOut.Close()

	keyOut, _ := os.Create(caKeyPath)
	keyBytes, _ := x509.MarshalECPrivateKey(caKey)
	pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	keyOut.Close()

	log.Printf("[+] CA certificate saved to %s", caCertPath)
	log.Printf("[+] IMPORTANT: Install this CA in your browser's trusted root store!")
	return nil
}

func (ap *AegisProxy) loadCA(certData, keyData []byte) error {
	certBlock, _ := pem.Decode(certData)
	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return err
	}

	keyBlock, _ := pem.Decode(keyData)
	caKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return err
	}

	ap.caCert = caCert
	ap.caKey = caKey
	log.Printf("[+] CA certificate loaded successfully")
	return nil
}

func (ap *AegisProxy) getCert(host string) (*tls.Certificate, error) {
	hostname, _, err := net.SplitHostPort(host)
	if err != nil {
		hostname = host
	}

	ap.mu.RLock()
	if cert, ok := ap.certCache[hostname]; ok {
		ap.mu.RUnlock()
		return cert, nil
	}
	ap.mu.RUnlock()

	cert, err := ap.generateCert(hostname)
	if err != nil {
		return nil, err
	}

	ap.mu.Lock()
	ap.certCache[hostname] = cert
	ap.mu.Unlock()

	return cert, nil
}

func (ap *AegisProxy) generateCert(hostname string) (*tls.Certificate, error) {
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: hostname,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}

	template.DNSNames = append(template.DNSNames, hostname)
	if ip := net.ParseIP(hostname); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ap.caCert, &serverKey.PublicKey, ap.caKey)
	if err != nil {
		return nil, err
	}

	return &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  serverKey,
	}, nil
}

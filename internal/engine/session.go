package engine

import (
	"net/http"
	"strings"
	"sync"
)

type SessionContainer struct {
	sessions map[string]*UserSession // role -> session
	mu       sync.RWMutex
}

type UserSession struct {
	Role    string
	Cookies []*http.Cookie
	Headers map[string]string
	Tokens  map[string]string // CSRF tokens, API keys, etc.
}

func NewSessionContainer() *SessionContainer {
	return &SessionContainer{
		sessions: make(map[string]*UserSession),
	}
}

// CaptureSession extracts session information from a response
func (sc *SessionContainer) CaptureSession(role string, resp *http.Response) {
	if resp == nil {
		return
	}

	session := &UserSession{
		Role:    role,
		Cookies: resp.Cookies(),
		Headers: make(map[string]string),
		Tokens:  make(map[string]string),
	}

	// Capture important headers
	for _, key := range []string{"Authorization", "X-CSRF-Token", "X-API-Key"} {
		if val := resp.Header.Get(key); val != "" {
			session.Headers[key] = val
		}
	}

	sc.mu.Lock()
	sc.sessions[role] = session
	sc.mu.Unlock()
}

// CaptureSessionFromRequest extracts session from a request
func (sc *SessionContainer) CaptureSessionFromRequest(role string, req *http.Request) {
	if req == nil {
		return
	}

	session := &UserSession{
		Role:    role,
		Cookies: req.Cookies(),
		Headers: make(map[string]string),
		Tokens:  make(map[string]string),
	}

	for _, key := range []string{"Authorization", "X-CSRF-Token", "X-API-Key"} {
		if val := req.Header.Get(key); val != "" {
			session.Headers[key] = val
		}
	}

	sc.mu.Lock()
	sc.sessions[role] = session
	sc.mu.Unlock()
}

// GetSession returns a session for replay
func (sc *SessionContainer) GetSession(role string) *UserSession {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return sc.sessions[role]
}

// GetAllSessions returns all captured sessions
func (sc *SessionContainer) GetAllSessions() []*UserSession {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	var sessions []*UserSession
	for _, s := range sc.sessions {
		sessions = append(sessions, s)
	}
	return sessions
}

// ApplySession adds session cookies/headers to a request
func (s *UserSession) ApplySession(req *http.Request) {
	if s == nil {
		return
	}
	for _, cookie := range s.Cookies {
		req.AddCookie(cookie)
	}
	for key, val := range s.Headers {
		req.Header.Set(key, val)
	}
}

// DetectRoleFromURL tries to determine the user's role from URL patterns
func DetectRoleFromURL(url string) string {
	urlLower := strings.ToLower(url)
	if strings.Contains(urlLower, "/admin") || strings.Contains(urlLower, "/manage") {
		return "admin"
	}
	if strings.Contains(urlLower, "/login") || strings.Contains(urlLower, "/signin") {
		return "unauthenticated"
	}
	if strings.Contains(urlLower, "/api/me") || strings.Contains(urlLower, "/profile") {
		return "authenticated"
	}
	return "unknown"
}

// IsSessionExpired checks if a session might be expired
func IsSessionExpired(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	return resp.StatusCode == 401 || resp.StatusCode == 403 ||
		strings.Contains(resp.Header.Get("Location"), "login")
}

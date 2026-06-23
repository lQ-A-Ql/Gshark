package transport

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

type apiError struct {
	Error string `json:"error"`
}

const maxJSONBody = 1 << 20 // 1MB

var sensitivePathPrefixes = []string{
	os.TempDir(),
	filepath.Join("meow-traffic"),
	"/tmp/",
	"/var/",
	"C:\\Users\\",
	"C:\\Windows\\",
}

func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBody)
	return json.NewDecoder(r.Body).Decode(dst)
}

func writeJSON(w http.ResponseWriter, code int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, code int, message string) {
	writeJSON(w, code, apiError{Error: message})
}

func sanitizeErrorMessage(err error) string {
	if err == nil {
		return "internal error"
	}
	msg := err.Error()
	lower := strings.ToLower(msg)
	for _, prefix := range sensitivePathPrefixes {
		if strings.Contains(lower, strings.ToLower(prefix)) {
			return "internal error"
		}
	}
	if len(msg) > 200 {
		return msg[:200]
	}
	return msg
}

func parseInt64(s string, fallback int64) int64 {
	if s == "" {
		return fallback
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return fallback
	}
	return v
}

func (s *Server) currentMCPStatus(r *http.Request) model.MCPStatus {
	endpoint := mcpEndpointForRequest(r)
	if s.toolRuntime == nil {
		return model.MCPStatus{
			Config:          model.MCPConfig{},
			Enabled:         false,
			Endpoint:        endpoint,
			Transport:       "streamable-http",
			AuthRequired:    false,
			ReadOnly:        true,
			RemoteSupported: false,
			StdioSupported:  false,
			LastError:       "tool runtime service unavailable",
		}
	}
	status := s.toolRuntime.MCPStatus(s.authRequired())
	status.Endpoint = endpoint
	return status
}

func mcpEndpointForRequest(r *http.Request) string {
	if r == nil {
		return "http://127.0.0.1:17891/api/mcp"
	}
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	host := r.Host
	if host == "" {
		host = "127.0.0.1:17891"
	}
	return scheme + "://" + host + "/api/mcp"
}

func (s *Server) authRequired() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.TrimSpace(s.authToken) != ""
}

var allowedLocalOrigins = map[string]bool{
	"127.0.0.1":       true,
	"localhost":       true,
	"::1":             true,
	"wails.localhost": true,
}

var allowedOriginPorts = map[string]bool{
	"":      true, // no explicit port
	"80":    true,
	"443":   true,
	"17891": true,
	"34115": true,
	"34116": true,
	"5173":  true,
	"4173":  true,
}

func isAllowedOrigin(origin string) bool {
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return false
	}
	if !allowedLocalOrigins[strings.ToLower(parsed.Hostname())] {
		return false
	}
	port := parsed.Port()
	if port == "" && (scheme == "http" || scheme == "https") {
		return true
	}
	return allowedOriginPorts[port]
}

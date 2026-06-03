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

func (s *Server) currentMCPStatus() model.MCPStatus {
	if s.toolRuntime == nil {
		return model.MCPStatus{
			Config:          model.MCPConfig{},
			Enabled:         false,
			Endpoint:        "http://127.0.0.1:17891/api/mcp",
			Transport:       "streamable-http",
			AuthRequired:    false,
			ReadOnly:        true,
			RemoteSupported: false,
			StdioSupported:  false,
			LastError:       "tool runtime service unavailable",
		}
	}
	return s.toolRuntime.MCPStatus(s.authRequired())
}

func (s *Server) authRequired() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.TrimSpace(s.authToken) != ""
}

func isAllowedOrigin(origin string) bool {
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}
	switch strings.ToLower(parsed.Hostname()) {
	case "127.0.0.1", "localhost", "::1", "wails.localhost":
		return true
	default:
		return false
	}
}

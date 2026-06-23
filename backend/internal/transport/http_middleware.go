package transport

import (
	"bufio"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"log"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/gshark/sentinel/backend/internal/model"
)

func requireMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method != method {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return false
	}
	return true
}

func withRecovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("transport: panic recovered: %v\n%s", rec, debug.Stack())
				writeError(w, http.StatusInternalServerError, "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := strings.TrimSpace(r.Header.Get("Origin"))
		if origin != "" {
			if !isAllowedOrigin(origin) {
				http.Error(w, "forbidden origin", http.StatusForbidden)
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
		}
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Meow-Traffic-Auth")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		token := s.authToken
		s.mu.Unlock()

		if token == "" || r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}

		candidate := strings.TrimSpace(r.Header.Get("Authorization"))
		if strings.HasPrefix(strings.ToLower(candidate), "bearer ") {
			candidate = strings.TrimSpace(candidate[7:])
		}
		if candidate == "" {
			candidate = strings.TrimSpace(r.Header.Get("X-Meow-Traffic-Auth"))
		}
		if !constantTimeTokenMatch(candidate, token) {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		next.ServeHTTP(w, r)
	})
}

func constantTimeTokenMatch(candidate, token string) bool {
	if token == "" {
		return candidate == ""
	}
	// Use SHA-256 to normalize length before constant-time comparison,
	// avoiding timing leaks from length differences.
	candidateHash := sha256.Sum256([]byte(candidate))
	tokenHash := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(candidateHash[:], tokenHash[:]) == 1
}

func (s *Server) withAudit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" || r.URL.Path == "/api/events" || r.URL.Path == "/api/audit/logs" {
			next.ServeHTTP(w, r)
			return
		}

		s.mu.Lock()
		authEnabled := strings.TrimSpace(s.authToken) != ""
		s.mu.Unlock()

		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)

		entry := model.AuditEntry{
			Time:          time.Now().Format(time.RFC3339),
			Method:        r.Method,
			Path:          r.URL.Path,
			Action:        classifyAuditAction(r.URL.Path, r.Method),
			Risk:          classifyAuditRisk(r.URL.Path, r.Method),
			Origin:        strings.TrimSpace(r.Header.Get("Origin")),
			RemoteAddr:    strings.TrimSpace(r.RemoteAddr),
			Status:        recorder.status,
			Authenticated: !authEnabled || recorder.status != http.StatusUnauthorized,
		}
		s.appendAuditEntry(entry)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

var (
	_ http.Flusher = (*statusRecorder)(nil)
)

func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := r.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, fmt.Errorf("statusRecorder: underlying ResponseWriter does not implement http.Hijacker")
}

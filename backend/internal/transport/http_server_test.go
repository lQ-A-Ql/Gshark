package transport

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestWithCORSAllowsLoopbackDeletePreflight(t *testing.T) {
	handler := withCORS(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodOptions, "/api/analysis/vehicle/dbc", nil)
	req.Header.Set("Origin", "http://127.0.0.1:5173")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected preflight to succeed, got %d", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://127.0.0.1:5173" {
		t.Fatalf("unexpected allow origin %q", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Methods"); got != "GET,POST,DELETE,OPTIONS" {
		t.Fatalf("unexpected allow methods %q", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Headers"); got != "Authorization, Content-Type, X-GShark-Auth" {
		t.Fatalf("unexpected allow headers %q", got)
	}
}

func TestWithCORSRejectsUnexpectedOrigin(t *testing.T) {
	handler := withCORS(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden origin, got %d", rec.Code)
	}
}

func TestWithAuthRequiresMatchingToken(t *testing.T) {
	server := &Server{}
	server.SetAuthToken("secret-token")
	handler := server.withAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	unauthorized := httptest.NewRequest(http.MethodGet, "/api/packets", nil)
	unauthorizedRec := httptest.NewRecorder()
	handler.ServeHTTP(unauthorizedRec, unauthorized)
	if unauthorizedRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized request to fail, got %d", unauthorizedRec.Code)
	}

	authorized := httptest.NewRequest(http.MethodGet, "/api/packets", nil)
	authorized.Header.Set("Authorization", "Bearer secret-token")
	authorizedRec := httptest.NewRecorder()
	handler.ServeHTTP(authorizedRec, authorized)
	if authorizedRec.Code != http.StatusOK {
		t.Fatalf("expected authorized request to succeed, got %d", authorizedRec.Code)
	}
}

func TestWithAuthAllowsTrustedDesktopOriginWithoutToken(t *testing.T) {
	server := &Server{}
	server.SetAuthToken("secret-token")
	handler := server.withAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/tools/tshark", nil)
	req.Header.Set("Origin", "http://wails.localhost")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected trusted desktop origin request to succeed, got %d", rec.Code)
	}
}

func TestWithAuditRecordsSensitiveRequests(t *testing.T) {
	server := &Server{}
	handler := server.withAudit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/plugins/add", nil)
	req.Header.Set("Origin", "http://127.0.0.1:5173")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected wrapped handler status, got %d", rec.Code)
	}

	server.auditMu.Lock()
	defer server.auditMu.Unlock()
	if len(server.auditLogs) != 1 {
		t.Fatalf("expected 1 audit log entry, got %d", len(server.auditLogs))
	}
	entry := server.auditLogs[0]
	if entry.Action != "plugin.add" || entry.Risk != "high" || entry.Status != http.StatusAccepted {
		t.Fatalf("unexpected audit entry: %+v", entry)
	}
}

func TestHandleAuditLogsReturnsRecordedEntries(t *testing.T) {
	server := &Server{
		auditLogs: []model.AuditEntry{
			{
				Time:          "2026-03-28T18:00:00+08:00",
				Method:        http.MethodPost,
				Path:          "/api/plugins/add",
				Action:        "plugin.add",
				Risk:          "high",
				Status:        http.StatusOK,
				Authenticated: true,
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/audit/logs", nil)
	rec := httptest.NewRecorder()
	server.handleAuditLogs(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected audit logs endpoint to succeed, got %d", rec.Code)
	}

	var payload []model.AuditEntry
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode audit log payload: %v", err)
	}
	if len(payload) != 1 || payload[0].Action != "plugin.add" {
		t.Fatalf("unexpected audit log payload: %+v", payload)
	}
}

func TestUploadedFileLifecycleCleansInactiveFiles(t *testing.T) {
	dir := t.TempDir()
	makeFile := func(name string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(name), 0o644); err != nil {
			t.Fatalf("WriteFile(%q) error = %v", path, err)
		}
		return path
	}

	server := &Server{uploadedFiles: map[string]struct{}{}}
	first := makeFile("first.pcapng")
	second := makeFile("second.pcapng")
	third := makeFile("third.pcapng")

	server.registerUploadedFile(first)
	server.registerUploadedFile(second)

	if _, err := os.Stat(first); !os.IsNotExist(err) {
		t.Fatalf("expected first upload to be reclaimed, stat error = %v", err)
	}
	if _, err := os.Stat(second); err != nil {
		t.Fatalf("expected second upload to remain, stat error = %v", err)
	}

	server.promoteUploadedFile(second)
	server.registerUploadedFile(third)

	if _, err := os.Stat(second); err != nil {
		t.Fatalf("expected active upload to remain, stat error = %v", err)
	}
	server.promoteUploadedFile(third)

	if _, err := os.Stat(second); !os.IsNotExist(err) {
		t.Fatalf("expected previous active upload to be reclaimed, stat error = %v", err)
	}
	if _, err := os.Stat(third); err != nil {
		t.Fatalf("expected current active upload to remain, stat error = %v", err)
	}

	server.cleanupUploadedFiles()
	if _, err := os.Stat(third); !os.IsNotExist(err) {
		t.Fatalf("expected cleanup to remove current upload, stat error = %v", err)
	}
}

package transport

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gshark/sentinel/backend/internal/engine"
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

func TestHandleC2AnalysisReturnsSkeleton(t *testing.T) {
	server := NewServer(engine.NewService(nil, nil), NewHub())
	req := httptest.NewRequest(http.MethodGet, "/api/c2-analysis", nil)
	rec := httptest.NewRecorder()

	server.handleC2Analysis(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected c2 analysis endpoint to succeed, got %d body=%s", rec.Code, rec.Body.String())
	}

	var payload model.C2SampleAnalysis
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode c2 analysis payload: %v", err)
	}
	if payload.CS.Candidates == nil || payload.VShell.Candidates == nil {
		t.Fatalf("expected initialized family payload, got %+v", payload)
	}
}

func TestHandleMiscModulesReturnsBuiltinsAndCustomModules(t *testing.T) {
	server := NewServer(nil, NewHub())
	err := server.RegisterMiscModule(NewMiscRouteModule(model.MiscModuleManifest{
		ID:              "custom-demo",
		Kind:            "custom",
		Title:           "Custom Demo",
		Summary:         "custom misc module",
		Tags:            []string{"Custom"},
		APIPrefix:       "/api/tools/misc/custom-demo",
		DocsPath:        "docs/misc-module-interface.md",
		RequiresCapture: false,
	}, func(mux *http.ServeMux, _ *Server) {
		mux.HandleFunc("/api/tools/misc/custom-demo/ping", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, map[string]string{"message": "pong"})
		})
	}))
	if err != nil {
		t.Fatalf("RegisterMiscModule error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/tools/misc/modules", nil)
	rec := httptest.NewRecorder()
	server.handleMiscModules(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected misc modules endpoint to succeed, got %d", rec.Code)
	}

	var payload []model.MiscModuleManifest
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode misc modules payload: %v", err)
	}
	if len(payload) < 3 {
		t.Fatalf("expected built-in and custom misc modules, got %+v", payload)
	}
	if !containsMiscModule(payload, "winrm-decrypt") {
		t.Fatalf("expected built-in winrm module in payload: %+v", payload)
	}
	payloadDecoder, ok := findMiscModule(payload, "payload-webshell-decoder")
	if !ok {
		t.Fatalf("expected built-in payload decoder module in payload: %+v", payload)
	}
	if payloadDecoder.APIPrefix != "/api/streams" || payloadDecoder.RequiresCapture || !payloadDecoder.SupportsExport || !payloadDecoder.Cancellable {
		t.Fatalf("unexpected payload decoder manifest: %+v", payloadDecoder)
	}
	if payloadDecoder.ProtocolDomain != "Payload / WebShell" {
		t.Fatalf("unexpected payload decoder protocol domain: %+v", payloadDecoder)
	}
	if !containsMiscModule(payload, "smb3-session-key") {
		t.Fatalf("expected built-in smb3 module in payload: %+v", payload)
	}
	if !containsMiscModule(payload, "custom-demo") {
		t.Fatalf("expected custom module in payload: %+v", payload)
	}
}

func TestHandleImportMiscModulePackageAndInvoke(t *testing.T) {
	server := NewServer(engine.NewService(nil, nil), NewHub())
	moduleID := fmt.Sprintf("echo-demo-test-%d", time.Now().UnixNano())

	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", moduleID+".zip")
	if err != nil {
		t.Fatalf("CreateFormFile() error = %v", err)
	}
	if _, err := part.Write(testMiscModuleZip(t, moduleID)); err != nil {
		t.Fatalf("zip write error = %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("multipart close error = %v", err)
	}

	importReq := httptest.NewRequest(http.MethodPost, "/api/tools/misc/import", body)
	importReq.Header.Set("Content-Type", writer.FormDataContentType())
	importRec := httptest.NewRecorder()
	server.handleImportMiscModulePackage(importRec, importReq)

	if importRec.Code != http.StatusOK {
		t.Fatalf("expected import endpoint to succeed, got %d body=%s", importRec.Code, importRec.Body.String())
	}

	var imported model.MiscModulePackageImportResult
	if err := json.Unmarshal(importRec.Body.Bytes(), &imported); err != nil {
		t.Fatalf("failed to decode import payload: %v", err)
	}
	if imported.Module.ID != moduleID {
		t.Fatalf("expected echo-demo import result, got %+v", imported)
	}

	runReq := httptest.NewRequest(http.MethodPost, "/api/tools/misc/packages/"+moduleID+"/invoke", strings.NewReader(`{"values":{"message":"hello"}}`))
	runRec := httptest.NewRecorder()
	server.handlePackagedMiscModuleRoute(runRec, runReq)

	if runRec.Code != http.StatusOK {
		t.Fatalf("expected invoke endpoint to succeed, got %d body=%s", runRec.Code, runRec.Body.String())
	}

	var runResult model.MiscModuleRunResult
	if err := json.Unmarshal(runRec.Body.Bytes(), &runResult); err != nil {
		t.Fatalf("failed to decode invoke payload: %v", err)
	}
	if runResult.Text != "hello" {
		t.Fatalf("unexpected invoke payload: %+v", runResult)
	}
}

func TestHandleDeletePackagedMiscModule(t *testing.T) {
	server := NewServer(engine.NewService(nil, nil), NewHub())
	moduleID := fmt.Sprintf("delete-demo-%d", time.Now().UnixNano())

	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", moduleID+".zip")
	if err != nil {
		t.Fatalf("CreateFormFile() error = %v", err)
	}
	if _, err := part.Write(testMiscModuleZip(t, moduleID)); err != nil {
		t.Fatalf("zip write error = %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("multipart close error = %v", err)
	}

	importReq := httptest.NewRequest(http.MethodPost, "/api/tools/misc/import", body)
	importReq.Header.Set("Content-Type", writer.FormDataContentType())
	importRec := httptest.NewRecorder()
	server.handleImportMiscModulePackage(importRec, importReq)
	if importRec.Code != http.StatusOK {
		t.Fatalf("expected import endpoint to succeed, got %d body=%s", importRec.Code, importRec.Body.String())
	}

	deleteReq := httptest.NewRequest(http.MethodDelete, "/api/tools/misc/packages/"+moduleID, nil)
	deleteRec := httptest.NewRecorder()
	server.handlePackagedMiscModuleRoute(deleteRec, deleteReq)
	if deleteRec.Code != http.StatusOK {
		t.Fatalf("expected delete endpoint to succeed, got %d body=%s", deleteRec.Code, deleteRec.Body.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(deleteRec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode delete payload: %v", err)
	}
	if payload["deleted"] != true {
		t.Fatalf("unexpected delete payload: %+v", payload)
	}

	modulesReq := httptest.NewRequest(http.MethodGet, "/api/tools/misc/modules", nil)
	modulesRec := httptest.NewRecorder()
	server.handleMiscModules(modulesRec, modulesReq)
	var modules []model.MiscModuleManifest
	if err := json.Unmarshal(modulesRec.Body.Bytes(), &modules); err != nil {
		t.Fatalf("failed to decode modules payload: %v", err)
	}
	if containsMiscModule(modules, moduleID) {
		t.Fatalf("expected deleted module %q to be absent, got %+v", moduleID, modules)
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

func TestBroadcastPrioritizesStatusEventsWhenClientBufferIsFull(t *testing.T) {
	server := &Server{
		clients: map[chan event]struct{}{},
	}
	ch := make(chan event, 4)
	server.clients[ch] = struct{}{}

	for i := 0; i < cap(ch); i++ {
		ch <- event{Type: "packet", Data: i}
	}

	server.broadcast(event{Type: "status", Data: map[string]string{"message": "解析完成"}})

	events := drainEvents(ch)
	if len(events) == 0 {
		t.Fatal("expected buffered events after broadcast")
	}
	if events[len(events)-1].Type != "status" {
		t.Fatalf("expected latest event to be status, got %+v", events[len(events)-1])
	}
	for _, ev := range events {
		if ev.Type != "packet" && ev.Type != "status" {
			t.Fatalf("unexpected event type %q", ev.Type)
		}
	}
}

func TestBroadcastRetainsNewestControlEventsUnderPressure(t *testing.T) {
	server := &Server{
		clients: map[chan event]struct{}{},
	}
	ch := make(chan event, 3)
	server.clients[ch] = struct{}{}

	ch <- event{Type: "status", Data: map[string]string{"message": "old-1"}}
	ch <- event{Type: "status", Data: map[string]string{"message": "old-2"}}
	ch <- event{Type: "status", Data: map[string]string{"message": "old-3"}}

	server.broadcast(event{Type: "error", Data: map[string]string{"message": "latest-error"}})

	events := drainEvents(ch)
	if len(events) != cap(ch) {
		t.Fatalf("expected %d control events after rebalance, got %d", cap(ch), len(events))
	}
	if events[len(events)-1].Type != "error" {
		t.Fatalf("expected latest event to be error, got %+v", events[len(events)-1])
	}
	if payload, ok := events[0].Data.(map[string]string); ok && strings.TrimSpace(payload["message"]) == "old-1" {
		t.Fatalf("expected oldest control event to be dropped, events=%+v", events)
	}
}

func drainEvents(ch chan event) []event {
	out := make([]event, 0, cap(ch))
	for {
		select {
		case ev := <-ch:
			out = append(out, ev)
		default:
			return out
		}
	}
}

func containsMiscModule(items []model.MiscModuleManifest, id string) bool {
	_, ok := findMiscModule(items, id)
	return ok
}

func findMiscModule(items []model.MiscModuleManifest, id string) (model.MiscModuleManifest, bool) {
	for _, item := range items {
		if item.ID == id {
			return item, true
		}
	}
	return model.MiscModuleManifest{}, false
}

func testMiscModuleZip(t *testing.T, moduleID string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	files := map[string]string{
		moduleID + `/manifest.json`: `{"id":"` + moduleID + `","title":"Echo Demo","summary":"demo","backend":"backend.js"}`,
		moduleID + `/api.json`:      `{"method":"POST","entry":"backend.js"}`,
		moduleID + `/form.json`:     `{"fields":[{"name":"message","label":"Message","type":"textarea"}]}`,
		moduleID + `/backend.js`:    `export function onRequest(input) { return { text: String(input.values.message || "") }; }`,
	}
	for name, content := range files {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatalf("zip Create(%q) error = %v", name, err)
		}
		if _, err := entry.Write([]byte(content)); err != nil {
			t.Fatalf("zip Write(%q) error = %v", name, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("zip Close() error = %v", err)
	}
	return buffer.Bytes()
}

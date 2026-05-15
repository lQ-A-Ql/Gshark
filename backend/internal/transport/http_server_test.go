package transport

import (
	"archive/zip"
	"bytes"
	"context"
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
	"github.com/gshark/sentinel/backend/internal/miscpkg"
	"github.com/gshark/sentinel/backend/internal/model"
)

func newTestServerWithTempMiscPackages(t *testing.T) *Server {
	t.Helper()

	server := NewServer(engine.NewService(nil, nil), NewHub())
	manager := miscpkg.NewManager()
	if err := manager.LoadFromDir(t.TempDir()); err != nil {
		t.Fatalf("LoadFromDir(temp misc package dir) error = %v", err)
	}
	server.miscPkgMgr = manager
	return server
}

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

func TestHandleRuntimeIdentityReportsServiceAndAuthState(t *testing.T) {
	server := &Server{}
	server.SetAuthToken("secret-token")

	req := httptest.NewRequest(http.MethodGet, "/api/runtime/identity", nil)
	rec := httptest.NewRecorder()
	server.handleRuntimeIdentity(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected runtime identity endpoint to succeed, got %d", rec.Code)
	}

	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode runtime identity payload: %v", err)
	}
	if got := payload["service"]; got != "gshark-sentinel" {
		t.Fatalf("unexpected service value: %#v", got)
	}
	if got := payload["auth_enabled"]; got != true {
		t.Fatalf("unexpected auth_enabled value: %#v", got)
	}
}

func TestHandlerRegistersCoreReadRoutes(t *testing.T) {
	server := NewServer(engine.NewService(nil, nil), NewHub())
	handler := server.Handler()
	tests := []struct {
		path string
		want int
	}{
		{path: "/health", want: http.StatusOK},
		{path: "/api/runtime/identity", want: http.StatusOK},
		{path: "/api/capture/status", want: http.StatusOK},
		{path: "/api/packets/page?cursor=0&limit=1", want: http.StatusOK},
		{path: "/api/streams/index?protocol=tcp", want: http.StatusOK},
		{path: "/api/evidence", want: http.StatusOK},
		{path: "/api/tools/misc/modules", want: http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tt.path, nil))
			if rec.Code != tt.want {
				t.Fatalf("%s status = %d, want %d body=%s", tt.path, rec.Code, tt.want, rec.Body.String())
			}
		})
	}
}

func TestHandlerRegistersMutatingRouteMethodPolicy(t *testing.T) {
	server := NewServer(engine.NewService(nil, nil), NewHub())
	handler := server.Handler()
	tests := []struct {
		name        string
		path        string
		badMethod   string
		goodMethod  string
		goodStatus  int
		goodPayload string
	}{
		{
			name:        "capture stop",
			path:        "/api/capture/stop",
			badMethod:   http.MethodGet,
			goodMethod:  http.MethodPost,
			goodStatus:  http.StatusOK,
			goodPayload: `{"status":"stopped"}`,
		},
		{
			name:        "capture prepare replacement",
			path:        "/api/capture/prepare-replacement",
			badMethod:   http.MethodGet,
			goodMethod:  http.MethodPost,
			goodStatus:  http.StatusOK,
			goodPayload: `{"status":"prepared"}`,
		},
		{
			name:        "capture close",
			path:        "/api/capture/close",
			badMethod:   http.MethodGet,
			goodMethod:  http.MethodPost,
			goodStatus:  http.StatusOK,
			goodPayload: `{"status":"closed"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name+" rejects bad method", func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(tt.badMethod, tt.path, nil))
			if rec.Code != http.StatusMethodNotAllowed {
				t.Fatalf("%s %s status = %d, want %d body=%s", tt.badMethod, tt.path, rec.Code, http.StatusMethodNotAllowed, rec.Body.String())
			}
		})

		t.Run(tt.name+" accepts good method", func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(tt.goodMethod, tt.path, nil))
			if rec.Code != tt.goodStatus {
				t.Fatalf("%s %s status = %d, want %d body=%s", tt.goodMethod, tt.path, rec.Code, tt.goodStatus, rec.Body.String())
			}
			if body := strings.TrimSpace(rec.Body.String()); body != tt.goodPayload {
				t.Fatalf("%s %s body = %s, want %s", tt.goodMethod, tt.path, body, tt.goodPayload)
			}
		})
	}
}

func TestHandlerRegistersPacketStreamRoutes(t *testing.T) {
	server := NewServer(nil, NewHub())
	server.capture = contractCaptureService{}
	handler := server.Handler()
	tests := []struct {
		name string
		path string
	}{
		{name: "packets", path: "/api/packets"},
		{name: "packets page", path: "/api/packets/page?cursor=0&limit=1"},
		{name: "packet locate", path: "/api/packets/locate?id=7&limit=1"},
		{name: "packet detail", path: "/api/packet?id=7"},
		{name: "packet raw", path: "/api/packet/raw?id=7"},
		{name: "packet layers", path: "/api/packet/layers?id=7"},
		{name: "stream index", path: "/api/streams/index?protocol=tcp"},
		{name: "http stream", path: "/api/streams/http?streamId=3"},
		{name: "raw stream", path: "/api/streams/raw?protocol=tcp&streamId=3"},
		{name: "raw stream page", path: "/api/streams/raw/page?protocol=tcp&streamId=3&cursor=0&limit=1"},
		{name: "payload sources", path: "/api/streams/payload-sources?limit=1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tt.path, nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("%s status = %d, want %d body=%s", tt.path, rec.Code, http.StatusOK, rec.Body.String())
			}
		})
	}
}

func TestHandlerRegistersStreamMutationRoutes(t *testing.T) {
	server := NewServer(nil, NewHub())
	server.capture = contractCaptureService{}
	handler := server.Handler()
	tests := []struct {
		name       string
		path       string
		payload    string
		wantKeys   []string
		badMethod  string
		goodMethod string
		goodStatus int
		badStatus  int
	}{
		{
			name:       "stream decode",
			path:       "/api/streams/decode",
			payload:    `{"payload":"SGVsbG8=","decoder":"base64"}`,
			wantKeys:   []string{"decoder", "summary", "text", "bytes_hex", "encoding"},
			badMethod:  http.MethodGet,
			goodMethod: http.MethodPost,
			goodStatus: http.StatusOK,
			badStatus:  http.StatusMethodNotAllowed,
		},
		{
			name:       "stream inspect",
			path:       "/api/streams/inspect",
			payload:    `{"payload":"cmd=whoami"}`,
			wantKeys:   []string{"candidates"},
			badMethod:  http.MethodGet,
			goodMethod: http.MethodPost,
			goodStatus: http.StatusOK,
			badStatus:  http.StatusMethodNotAllowed,
		},
		{
			name:       "stream payloads",
			path:       "/api/streams/payloads",
			payload:    `{"protocol":"tcp","stream_id":3,"patches":[{"index":0,"body":"patched"}]}`,
			wantKeys:   []string{"stream_id", "protocol", "chunks"},
			badMethod:  http.MethodGet,
			goodMethod: http.MethodPost,
			goodStatus: http.StatusOK,
			badStatus:  http.StatusMethodNotAllowed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name+" rejects bad method", func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(tt.badMethod, tt.path, nil))
			if rec.Code != tt.badStatus {
				t.Fatalf("%s %s status = %d, want %d body=%s", tt.badMethod, tt.path, rec.Code, tt.badStatus, rec.Body.String())
			}
		})

		t.Run(tt.name+" accepts post", func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(tt.goodMethod, tt.path, strings.NewReader(tt.payload)))
			if rec.Code != tt.goodStatus {
				t.Fatalf("%s %s status = %d, want %d body=%s", tt.goodMethod, tt.path, rec.Code, tt.goodStatus, rec.Body.String())
			}
			var payload map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
				t.Fatalf("decode %s response: %v body=%s", tt.name, err, rec.Body.String())
			}
			for _, key := range tt.wantKeys {
				if _, ok := payload[key]; !ok {
					t.Fatalf("%s response missing key %q: %#v", tt.name, key, payload)
				}
			}
		})
	}
}

func TestHandlerRegistersPluginWriteRoutes(t *testing.T) {
	plugins := &fakePluginService{}
	server := &Server{plugins: plugins}
	handler := server.Handler()

	t.Run("plugin add", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/plugins/add", strings.NewReader(`{"id":"plug-1","name":"Demo","version":"1.0.0","tag":"demo","author":"qa","enabled":true}`))
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected add plugin route to succeed, got %d body=%s", rec.Code, rec.Body.String())
		}
		var payload model.Plugin
		if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
			t.Fatalf("decode add plugin payload: %v", err)
		}
		if payload.ID != "plug-1" || payload.Enabled != true {
			t.Fatalf("unexpected add plugin payload: %+v", payload)
		}
		if !plugins.addCalled {
			t.Fatal("expected AddPlugin to be called")
		}
	})

	t.Run("plugin delete", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodDelete, "/api/plugins/delete?id=plug-1", nil)
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected delete plugin route to succeed, got %d body=%s", rec.Code, rec.Body.String())
		}
		var payload map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
			t.Fatalf("decode delete plugin payload: %v", err)
		}
		if got := payload["id"]; got != "plug-1" {
			t.Fatalf("unexpected delete payload id: %#v", got)
		}
		if got := payload["deleted"]; got != true {
			t.Fatalf("unexpected delete payload deleted flag: %#v", got)
		}
		if !plugins.deleteCalled {
			t.Fatal("expected DeletePlugin to be called")
		}
	})

	t.Run("plugin source", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/plugins/source?id=plug-1", nil)
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected plugin source route to succeed, got %d body=%s", rec.Code, rec.Body.String())
		}
		var payload model.PluginSource
		if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
			t.Fatalf("decode plugin source payload: %v", err)
		}
		if payload.ID != "plug-1" {
			t.Fatalf("unexpected plugin source payload: %+v", payload)
		}
	})

	t.Run("plugin bulk", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/plugins/bulk", strings.NewReader(`{"ids":["plug-1"],"enabled":false}`))
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected plugin bulk route to succeed, got %d body=%s", rec.Code, rec.Body.String())
		}
		if !plugins.bulkCalled {
			t.Fatal("expected SetPluginsEnabled to be called")
		}
	})
}

type fakePluginService struct {
	addCalled    bool
	deleteCalled bool
	bulkCalled   bool
}

func (s *fakePluginService) ListPlugins() []model.Plugin { return []model.Plugin{} }

func (s *fakePluginService) AddPlugin(p model.Plugin) (model.Plugin, error) {
	s.addCalled = true
	return p, nil
}

func (s *fakePluginService) DeletePlugin(id string) error {
	s.deleteCalled = true
	return nil
}

func (s *fakePluginService) PluginSource(id string) (model.PluginSource, error) {
	return model.PluginSource{ID: id}, nil
}

func (s *fakePluginService) UpdatePluginSource(source model.PluginSource) (model.PluginSource, error) {
	return source, nil
}

func (s *fakePluginService) TogglePlugin(id string) (model.Plugin, error) {
	return model.Plugin{ID: id}, nil
}

func (s *fakePluginService) SetPluginsEnabled(ids []string, enabled bool) ([]model.Plugin, error) {
	s.bulkCalled = true
	plugins := make([]model.Plugin, 0, len(ids))
	for _, id := range ids {
		plugins = append(plugins, model.Plugin{ID: id, Enabled: enabled})
	}
	return plugins, nil
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

func TestHandleC2AnalysisReturnsInitializedPayload(t *testing.T) {
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

func TestHandleC2AnalysisUsesCanceledRequestContext(t *testing.T) {
	analysis := &canceledC2AnalysisService{}
	server := &Server{analysis: analysis}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/c2-analysis", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	server.handleC2Analysis(rec, req)

	if rec.Code != http.StatusRequestTimeout {
		t.Fatalf("expected canceled c2 analysis request to return %d, got %d body=%s", http.StatusRequestTimeout, rec.Code, rec.Body.String())
	}
	if analysis.ctxErr != context.Canceled {
		t.Fatalf("analysis ctx error = %v, want %v", analysis.ctxErr, context.Canceled)
	}
}

type canceledC2AnalysisService struct {
	contractAnalysisService
	ctxErr error
}

func (s *canceledC2AnalysisService) C2SampleAnalysis(ctx context.Context) (model.C2SampleAnalysis, error) {
	s.ctxErr = ctx.Err()
	return model.C2SampleAnalysis{}, s.ctxErr
}

func TestHandleMediaArtifactTranscriptionUsesCanceledRequestContext(t *testing.T) {
	media := &canceledMediaTranscriptionService{}
	server := &Server{media: media}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodPost, "/api/analysis/media/transcribe", strings.NewReader(`{"token":"audio-1","force":true}`)).WithContext(ctx)
	rec := httptest.NewRecorder()

	server.handleMediaArtifactTranscription(rec, req)

	if rec.Code != http.StatusRequestTimeout {
		t.Fatalf("expected canceled media transcription request to return %d, got %d body=%s", http.StatusRequestTimeout, rec.Code, rec.Body.String())
	}
	if media.ctxErr != context.Canceled {
		t.Fatalf("media ctx error = %v, want %v", media.ctxErr, context.Canceled)
	}
}

type canceledMediaTranscriptionService struct {
	contractMediaService
	ctxErr error
}

func (s *canceledMediaTranscriptionService) TranscribeMediaArtifactWithContext(ctx context.Context, _ string, _ bool) (model.MediaTranscription, error) {
	s.ctxErr = ctx.Err()
	return model.MediaTranscription{}, s.ctxErr
}

type contractMediaService struct{}

func (contractMediaService) MediaAnalysis() (model.MediaAnalysis, error) {
	return model.MediaAnalysis{}, nil
}

func (contractMediaService) RefreshMediaAnalysis() (model.MediaAnalysis, error) {
	return model.MediaAnalysis{}, nil
}

func (contractMediaService) MediaArtifact(string) (string, string, error) { return "", "", nil }

func (contractMediaService) MediaPlaybackWithContext(context.Context, string) (string, string, error) {
	return "", "", nil
}

func (contractMediaService) TranscribeMediaArtifact(string, bool) (model.MediaTranscription, error) {
	return model.MediaTranscription{}, nil
}

func (contractMediaService) TranscribeMediaArtifactWithContext(context.Context, string, bool) (model.MediaTranscription, error) {
	return model.MediaTranscription{}, nil
}

func (contractMediaService) MediaBatchTranscriptionStatus() model.SpeechBatchTaskStatus {
	return model.SpeechBatchTaskStatus{}
}

func (contractMediaService) StartMediaBatchTranscription(bool) (model.SpeechBatchTaskStatus, error) {
	return model.SpeechBatchTaskStatus{}, nil
}

func (contractMediaService) CancelMediaBatchTranscription() model.SpeechBatchTaskStatus {
	return model.SpeechBatchTaskStatus{}
}

func (contractMediaService) ExportMediaBatchTranscription() model.MediaTranscriptionBatchExport {
	return model.MediaTranscriptionBatchExport{}
}

func (contractMediaService) SpeechToTextStatus() model.SpeechToTextStatus {
	return model.SpeechToTextStatus{}
}

func TestHandleNTLMSessionMaterialsUsesCanceledRequestContext(t *testing.T) {
	toolAnalysis := &canceledToolAnalysisService{}
	server := &Server{toolAnalysis: toolAnalysis}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/tools/ntlm-sessions", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	server.handleNTLMSessionMaterials(rec, req)

	if rec.Code != http.StatusRequestTimeout {
		t.Fatalf("expected canceled NTLM session request to return %d, got %d body=%s", http.StatusRequestTimeout, rec.Code, rec.Body.String())
	}
	if toolAnalysis.ctxErr != context.Canceled {
		t.Fatalf("tool ctx error = %v, want %v", toolAnalysis.ctxErr, context.Canceled)
	}
}

func TestHandleSMB3SessionCandidatesUsesCanceledRequestContext(t *testing.T) {
	toolAnalysis := &canceledToolAnalysisService{}
	server := &Server{toolAnalysis: toolAnalysis}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/tools/smb3-session-candidates", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	server.handleSMB3SessionCandidates(rec, req)

	if rec.Code != http.StatusRequestTimeout {
		t.Fatalf("expected canceled SMB3 candidates request to return %d, got %d body=%s", http.StatusRequestTimeout, rec.Code, rec.Body.String())
	}
	if toolAnalysis.ctxErr != context.Canceled {
		t.Fatalf("tool ctx error = %v, want %v", toolAnalysis.ctxErr, context.Canceled)
	}
}

func TestHandleWinRMDecryptUsesCanceledRequestContext(t *testing.T) {
	toolAnalysis := &canceledToolAnalysisService{}
	server := &Server{toolAnalysis: toolAnalysis}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodPost, "/api/tools/winrm-decrypt", strings.NewReader(`{}`)).WithContext(ctx)
	rec := httptest.NewRecorder()

	server.handleWinRMDecrypt(rec, req)

	if rec.Code != http.StatusRequestTimeout {
		t.Fatalf("expected canceled WinRM decrypt request to return %d, got %d body=%s", http.StatusRequestTimeout, rec.Code, rec.Body.String())
	}
	if toolAnalysis.ctxErr != context.Canceled {
		t.Fatalf("tool ctx error = %v, want %v", toolAnalysis.ctxErr, context.Canceled)
	}
}

type canceledToolAnalysisService struct {
	contractToolAnalysisService
	ctxErr error
}

func (s *canceledToolAnalysisService) ListNTLMSessionMaterialsWithContext(ctx context.Context) ([]model.NTLMSessionMaterial, error) {
	s.ctxErr = ctx.Err()
	return nil, s.ctxErr
}

func (s *canceledToolAnalysisService) ListSMB3SessionCandidatesWithContext(ctx context.Context) ([]model.SMB3SessionCandidate, error) {
	s.ctxErr = ctx.Err()
	return nil, s.ctxErr
}

func (s *canceledToolAnalysisService) RunWinRMDecryptWithContext(ctx context.Context, _ model.WinRMDecryptRequest) (model.WinRMDecryptResult, error) {
	s.ctxErr = ctx.Err()
	return model.WinRMDecryptResult{}, s.ctxErr
}

type contractToolAnalysisService struct{}

func (contractToolAnalysisService) ListNTLMSessionMaterials() ([]model.NTLMSessionMaterial, error) {
	return []model.NTLMSessionMaterial{}, nil
}

func (contractToolAnalysisService) ListNTLMSessionMaterialsWithContext(context.Context) ([]model.NTLMSessionMaterial, error) {
	return []model.NTLMSessionMaterial{}, nil
}

func (contractToolAnalysisService) HTTPLoginAnalysis(context.Context) (model.HTTPLoginAnalysis, error) {
	return model.HTTPLoginAnalysis{}, nil
}

func (contractToolAnalysisService) SMTPAnalysis(context.Context) (model.SMTPAnalysis, error) {
	return model.SMTPAnalysis{}, nil
}

func (contractToolAnalysisService) MySQLAnalysis(context.Context) (model.MySQLAnalysis, error) {
	return model.MySQLAnalysis{}, nil
}

func (contractToolAnalysisService) ShiroRememberMeAnalysis(context.Context, model.ShiroRememberMeRequest) (model.ShiroRememberMeAnalysis, error) {
	return model.ShiroRememberMeAnalysis{}, nil
}

func (contractToolAnalysisService) ListSMB3SessionCandidates() ([]model.SMB3SessionCandidate, error) {
	return []model.SMB3SessionCandidate{}, nil
}

func (contractToolAnalysisService) ListSMB3SessionCandidatesWithContext(context.Context) ([]model.SMB3SessionCandidate, error) {
	return []model.SMB3SessionCandidate{}, nil
}

func (contractToolAnalysisService) GenerateSMB3RandomSessionKey(model.SMB3RandomSessionKeyRequest) (model.SMB3RandomSessionKeyResult, error) {
	return model.SMB3RandomSessionKeyResult{}, nil
}

func (contractToolAnalysisService) RunWinRMDecrypt(model.WinRMDecryptRequest) (model.WinRMDecryptResult, error) {
	return model.WinRMDecryptResult{}, nil
}

func (contractToolAnalysisService) RunWinRMDecryptWithContext(context.Context, model.WinRMDecryptRequest) (model.WinRMDecryptResult, error) {
	return model.WinRMDecryptResult{}, nil
}

func (contractToolAnalysisService) WinRMExportFile(string) (string, string, error) {
	return "", "", nil
}

func TestHandleAPTAnalysisReturnsInitializedPayload(t *testing.T) {
	server := NewServer(engine.NewService(nil, nil), NewHub())
	req := httptest.NewRequest(http.MethodGet, "/api/apt-analysis", nil)
	rec := httptest.NewRecorder()

	server.handleAPTAnalysis(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected apt analysis endpoint to succeed, got %d body=%s", rec.Code, rec.Body.String())
	}

	var payload model.APTAnalysis
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode apt analysis payload: %v", err)
	}
	if payload.Evidence == nil || len(payload.Profiles) == 0 {
		t.Fatalf("expected initialized apt payload, got %+v", payload)
	}
	if payload.Profiles[0].ID != "silver-fox" {
		t.Fatalf("expected silver fox baseline profile, got %+v", payload.Profiles)
	}
}

func TestHandleStreamPayloadSourcesReturnsInitializedPayload(t *testing.T) {
	server := NewServer(engine.NewService(nil, nil), NewHub())
	req := httptest.NewRequest(http.MethodGet, "/api/streams/payload-sources?limit=10", nil)
	rec := httptest.NewRecorder()

	server.handleStreamPayloadSources(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected payload sources endpoint to succeed, got %d body=%s", rec.Code, rec.Body.String())
	}
	var payload []model.StreamPayloadSource
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode payload sources: %v", err)
	}
	if payload == nil {
		t.Fatalf("expected initialized payload source slice, got nil")
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
	server := newTestServerWithTempMiscPackages(t)
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
	server := newTestServerWithTempMiscPackages(t)
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

func TestHandleCapturePrepareReplacement(t *testing.T) {
	server := NewServer(engine.NewService(nil, nil), NewHub())

	req := httptest.NewRequest(http.MethodPost, "/api/capture/prepare-replacement", nil)
	rec := httptest.NewRecorder()
	server.handleCapturePrepareReplacement(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected prepare replacement endpoint to succeed, got %d body=%s", rec.Code, rec.Body.String())
	}

	var payload map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode prepare replacement payload: %v", err)
	}
	if payload["status"] != "prepared" {
		t.Fatalf("unexpected prepare replacement payload: %+v", payload)
	}

	getReq := httptest.NewRequest(http.MethodGet, "/api/capture/prepare-replacement", nil)
	getRec := httptest.NewRecorder()
	server.handleCapturePrepareReplacement(getRec, getReq)
	if getRec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected non-POST prepare replacement request to fail, got %d", getRec.Code)
	}
}

func TestHandleCaptureStatusReportsEmptyCapture(t *testing.T) {
	server := NewServer(engine.NewService(nil, nil), NewHub())

	req := httptest.NewRequest(http.MethodGet, "/api/capture/status", nil)
	rec := httptest.NewRecorder()
	server.handleCaptureStatus(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected capture status endpoint to succeed, got %d body=%s", rec.Code, rec.Body.String())
	}

	var payload model.CaptureStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode capture status payload: %v", err)
	}
	if payload.HasCapture || payload.FilePath != "" || payload.PacketCount != 0 {
		t.Fatalf("unexpected empty capture status payload: %+v", payload)
	}

	postReq := httptest.NewRequest(http.MethodPost, "/api/capture/status", nil)
	postRec := httptest.NewRecorder()
	server.handleCaptureStatus(postRec, postReq)
	if postRec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected non-GET capture status request to fail, got %d", postRec.Code)
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

package transport

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestToolRuntimeAndSpeechHandlersCoverMethodAndPayloadBranches(t *testing.T) {
	runtime := &recordingToolRuntimeService{}
	media := contractMediaService{}
	server := &Server{toolRuntime: runtime, media: media}

	rec := httptest.NewRecorder()
	server.handleTsharkConfig(rec, httptest.NewRequest(http.MethodGet, "/api/tools/tshark", nil))
	requireStatus(t, rec, http.StatusOK)

	rec = httptest.NewRecorder()
	server.handleTsharkConfig(rec, httptest.NewRequest(http.MethodPost, "/api/tools/tshark", strings.NewReader(`{"path":" "}`)))
	requireStatus(t, rec, http.StatusOK)

	rec = httptest.NewRecorder()
	server.handleTsharkConfig(rec, httptest.NewRequest(http.MethodPost, "/api/tools/tshark", strings.NewReader(`{bad`)))
	requireStatus(t, rec, http.StatusBadRequest)

	rec = httptest.NewRecorder()
	server.handleTsharkConfig(rec, httptest.NewRequest(http.MethodDelete, "/api/tools/tshark", nil))
	requireStatus(t, rec, http.StatusMethodNotAllowed)

	rec = httptest.NewRecorder()
	server.handleFFmpegStatus(rec, httptest.NewRequest(http.MethodGet, "/api/tools/ffmpeg", nil))
	requireStatus(t, rec, http.StatusOK)

	rec = httptest.NewRecorder()
	server.handleFFmpegStatus(rec, httptest.NewRequest(http.MethodPost, "/api/tools/ffmpeg", nil))
	requireStatus(t, rec, http.StatusMethodNotAllowed)

	rec = httptest.NewRecorder()
	server.handleSpeechToTextStatus(rec, httptest.NewRequest(http.MethodGet, "/api/tools/speech-to-text", nil))
	requireStatus(t, rec, http.StatusOK)

	rec = httptest.NewRecorder()
	server.handleSpeechToTextStatus(rec, httptest.NewRequest(http.MethodPost, "/api/tools/speech-to-text", nil))
	requireStatus(t, rec, http.StatusMethodNotAllowed)
}

func TestVehicleDBCHandlerMethodValidationAndTraversal(t *testing.T) {
	analysis := &vehicleDBCAnalysisService{}
	server := &Server{analysis: analysis}

	rec := httptest.NewRecorder()
	server.handleVehicleDBC(rec, httptest.NewRequest(http.MethodGet, "/api/analysis/vehicle/dbc", nil))
	requireStatus(t, rec, http.StatusOK)

	rec = httptest.NewRecorder()
	server.handleVehicleDBC(rec, httptest.NewRequest(http.MethodPost, "/api/analysis/vehicle/dbc", strings.NewReader(`{"path":"demo.dbc"}`)))
	requireStatus(t, rec, http.StatusOK)
	if analysis.added != "demo.dbc" {
		t.Fatalf("AddVehicleDBC path = %q", analysis.added)
	}

	rec = httptest.NewRecorder()
	server.handleVehicleDBC(rec, httptest.NewRequest(http.MethodPost, "/api/analysis/vehicle/dbc", strings.NewReader(`{"path":"../secret.dbc"}`)))
	requireStatus(t, rec, http.StatusBadRequest)

	rec = httptest.NewRecorder()
	server.handleVehicleDBC(rec, httptest.NewRequest(http.MethodPost, "/api/analysis/vehicle/dbc", strings.NewReader(`{bad`)))
	requireStatus(t, rec, http.StatusBadRequest)

	rec = httptest.NewRecorder()
	server.handleVehicleDBC(rec, httptest.NewRequest(http.MethodDelete, "/api/analysis/vehicle/dbc?path=demo.dbc", nil))
	requireStatus(t, rec, http.StatusOK)
	if analysis.removed != "demo.dbc" {
		t.Fatalf("RemoveVehicleDBC path = %q", analysis.removed)
	}

	rec = httptest.NewRecorder()
	server.handleVehicleDBC(rec, httptest.NewRequest(http.MethodDelete, "/api/analysis/vehicle/dbc", nil))
	requireStatus(t, rec, http.StatusBadRequest)

	rec = httptest.NewRecorder()
	server.handleVehicleDBC(rec, httptest.NewRequest(http.MethodDelete, "/api/analysis/vehicle/dbc?path=../bad.dbc", nil))
	requireStatus(t, rec, http.StatusBadRequest)

	rec = httptest.NewRecorder()
	server.handleVehicleDBC(rec, httptest.NewRequest(http.MethodPatch, "/api/analysis/vehicle/dbc", nil))
	requireStatus(t, rec, http.StatusMethodNotAllowed)
}

func TestToolAnalysisHandlersCoverExportAndExtraToolRoutes(t *testing.T) {
	dir := t.TempDir()
	exportPath := filepath.Join(dir, "winrm.txt")
	if err := os.WriteFile(exportPath, []byte("winrm export"), 0o644); err != nil {
		t.Fatalf("write export: %v", err)
	}
	tool := &exportToolAnalysisService{path: exportPath, name: "winrm.txt"}
	server := &Server{toolAnalysis: tool}

	rec := httptest.NewRecorder()
	server.handleWinRMDecryptExport(rec, httptest.NewRequest(http.MethodGet, "/api/tools/winrm-decrypt/export?result_id=ok", nil))
	requireStatus(t, rec, http.StatusOK)
	if !strings.Contains(rec.Body.String(), "winrm export") {
		t.Fatalf("export body = %q", rec.Body.String())
	}

	rec = httptest.NewRecorder()
	server.handleWinRMDecryptExport(rec, httptest.NewRequest(http.MethodGet, "/api/tools/winrm-decrypt/export", nil))
	requireStatus(t, rec, http.StatusBadRequest)

	rec = httptest.NewRecorder()
	server.handleWinRMDecryptExport(rec, httptest.NewRequest(http.MethodPost, "/api/tools/winrm-decrypt/export?result_id=ok", nil))
	requireStatus(t, rec, http.StatusMethodNotAllowed)

	tool.err = errors.New("missing")
	rec = httptest.NewRecorder()
	server.handleWinRMDecryptExport(rec, httptest.NewRequest(http.MethodGet, "/api/tools/winrm-decrypt/export?result_id=missing", nil))
	requireStatus(t, rec, http.StatusNotFound)

	tool.err = nil
	tool.path = filepath.Join(dir, "missing.txt")
	rec = httptest.NewRecorder()
	server.handleWinRMDecryptExport(rec, httptest.NewRequest(http.MethodGet, "/api/tools/winrm-decrypt/export?result_id=badfile", nil))
	requireStatus(t, rec, http.StatusInternalServerError)

	server = &Server{toolAnalysis: contractToolAnalysisService{}}
	for _, tt := range []struct {
		name   string
		handle func(http.ResponseWriter, *http.Request)
		path   string
	}{
		{name: "udp", handle: server.handleUDPTunnelAnalysis, path: "/api/tools/udp-tunnel"},
		{name: "bruteforce", handle: server.handleBruteforceAnalysis, path: "/api/tools/bruteforce"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tt.handle(rec, httptest.NewRequest(http.MethodGet, tt.path, nil))
			requireStatus(t, rec, http.StatusOK)

			rec = httptest.NewRecorder()
			tt.handle(rec, httptest.NewRequest(http.MethodPost, tt.path, nil))
			requireStatus(t, rec, http.StatusMethodNotAllowed)
		})
	}
}

func TestTransportHelpersAndHubCoverEdgeBranches(t *testing.T) {
	if packetServiceErrorStatus(errors.New("packet not found")) != http.StatusNotFound {
		t.Fatal("not found packet error should map to 404")
	}
	if packetServiceErrorStatus(errors.New("no capture loaded")) != http.StatusBadRequest {
		t.Fatal("no capture loaded should map to 400")
	}
	if packetServiceErrorStatus(errors.New("invalid packet id")) != http.StatusBadRequest {
		t.Fatal("invalid packet id should map to 400")
	}
	if packetServiceErrorStatus(errors.New("boom")) != http.StatusInternalServerError {
		t.Fatal("generic packet error should map to 500")
	}

	if sanitizeErrorMessage(nil) != "internal error" {
		t.Fatal("nil error should sanitize to internal error")
	}
	if sanitizeErrorMessage(errors.New(strings.Repeat("x", 250))) != strings.Repeat("x", 200) {
		t.Fatal("long errors should be truncated")
	}
	if sanitizeErrorMessage(errors.New(os.TempDir()+"/secret")) != "internal error" {
		t.Fatal("temp path should be sanitized")
	}

	server := &Server{auditLogs: []model.AuditEntry{{Action: "one"}, {Action: "two"}, {Action: "three"}}}
	if got := server.recentAuditEntries(2); len(got) != 2 || got[0].Action != "two" || got[1].Action != "three" {
		t.Fatalf("recentAuditEntries(2) = %+v", got)
	}
	if got := server.recentAuditEntries(0); len(got) != 3 {
		t.Fatalf("recentAuditEntries default = %+v", got)
	}

	hub := NewHub()
	var packetSeen, statusSeen, errorSeen bool
	hub.OnPacket(func(packet model.Packet) { packetSeen = packet.ID == 7 })
	hub.OnStatus(func(status string) { statusSeen = status == "ready" })
	hub.OnError(func(message string) { errorSeen = message == "boom" })
	hub.EmitPacket(model.Packet{ID: 7})
	hub.EmitStatus("ready")
	hub.EmitError("boom")
	if !packetSeen || !statusSeen || !errorSeen {
		t.Fatalf("hub listeners packet=%v status=%v error=%v", packetSeen, statusSeen, errorSeen)
	}
}

type vehicleDBCAnalysisService struct {
	contractAnalysisService
	added   string
	removed string
}

func (s *vehicleDBCAnalysisService) VehicleDBCProfiles() []model.DBCProfile {
	return []model.DBCProfile{{Path: "demo.dbc", Name: "demo", MessageCount: 1}}
}

func (s *vehicleDBCAnalysisService) AddVehicleDBC(path string) ([]model.DBCProfile, error) {
	s.added = path
	return s.VehicleDBCProfiles(), nil
}

func (s *vehicleDBCAnalysisService) RemoveVehicleDBC(path string) []model.DBCProfile {
	s.removed = path
	return nil
}

type exportToolAnalysisService struct {
	contractToolAnalysisService
	path string
	name string
	err  error
}

func (s *exportToolAnalysisService) WinRMExportFile(string) (string, string, error) {
	if s.err != nil {
		return "", "", s.err
	}
	return s.path, s.name, nil
}

func TestContextSensitiveToolHandlersReturnBusinessErrors(t *testing.T) {
	tool := &errorToolAnalysisService{}
	server := &Server{toolAnalysis: tool}
	for _, tt := range []struct {
		name   string
		handle func(http.ResponseWriter, *http.Request)
		path   string
	}{
		{name: "http-login", handle: server.handleHTTPLoginAnalysis, path: "/api/tools/http-login-analysis"},
		{name: "smtp", handle: server.handleSMTPAnalysis, path: "/api/tools/smtp-analysis"},
		{name: "mysql", handle: server.handleMySQLAnalysis, path: "/api/tools/mysql-analysis"},
		{name: "shiro", handle: server.handleShiroRememberMeAnalysis, path: "/api/tools/shiro-rememberme"},
		{name: "udp", handle: server.handleUDPTunnelAnalysis, path: "/api/tools/udp-tunnel"},
		{name: "bruteforce", handle: server.handleBruteforceAnalysis, path: "/api/tools/bruteforce"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tt.handle(rec, httptest.NewRequest(http.MethodGet, tt.path, nil))
			requireStatus(t, rec, http.StatusBadRequest)
		})
	}
}

type errorToolAnalysisService struct{ contractToolAnalysisService }

func (errorToolAnalysisService) HTTPLoginAnalysis(context.Context) (model.HTTPLoginAnalysis, error) {
	return model.HTTPLoginAnalysis{}, errors.New("analysis failed")
}

func (errorToolAnalysisService) SMTPAnalysis(context.Context) (model.SMTPAnalysis, error) {
	return model.SMTPAnalysis{}, errors.New("analysis failed")
}

func (errorToolAnalysisService) MySQLAnalysis(context.Context) (model.MySQLAnalysis, error) {
	return model.MySQLAnalysis{}, errors.New("analysis failed")
}

func (errorToolAnalysisService) ShiroRememberMeAnalysis(context.Context, model.ShiroRememberMeRequest) (model.ShiroRememberMeAnalysis, error) {
	return model.ShiroRememberMeAnalysis{}, errors.New("analysis failed")
}

func (errorToolAnalysisService) UDPTunnelAnalysis(context.Context) (model.UDPTunnelAnalysis, error) {
	return model.UDPTunnelAnalysis{}, errors.New("analysis failed")
}

func (errorToolAnalysisService) BruteforceAnalysis(context.Context) (model.BruteforceAnalysis, error) {
	return model.BruteforceAnalysis{}, errors.New("analysis failed")
}

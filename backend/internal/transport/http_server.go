package transport

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gshark/sentinel/backend/internal/engine"
	"github.com/gshark/sentinel/backend/internal/mcp"
	"github.com/gshark/sentinel/backend/internal/miscpkg"
	"github.com/gshark/sentinel/backend/internal/model"
)

type apiError struct {
	Error string `json:"error"`
}

type event struct {
	Type string `json:"type"`
	Data any    `json:"data"`
}

const (
	clientEventBufferSize   = 1024
	maxStreamDecodeBodySize = 1 << 20 // 1MB
	miscPackageDirEnvVar    = "MEOW_TRAFFIC_MISC_PACKAGE_DIR"
)

var runtimeIdentityStartedAt = time.Now().UTC().Format(time.RFC3339)

type ServerOptions struct {
	MiscPackageDir string
}

type Server struct {
	capture      CaptureService
	detection    DetectionService
	analysis     AnalysisService
	media        MediaService
	toolRuntime  ToolRuntimeService
	toolAnalysis ToolAnalysisService

	hub *Hub

	mu             sync.Mutex
	clients        map[chan event]struct{}
	authToken      string
	miscModules    []MiscModule
	miscPkgMgr     *miscpkg.Manager
	miscPackageDir string

	auditMu   sync.Mutex
	auditLogs []model.AuditEntry

	uploadMu           sync.Mutex
	uploadedFiles      map[string]struct{}
	activeUploadedPCAP string

	mcpServer *mcp.Server
}

func NewServer(svc *engine.Service, hub *Hub) *Server {
	return NewServerWithOptions(svc, hub, ServerOptions{})
}

func NewServerWithOptions(svc *engine.Service, hub *Hub, opts ServerOptions) *Server {
	pkgMgr := miscpkg.NewManager()
	miscPackageDir := resolveMiscPackageDir(opts.MiscPackageDir)
	if err := pkgMgr.LoadFromDir(miscPackageDir); err != nil {
		log.Printf("misc package manager: %v", err)
	}
	s := &Server{
		hub:            hub,
		clients:        map[chan event]struct{}{},
		miscModules:    defaultMiscModules(),
		miscPkgMgr:     pkgMgr,
		miscPackageDir: miscPackageDir,
		uploadedFiles:  map[string]struct{}{},
	}
	if svc != nil {
		s.capture = svc
		s.detection = svc
		s.analysis = svc
		s.media = svc
		s.toolRuntime = svc
		s.toolAnalysis = svc
	}
	s.mcpServer = mcp.NewServer(mcp.Dependencies{
		Capture:      s.capture,
		Detection:    s.detection,
		Analysis:     s.analysis,
		Media:        s.media,
		ToolRuntime:  s.toolRuntime,
		ToolAnalysis: s.toolAnalysis,
		Evidence: func(ctx context.Context, modules []string) (any, error) {
			var filter model.EvidenceFilter
			filter.Modules = append(filter.Modules, modules...)
			return s.analysis.GatherEvidence(ctx, filter)
		},
		MiscModules: s.miscModuleManifests,
		AuditLogs:   s.recentAuditEntries,
		AuthEnabled: func() bool {
			s.mu.Lock()
			defer s.mu.Unlock()
			return strings.TrimSpace(s.authToken) != ""
		},
	})
	hub.OnPacket(func(packet model.Packet) {
		s.broadcast(event{Type: "packet", Data: packet})
	})
	hub.OnStatus(func(status string) {
		s.broadcast(event{Type: "status", Data: map[string]string{"message": status}})
	})
	hub.OnError(func(message string) {
		s.broadcast(event{Type: "error", Data: map[string]string{"message": message}})
	})
	return s
}

func resolveMiscPackageDir(override string) string {
	if trimmed := strings.TrimSpace(override); trimmed != "" {
		return trimmed
	}
	if trimmed := strings.TrimSpace(os.Getenv(miscPackageDirEnvVar)); trimmed != "" {
		return trimmed
	}
	if configDir, err := os.UserConfigDir(); err == nil && strings.TrimSpace(configDir) != "" {
		return filepath.Join(configDir, "meow-traffic", "plugins", "misc")
	}
	return filepath.Join(os.TempDir(), "meow-traffic", "plugins", "misc")
}

func (s *Server) SetAuthToken(token string) {
	s.mu.Lock()
	s.authToken = strings.TrimSpace(token)
	s.mu.Unlock()
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/api/runtime/identity", s.handleRuntimeIdentity)
	mux.HandleFunc("/api/tools/tshark", s.handleTsharkConfig)
	mux.HandleFunc("/api/tools/runtime-config", s.handleToolRuntimeConfig)
	mux.HandleFunc("/api/mcp/config", s.handleMCPConfig)
	mux.HandleFunc("/api/mcp", s.handleMCP)
	mux.HandleFunc("/api/tools/ffmpeg", s.handleFFmpegStatus)
	mux.HandleFunc("/api/tools/speech-to-text", s.handleSpeechToTextStatus)
	s.registerMiscModuleRoutes(mux)
	mux.HandleFunc("/api/events", s.handleEvents)
	mux.HandleFunc("/api/capture/start", s.handleCaptureStart)
	mux.HandleFunc("/api/capture/stop", s.handleCaptureStop)
	mux.HandleFunc("/api/capture/prepare-replacement", s.handleCapturePrepareReplacement)
	mux.HandleFunc("/api/capture/close", s.handleCaptureClose)
	mux.HandleFunc("/api/capture/status", s.handleCaptureStatus)
	mux.HandleFunc("/api/capture/upload", s.handleCaptureUpload)
	mux.HandleFunc("/api/packets", s.handlePackets)
	mux.HandleFunc("/api/packets/page", s.handlePacketsPage)
	mux.HandleFunc("/api/packets/locate", s.handlePacketLocate)
	mux.HandleFunc("/api/packet", s.handlePacket)
	mux.HandleFunc("/api/hunting", s.handleHunting)
	mux.HandleFunc("/api/hunting/config", s.handleHuntingConfig)
	mux.HandleFunc("/api/objects", s.handleObjects)
	mux.HandleFunc("/api/objects/download", s.handleObjectsDownload)
	mux.HandleFunc("/api/streams/http", s.handleHTTPStream)
	mux.HandleFunc("/api/streams/raw", s.handleRawStream)
	mux.HandleFunc("/api/streams/raw/page", s.handleRawStreamPage)
	mux.HandleFunc("/api/streams/decode", s.handleStreamDecode)
	mux.HandleFunc("/api/streams/inspect", s.handleStreamInspect)
	mux.HandleFunc("/api/streams/payload-sources", s.handleStreamPayloadSources)
	mux.HandleFunc("/api/streams/payloads", s.handleStreamPayloads)
	mux.HandleFunc("/api/streams/index", s.handleStreamIndex)
	mux.HandleFunc("/api/packet/raw", s.handlePacketRaw)
	mux.HandleFunc("/api/packet/layers", s.handlePacketLayers)
	mux.HandleFunc("/api/stats/traffic/global", s.handleGlobalTrafficStats)
	mux.HandleFunc("/api/analysis/industrial", s.handleIndustrialAnalysis)
	mux.HandleFunc("/api/analysis/vehicle", s.handleVehicleAnalysis)
	mux.HandleFunc("/api/analysis/vehicle/dbc", s.handleVehicleDBC)
	mux.HandleFunc("/api/analysis/media", s.handleMediaAnalysis)
	mux.HandleFunc("/api/analysis/usb", s.handleUSBAnalysis)
	mux.HandleFunc("/api/c2-analysis", s.handleC2Analysis)
	mux.HandleFunc("/api/c2-analysis/decrypt", s.handleC2Decrypt)
	mux.HandleFunc("/api/apt-analysis", s.handleAPTAnalysis)
	mux.HandleFunc("/api/evidence", s.handleEvidence)
	mux.HandleFunc("/api/analysis/media/export", s.handleMediaArtifactDownload)
	mux.HandleFunc("/api/analysis/media/play", s.handleMediaArtifactPlayback)
	mux.HandleFunc("/api/analysis/media/transcribe", s.handleMediaArtifactTranscription)
	mux.HandleFunc("/api/analysis/media/transcribe/batch", s.handleMediaBatchTranscription)
	mux.HandleFunc("/api/analysis/media/transcribe/batch/cancel", s.handleMediaBatchTranscriptionCancel)
	mux.HandleFunc("/api/analysis/media/transcribe/batch/export", s.handleMediaBatchTranscriptionExport)
	mux.HandleFunc("/api/tls", s.handleTLS)
	mux.HandleFunc("/api/audit/logs", s.handleAuditLogs)
	mux.HandleFunc("/api/tools/ntlm-sessions", s.handleNTLMSessionMaterials)
	mux.HandleFunc("/api/tools/http-login-analysis", s.handleHTTPLoginAnalysis)
	mux.HandleFunc("/api/tools/smtp-analysis", s.handleSMTPAnalysis)
	mux.HandleFunc("/api/tools/mysql-analysis", s.handleMySQLAnalysis)
	mux.HandleFunc("/api/tools/shiro-rememberme", s.handleShiroRememberMeAnalysis)

	return withRecovery(withCORS(s.withAuth(s.withAudit(mux))))
}

func (s *Server) Start(ctx context.Context, addr string) error {
	httpServer := &http.Server{Addr: addr, Handler: s.Handler()}
	go func() {
		<-ctx.Done()
		_ = httpServer.Shutdown(context.Background())
		s.cleanupUploadedFiles()
	}()
	log.Printf("sentinel backend listening on %s", addr)
	err := httpServer.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleRuntimeIdentity(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	authEnabled := strings.TrimSpace(s.authToken) != ""
	s.mu.Unlock()
	miscPackageDir := strings.TrimSpace(s.miscPackageDir)
	if miscPackageDir == "" {
		miscPackageDir = resolveMiscPackageDir("")
	}
	buildID := strings.TrimSpace(os.Getenv("MEOW_TRAFFIC_BACKEND_BUILD_ID"))
	if buildID == "" {
		buildID = "dev"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"service":          "meow-traffic",
		"version":          "dev",
		"build_commit":     "",
		"auth_enabled":     authEnabled,
		"build_id":         buildID,
		"misc_package_dir": miscPackageDir,
		"started_at":       runtimeIdentityStartedAt,
	})
}

func (s *Server) handleTsharkConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.toolRuntime.TSharkStatusWithContext(r.Context()))
	case http.MethodPost:
		var payload struct {
			Path string `json:"path"`
		}
		if err := decodeJSONBody(w, r, &payload); err != nil {
			writeError(w, http.StatusBadRequest, "invalid payload")
			return
		}
		writeJSON(w, http.StatusOK, s.toolRuntime.SetTSharkPathWithContext(r.Context(), payload.Path))
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleToolRuntimeConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.toolRuntime.ToolRuntimeSnapshotWithOptions(r.Context(), toolRuntimeProbeOptionsFromRequest(r)))
	case http.MethodPost:
		var cfg model.ToolRuntimeConfig
		if err := decodeJSONBody(w, r, &cfg); err != nil {
			writeError(w, http.StatusBadRequest, "invalid payload")
			return
		}
		s.toolRuntime.SetToolRuntimeConfig(cfg)
		writeJSON(w, http.StatusOK, s.toolRuntime.ToolRuntimeSnapshotWithOptions(r.Context(), toolRuntimeProbeOptionsFromRequest(r)))
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleMCPConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.currentMCPStatus())
	case http.MethodPost:
		var cfg model.MCPConfig
		if err := decodeJSONBody(w, r, &cfg); err != nil {
			writeError(w, http.StatusBadRequest, "invalid payload")
			return
		}
		s.toolRuntime.SetMCPConfig(cfg)
		writeJSON(w, http.StatusOK, s.currentMCPStatus())
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleMCP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	status := s.currentMCPStatus()
	if !status.Enabled {
		writeError(w, http.StatusNotFound, "mcp endpoint is disabled")
		return
	}
	if s.mcpServer == nil {
		writeError(w, http.StatusServiceUnavailable, "mcp server is unavailable")
		return
	}
	s.mcpServer.ServeHTTP(w, r)
}

func toolRuntimeProbeOptionsFromRequest(r *http.Request) model.ToolRuntimeProbeOptions {
	mode := strings.TrimSpace(r.URL.Query().Get("probe"))
	if mode == "" {
		mode = "full"
	}
	return model.ToolRuntimeProbeOptions{Mode: mode}
}

func (s *Server) handleFFmpegStatus(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	writeJSON(w, http.StatusOK, s.toolRuntime.FFmpegStatus())
}

func (s *Server) handleSpeechToTextStatus(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	writeJSON(w, http.StatusOK, s.media.SpeechToTextStatus())
}

func (s *Server) handleHunting(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	prefixes := r.URL.Query()["prefix"]
	writeJSON(w, http.StatusOK, s.detection.ThreatHuntWithContext(r.Context(), prefixes))
}

func (s *Server) handleHuntingConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.detection.GetHuntingRuntimeConfig())
		return
	case http.MethodPost:
		var cfg model.HuntingRuntimeConfig
		if err := decodeJSONBody(w, r, &cfg); err != nil {
			writeError(w, http.StatusBadRequest, "invalid payload")
			return
		}
		writeJSON(w, http.StatusOK, s.detection.SetHuntingRuntimeConfig(cfg))
		return
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
}

func (s *Server) handleObjects(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	writeJSON(w, http.StatusOK, s.detection.ObjectsWithContext(r.Context()))
}

func (s *Server) handleGlobalTrafficStats(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	stats, err := s.analysis.GlobalTrafficStatsWithContext(r.Context())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

func (s *Server) handleIndustrialAnalysis(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	analysis, err := s.analysis.IndustrialAnalysisWithContext(r.Context())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, analysis)
}

func (s *Server) handleVehicleAnalysis(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	analysis, err := s.analysis.VehicleAnalysisWithContext(r.Context())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, analysis)
}

func (s *Server) handleMediaAnalysis(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	refreshParam := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("refresh")))
	forceRefresh := refreshParam == "1" || refreshParam == "true" || refreshParam == "yes"

	var (
		analysis model.MediaAnalysis
		err      error
	)
	if forceRefresh {
		analysis, err = s.media.RefreshMediaAnalysis()
	} else {
		analysis, err = s.media.MediaAnalysis()
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, analysis)
}

func (s *Server) handleUSBAnalysis(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	hidSource := strings.TrimSpace(r.URL.Query().Get("hid_source"))
	mode, ok := model.NormalizeUSBHIDSourceMode(hidSource)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid hid_source; expected auto, usbhid, capdata, btatt, or raw")
		return
	}
	hidEventLimit, ok := parseUSBHIDEventLimit(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid hid_event_limit; expected integer")
		return
	}
	analysis, err := s.analysis.USBAnalysisWithOptions(r.Context(), model.USBAnalysisOptions{HIDSourceMode: mode, HIDEventLimit: hidEventLimit})
	if err != nil {
		if strings.Contains(err.Error(), "no capture loaded") {
			writeError(w, http.StatusBadRequest, err.Error())
		} else {
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	writeJSON(w, http.StatusOK, analysis)
}

func parseUSBHIDEventLimit(r *http.Request) (int, bool) {
	raw := strings.TrimSpace(r.URL.Query().Get("hid_event_limit"))
	if raw == "" {
		return model.DefaultUSBHIDEventLimit, true
	}
	limit, err := strconv.Atoi(raw)
	if err != nil {
		return 0, false
	}
	return model.NormalizeUSBHIDEventLimit(limit), true
}

func (s *Server) handleC2Analysis(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	analysis, err := s.analysis.C2SampleAnalysis(r.Context())
	if err != nil {
		if errors.Is(err, context.Canceled) {
			writeError(w, http.StatusRequestTimeout, err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, analysis)
}

func (s *Server) handleC2Decrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var payload model.C2DecryptRequest
	if err := decodeJSONBody(w, r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	result, err := s.analysis.C2Decrypt(r.Context(), payload)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			writeError(w, http.StatusRequestTimeout, err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleAPTAnalysis(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	analysis, err := s.analysis.APTAnalysis(r.Context())
	if err != nil {
		if errors.Is(err, context.Canceled) {
			writeError(w, http.StatusRequestTimeout, err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, analysis)
}

func (s *Server) handleEvidence(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	var filter model.EvidenceFilter
	if modulesParam := r.URL.Query().Get("modules"); modulesParam != "" {
		for _, m := range strings.Split(modulesParam, ",") {
			m = strings.TrimSpace(m)
			if m != "" {
				filter.Modules = append(filter.Modules, m)
			}
		}
	}
	result, err := s.analysis.GatherEvidence(r.Context(), filter)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			writeError(w, http.StatusRequestTimeout, err.Error())
			return
		}
		if strings.Contains(err.Error(), "no capture loaded") {
			writeError(w, http.StatusBadRequest, err.Error())
		} else {
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleMediaArtifactDownload(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if token == "" {
		writeError(w, http.StatusBadRequest, "missing media artifact token")
		return
	}

	path, name, err := s.media.MediaArtifact(token)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	file, err := os.Open(path)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	header := make([]byte, 512)
	readBytes, _ := file.Read(header)
	_, _ = file.Seek(0, io.SeekStart)
	contentType := http.DetectContentType(header[:readBytes])
	if strings.HasSuffix(strings.ToLower(name), ".h264") || strings.HasSuffix(strings.ToLower(name), ".264") {
		contentType = "video/h264"
	}
	if strings.HasSuffix(strings.ToLower(name), ".h265") || strings.HasSuffix(strings.ToLower(name), ".hevc") {
		contentType = "video/h265"
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	http.ServeContent(w, r, name, info.ModTime(), file)
}

func (s *Server) handleMediaArtifactPlayback(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if token == "" {
		writeError(w, http.StatusBadRequest, "missing media artifact token")
		return
	}

	path, name, err := s.media.MediaPlaybackWithContext(r.Context(), token)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	file, err := os.Open(path)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	contentType := "video/mp4"
	switch strings.ToLower(filepath.Ext(name)) {
	case ".m4a":
		contentType = "audio/mp4"
	case ".mp3":
		contentType = "audio/mpeg"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("inline; filename=%q", name))
	http.ServeContent(w, r, name, info.ModTime(), file)
}

func (s *Server) handleMediaArtifactTranscription(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var payload struct {
		Token string `json:"token"`
		Force bool   `json:"force"`
	}
	if err := decodeJSONBody(w, r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	result, err := s.media.TranscribeMediaArtifactWithContext(r.Context(), payload.Token, payload.Force)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			writeError(w, http.StatusRequestTimeout, err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleMediaBatchTranscription(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.media.MediaBatchTranscriptionStatus())
	case http.MethodPost:
		var payload struct {
			Force bool `json:"force"`
		}
		if r.Body != nil {
			if err := decodeJSONBody(w, r, &payload); err != nil && !errors.Is(err, io.EOF) {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
		}
		status, err := s.media.StartMediaBatchTranscription(payload.Force)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, status)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleMediaBatchTranscriptionCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, s.media.CancelMediaBatchTranscription())
}

func (s *Server) handleMediaBatchTranscriptionExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	export := s.media.ExportMediaBatchTranscription()
	if len(export.Items) == 0 {
		writeError(w, http.StatusBadRequest, "no batch transcription results available")
		return
	}

	switch format {
	case "txt":
		var b strings.Builder
		for idx, item := range export.Items {
			if idx > 0 {
				b.WriteString("\n\n")
			}
			b.WriteString(item.Title)
			b.WriteString("\n")
			b.WriteString(item.Text)
		}
		filename := "media-transcription.txt"
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
		_, _ = w.Write([]byte(b.String()))
	case "json":
		filename := "media-transcription.json"
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
		_ = json.NewEncoder(w).Encode(export)
	default:
		writeError(w, http.StatusBadRequest, "unsupported export format")
	}
}

func (s *Server) handleVehicleDBC(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.analysis.VehicleDBCProfiles())
	case http.MethodPost:
		var payload struct {
			Path string `json:"path"`
		}
		if err := decodeJSONBody(w, r, &payload); err != nil {
			writeError(w, http.StatusBadRequest, "invalid payload")
			return
		}
		if strings.Contains(payload.Path, "..") {
			writeError(w, http.StatusBadRequest, "path traversal not allowed")
			return
		}
		profiles, err := s.analysis.AddVehicleDBC(payload.Path)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, profiles)
	case http.MethodDelete:
		path := strings.TrimSpace(r.URL.Query().Get("path"))
		if path == "" {
			writeError(w, http.StatusBadRequest, "missing dbc path")
			return
		}
		if strings.Contains(path, "..") {
			writeError(w, http.StatusBadRequest, "path traversal not allowed")
			return
		}
		writeJSON(w, http.StatusOK, s.analysis.RemoveVehicleDBC(path))
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleObjectsDownload(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodPost:
		// allowed
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var reqIds []int64
	if r.Method == http.MethodPost {
		var payload struct {
			IDs []int64 `json:"ids"`
		}
		if err := decodeJSONBody(w, r, &payload); err != nil && !errors.Is(err, io.EOF) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		reqIds = payload.IDs
	} else if r.Method == http.MethodGet {
		q := r.URL.Query().Get("ids")
		if q != "" {
			parts := strings.Split(q, ",")
			for _, part := range parts {
				if id, err := strconv.ParseInt(strings.TrimSpace(part), 10, 64); err == nil {
					reqIds = append(reqIds, id)
				}
			}
		}
	}

	allObjects := s.detection.ObjectsWithContext(r.Context())
	var toDownload []model.ObjectFile

	const maxObjectsPerDownload = 100

	if len(reqIds) == 0 {
		if len(allObjects) > maxObjectsPerDownload {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("too many objects (%d); specify ids to download", len(allObjects)))
			return
		}
		toDownload = allObjects
	} else {
		idMap := make(map[int64]bool)
		for _, id := range reqIds {
			idMap[id] = true
		}
		for _, obj := range allObjects {
			if idMap[obj.ID] {
				toDownload = append(toDownload, obj)
			}
		}
	}

	if len(toDownload) == 0 {
		writeError(w, http.StatusNotFound, "no objects to download")
		return
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="exported_objects.zip"`)

	zw := zip.NewWriter(w)
	for _, obj := range toDownload {
		if r.Context().Err() != nil {
			break
		}
		f, err := os.Open(obj.Path)
		if err != nil {
			continue
		}
		zf, err := zw.Create(obj.Name)
		if err == nil {
			const maxObjectFileSize = 256 << 20 // 256MB per file
			_, _ = io.Copy(zf, io.LimitReader(f, maxObjectFileSize))
		}
		f.Close()
	}
	zw.Close()
}

func (s *Server) handleTLS(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.toolRuntime.TLSConfig())
	case http.MethodPost:
		var cfg model.TLSConfig
		if err := decodeJSONBody(w, r, &cfg); err != nil {
			writeError(w, http.StatusBadRequest, "invalid payload")
			return
		}
		s.toolRuntime.SetTLSConfig(cfg)
		writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleAuditLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	s.auditMu.Lock()
	logs := make([]model.AuditEntry, len(s.auditLogs))
	copy(logs, s.auditLogs)
	s.auditMu.Unlock()
	writeJSON(w, http.StatusOK, logs)
}

func (s *Server) recentAuditEntries(limit int) []model.AuditEntry {
	if limit <= 0 {
		limit = 10
	}
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	if limit > len(s.auditLogs) {
		limit = len(s.auditLogs)
	}
	start := len(s.auditLogs) - limit
	logs := make([]model.AuditEntry, limit)
	copy(logs, s.auditLogs[start:])
	return logs
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := make(chan event, clientEventBufferSize)
	s.addClient(ch)
	defer s.removeClient(ch)

	_, _ = fmt.Fprint(w, "event: ready\ndata: {}\n\n")
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case ev := <-ch:
			payload, _ := json.Marshal(ev.Data)
			safeType := strings.ReplaceAll(strings.ReplaceAll(ev.Type, "\n", ""), "\r", "")
			_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", safeType, string(payload))
			flusher.Flush()
		}
	}
}

func (s *Server) addClient(ch chan event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[ch] = struct{}{}
}

func (s *Server) removeClient(ch chan event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.clients, ch)
	close(ch)
}

func (s *Server) broadcast(ev event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for ch := range s.clients {
		if ev.Type == "status" || ev.Type == "error" {
			s.enqueuePriorityEventLocked(ch, ev)
			continue
		}
		select {
		case ch <- ev:
		default:
		}
	}
}

func (s *Server) enqueuePriorityEventLocked(ch chan event, ev event) {
	if trySendEvent(ch, ev) {
		return
	}

	preserved := make([]event, 0, cap(ch))
	for {
		select {
		case pending := <-ch:
			if pending.Type == "packet" {
				continue
			}
			preserved = append(preserved, pending)
		default:
			maxPreserved := cap(ch) - 1
			if maxPreserved < 0 {
				maxPreserved = 0
			}
			if len(preserved) > maxPreserved {
				preserved = preserved[len(preserved)-maxPreserved:]
			}
			for _, pending := range preserved {
				if !trySendEvent(ch, pending) {
					break
				}
			}
			_ = trySendEvent(ch, ev)
			return
		}
	}
}

func trySendEvent(ch chan event, ev event) bool {
	select {
	case ch <- ev:
		return true
	default:
		return false
	}
}

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
		if candidate != token {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) withAudit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" || r.URL.Path == "/api/events" || r.URL.Path == "/api/audit/logs" {
			next.ServeHTTP(w, r)
			return
		}

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
			Authenticated: true,
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

const maxJSONBody = 1 << 20 // 1MB

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

var sensitivePathPrefixes = []string{
	os.TempDir(),
	filepath.Join("meow-traffic"),
	"/tmp/",
	"/var/",
	"C:\\Users\\",
	"C:\\Windows\\",
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

func classifyAuditAction(path, method string) string {
	switch path {
	case "/api/capture/start":
		return "capture.start"
	case "/api/capture/stop":
		return "capture.stop"
	case "/api/capture/prepare-replacement":
		return "capture.prepare_replacement"
	case "/api/capture/close":
		return "capture.close"
	case "/api/capture/upload":
		return "capture.upload"
	case "/api/tools/tshark":
		if method == http.MethodPost {
			return "tools.tshark.configure"
		}
		return "tools.tshark.inspect"
	case "/api/tools/runtime-config":
		if method == http.MethodPost {
			return "tools.runtime.configure"
		}
		return "tools.runtime.inspect"
	case "/api/mcp/config":
		if method == http.MethodPost {
			return "mcp.configure"
		}
		return "mcp.inspect"
	case "/api/mcp":
		return "mcp.request"
	case "/api/hunting/config":
		if method == http.MethodPost {
			return "hunting.configure"
		}
		return "hunting.inspect"
	case "/api/tls":
		if method == http.MethodPost {
			return "tls.configure"
		}
		return "tls.inspect"
	case "/api/analysis/vehicle/dbc":
		if method == http.MethodDelete {
			return "dbc.remove"
		}
		if method == http.MethodPost {
			return "dbc.add"
		}
		return "dbc.list"
	case "/api/tools/misc/import":
		return "misc.import"
	default:
		if strings.HasPrefix(path, "/api/tools/misc/packages/") {
			if method == http.MethodDelete {
				return "misc.delete"
			}
			return "misc.invoke"
		}
		if strings.HasPrefix(path, "/api/analysis/") {
			return "analysis.read"
		}
		if strings.HasPrefix(path, "/api/objects") || strings.HasPrefix(path, "/api/streams") || strings.HasPrefix(path, "/api/packet") || strings.HasPrefix(path, "/api/packets") {
			return "capture.read"
		}
		return "api.request"
	}
}

func classifyAuditRisk(path, method string) string {
	switch path {
	case "/api/tls", "/api/tools/misc/import":
		return "high"
	case "/api/capture/start", "/api/capture/upload", "/api/analysis/vehicle/dbc", "/api/tools/tshark", "/api/tools/runtime-config", "/api/mcp/config", "/api/hunting/config":
		if method == http.MethodGet {
			return "low"
		}
		return "medium"
	case "/api/mcp":
		return "low"
	default:
		if strings.HasPrefix(path, "/api/tools/misc/packages/") {
			if method == http.MethodDelete {
				return "high"
			}
			return "medium"
		}
		if method == http.MethodPost || method == http.MethodDelete {
			return "medium"
		}
		return "low"
	}
}

func (s *Server) appendAuditEntry(entry model.AuditEntry) {
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	s.auditLogs = append(s.auditLogs, entry)
	if len(s.auditLogs) > 200 {
		s.auditLogs = append([]model.AuditEntry(nil), s.auditLogs[len(s.auditLogs)-200:]...)
	}
}

func (s *Server) registerUploadedFile(path string) {
	path = strings.TrimSpace(path)
	if path == "" {
		return
	}

	s.uploadMu.Lock()
	s.uploadedFiles[path] = struct{}{}
	toDelete := s.collectUploadedFilesForCleanupLocked(path, s.activeUploadedPCAP)
	s.uploadMu.Unlock()
	deleteFiles(toDelete)
}

func (s *Server) promoteUploadedFile(path string) {
	path = strings.TrimSpace(path)

	s.uploadMu.Lock()
	var oldActive string
	if s.activeUploadedPCAP != "" && s.activeUploadedPCAP != path {
		oldActive = s.activeUploadedPCAP
		delete(s.uploadedFiles, s.activeUploadedPCAP)
	}
	if _, ok := s.uploadedFiles[path]; ok {
		s.activeUploadedPCAP = path
	} else {
		s.activeUploadedPCAP = ""
	}
	toDelete := s.collectUploadedFilesForCleanupLocked(s.activeUploadedPCAP)
	s.uploadMu.Unlock()
	if oldActive != "" {
		toDelete = append(toDelete, oldActive)
	}
	deleteFiles(toDelete)
}

func (s *Server) cleanupUploadedFiles() {
	s.uploadMu.Lock()
	toDelete := make([]string, 0, len(s.uploadedFiles))
	for path := range s.uploadedFiles {
		toDelete = append(toDelete, path)
	}
	s.uploadedFiles = map[string]struct{}{}
	s.activeUploadedPCAP = ""
	s.uploadMu.Unlock()
	deleteFiles(toDelete)
}

func (s *Server) collectUploadedFilesForCleanupLocked(keep ...string) []string {
	keepSet := make(map[string]struct{}, len(keep))
	for _, item := range keep {
		item = strings.TrimSpace(item)
		if item != "" {
			keepSet[item] = struct{}{}
		}
	}

	var toDelete []string
	for path := range s.uploadedFiles {
		if _, ok := keepSet[path]; ok {
			continue
		}
		toDelete = append(toDelete, path)
		delete(s.uploadedFiles, path)
	}
	return toDelete
}

func deleteFiles(paths []string) {
	for _, path := range paths {
		if strings.TrimSpace(path) == "" {
			continue
		}
		_ = os.Remove(path)
	}
}

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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gshark/sentinel/backend/internal/engine"
	"github.com/gshark/sentinel/backend/internal/miscpkg"
	"github.com/gshark/sentinel/backend/internal/model"
	"github.com/gshark/sentinel/backend/internal/tshark"
)

type apiError struct {
	Error string `json:"error"`
}

type openCaptureResult struct {
	FilePath string `json:"filePath"`
	FileSize int64  `json:"fileSize"`
	FileName string `json:"fileName"`
}

type event struct {
	Type string `json:"type"`
	Data any    `json:"data"`
}

const (
	clientEventBufferSize   = 1024
	maxStreamDecodeBodySize = 1 << 20 // 1MB
)

type Server struct {
	svc *engine.Service
	hub *Hub

	mu          sync.Mutex
	clients     map[chan event]struct{}
	authToken   string
	miscModules []MiscModule
	miscPkgMgr  *miscpkg.Manager

	auditMu   sync.Mutex
	auditLogs []model.AuditEntry

	uploadMu           sync.Mutex
	uploadedFiles      map[string]struct{}
	activeUploadedPCAP string
}

func NewServer(svc *engine.Service, hub *Hub) *Server {
	pkgMgr := miscpkg.NewManager()
	_ = pkgMgr.LoadFromDir(filepath.Join("plugins", "misc"))
	s := &Server{
		svc:           svc,
		hub:           hub,
		clients:       map[chan event]struct{}{},
		miscModules:   defaultMiscModules(),
		miscPkgMgr:    pkgMgr,
		uploadedFiles: map[string]struct{}{},
	}
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

func (s *Server) SetAuthToken(token string) {
	s.mu.Lock()
	s.authToken = strings.TrimSpace(token)
	s.mu.Unlock()
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/api/tools/tshark", s.handleTsharkConfig)
	mux.HandleFunc("/api/tools/runtime-config", s.handleToolRuntimeConfig)
	mux.HandleFunc("/api/tools/ffmpeg", s.handleFFmpegStatus)
	mux.HandleFunc("/api/tools/speech-to-text", s.handleSpeechToTextStatus)
	s.registerMiscModuleRoutes(mux)
	mux.HandleFunc("/api/events", s.handleEvents)
	mux.HandleFunc("/api/capture/start", s.handleCaptureStart)
	mux.HandleFunc("/api/capture/stop", s.handleCaptureStop)
	mux.HandleFunc("/api/capture/prepare-replacement", s.handleCapturePrepareReplacement)
	mux.HandleFunc("/api/capture/close", s.handleCaptureClose)
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
	mux.HandleFunc("/api/analysis/media/export", s.handleMediaArtifactDownload)
	mux.HandleFunc("/api/analysis/media/play", s.handleMediaArtifactPlayback)
	mux.HandleFunc("/api/analysis/media/transcribe", s.handleMediaArtifactTranscription)
	mux.HandleFunc("/api/analysis/media/transcribe/batch", s.handleMediaBatchTranscription)
	mux.HandleFunc("/api/analysis/media/transcribe/batch/cancel", s.handleMediaBatchTranscriptionCancel)
	mux.HandleFunc("/api/analysis/media/transcribe/batch/export", s.handleMediaBatchTranscriptionExport)
	mux.HandleFunc("/api/tls", s.handleTLS)
	mux.HandleFunc("/api/audit/logs", s.handleAuditLogs)
	mux.HandleFunc("/api/plugins", s.handlePlugins)
	mux.HandleFunc("/api/plugins/add", s.handleAddPlugin)
	mux.HandleFunc("/api/plugins/delete", s.handleDeletePlugin)
	mux.HandleFunc("/api/plugins/source", s.handlePluginSource)
	mux.HandleFunc("/api/plugins/toggle", s.handleTogglePlugin)
	mux.HandleFunc("/api/plugins/bulk", s.handleBulkPlugins)
	mux.HandleFunc("/api/tools/ntlm-sessions", s.handleNTLMSessionMaterials)
	mux.HandleFunc("/api/tools/http-login-analysis", s.handleHTTPLoginAnalysis)
	mux.HandleFunc("/api/tools/smtp-analysis", s.handleSMTPAnalysis)
	mux.HandleFunc("/api/tools/mysql-analysis", s.handleMySQLAnalysis)
	mux.HandleFunc("/api/tools/shiro-rememberme", s.handleShiroRememberMeAnalysis)

	return withCORS(s.withAuth(s.withAudit(mux)))
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

func (s *Server) handleTsharkConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, tshark.CurrentStatus())
	case http.MethodPost:
		var payload struct {
			Path string `json:"path"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeError(w, http.StatusBadRequest, "invalid payload")
			return
		}
		tshark.SetBinaryPath(payload.Path)
		writeJSON(w, http.StatusOK, tshark.CurrentStatus())
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleToolRuntimeConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.svc.ToolRuntimeSnapshot())
	case http.MethodPost:
		var cfg model.ToolRuntimeConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			writeError(w, http.StatusBadRequest, "invalid payload")
			return
		}
		s.svc.SetToolRuntimeConfig(cfg)
		writeJSON(w, http.StatusOK, s.svc.ToolRuntimeSnapshot())
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleFFmpegStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.svc.FFmpegStatus())
}

func (s *Server) handleSpeechToTextStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.svc.SpeechToTextStatus())
}

func (s *Server) handleWinRMDecrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req model.WinRMDecryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	result, err := s.svc.RunWinRMDecrypt(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleWinRMDecryptExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	resultID := strings.TrimSpace(r.URL.Query().Get("result_id"))
	if resultID == "" {
		writeError(w, http.StatusBadRequest, "missing result_id")
		return
	}
	filePath, filename, err := s.svc.WinRMExportFile(resultID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	content, err := os.ReadFile(filePath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read export file")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}

func (s *Server) handleSMB3RandomSessionKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req model.SMB3RandomSessionKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	result, err := s.svc.GenerateSMB3RandomSessionKey(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleSMB3SessionCandidates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	rows, err := s.svc.ListSMB3SessionCandidates()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

func (s *Server) handleCaptureStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var options model.ParseOptions
	if err := json.NewDecoder(r.Body).Decode(&options); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	options.FilePath = strings.TrimSpace(options.FilePath)
	if options.FilePath == "" {
		writeError(w, http.StatusBadRequest, "missing capture file path")
		return
	}
	info, err := os.Stat(options.FilePath)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("capture file is not accessible: %v", err))
		return
	}
	if info.IsDir() {
		writeError(w, http.StatusBadRequest, "capture file path points to a directory")
		return
	}
	tsharkStatus := tshark.CurrentStatus()
	log.Printf(
		"http: capture start requested file=%q size=%d filter=%q fast_list=%t tshark=%q custom=%t",
		options.FilePath,
		info.Size(),
		options.DisplayFilter,
		options.FastList,
		tsharkStatus.Path,
		tsharkStatus.UsingCustomPath,
	)
	s.promoteUploadedFile(options.FilePath)
	loadRunID, loadCtx := s.svc.BeginCaptureLoad(context.WithoutCancel(r.Context()))
	go func() {
		if err := s.svc.LoadPCAPWithRun(loadCtx, options, loadRunID); err != nil {
			log.Printf("http: capture start failed file=%q err=%v", options.FilePath, err)
			if errors.Is(err, context.Canceled) {
				return
			}
			s.hub.EmitError(err.Error())
			return
		}
		log.Printf("http: capture start finished file=%q", options.FilePath)
	}()
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "streaming"})
}

func (s *Server) handleCaptureStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	s.svc.StopStreaming()
	writeJSON(w, http.StatusOK, map[string]string{"status": "stopped"})
}

func (s *Server) handleCapturePrepareReplacement(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	s.svc.PrepareCaptureReplacement()
	writeJSON(w, http.StatusOK, map[string]string{"status": "prepared"})
}

func (s *Server) handleCaptureClose(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if err := s.svc.ClearCapture(); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "closed"})
}

func (s *Server) handleCaptureUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if err := r.ParseMultipartForm(4 << 30); err != nil {
		writeError(w, http.StatusBadRequest, "invalid multipart payload")
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "missing file field")
		return
	}
	defer file.Close()

	name := strings.TrimSpace(header.Filename)
	if name == "" {
		name = "capture.pcapng"
	}

	ext := strings.ToLower(filepath.Ext(name))
	if ext != ".pcap" && ext != ".pcapng" && ext != ".cap" {
		ext = ".pcapng"
	}

	targetPath := filepath.Join(os.TempDir(), fmt.Sprintf("gshark-%d%s", time.Now().UnixNano(), ext))
	target, err := os.Create(targetPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create temp file")
		return
	}
	defer target.Close()

	written, err := io.Copy(target, file)
	if err != nil {
		_ = os.Remove(targetPath)
		writeError(w, http.StatusInternalServerError, "failed to save upload")
		return
	}
	log.Printf("http: uploaded capture saved as %q (%d bytes)", targetPath, written)
	s.registerUploadedFile(targetPath)

	writeJSON(w, http.StatusOK, openCaptureResult{
		FilePath: targetPath,
		FileSize: written,
		FileName: name,
	})
}

func (s *Server) handlePackets(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.svc.Packets())
}

type packetsPageResponse struct {
	Items      []model.Packet `json:"items"`
	NextCursor int            `json:"next_cursor"`
	Total      int            `json:"total"`
	HasMore    bool           `json:"has_more"`
	Filtering  bool           `json:"filtering"`
}

func (s *Server) handlePacketsPage(w http.ResponseWriter, r *http.Request) {
	cursor, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("cursor")))
	limit, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("limit")))
	filter := strings.TrimSpace(r.URL.Query().Get("filter"))

	items, next, total, filtering, err := s.svc.PacketsPageWithState(cursor, limit, filter)
	if err != nil {
		if engine.IsDisplayFilterError(err) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, packetsPageResponse{
		Items:      items,
		NextCursor: next,
		Total:      total,
		HasMore:    next < total,
		Filtering:  filtering,
	})
}

func (s *Server) handlePacketLocate(w http.ResponseWriter, r *http.Request) {
	packetID, err := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("id")), 10, 64)
	if err != nil || packetID <= 0 {
		writeError(w, http.StatusBadRequest, "invalid packet id")
		return
	}

	limit, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("limit")))
	filter := strings.TrimSpace(r.URL.Query().Get("filter"))

	cursor, total, found, err := s.svc.PacketPageCursorWithError(packetID, limit, filter)
	if err != nil {
		if engine.IsDisplayFilterError(err) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"packet_id": packetID,
		"cursor":    cursor,
		"total":     total,
		"found":     found,
	})
}

func (s *Server) handlePacket(w http.ResponseWriter, r *http.Request) {
	packetID, err := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("id")), 10, 64)
	if err != nil || packetID <= 0 {
		writeError(w, http.StatusBadRequest, "invalid packet id")
		return
	}

	packet, err := s.svc.Packet(packetID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, packet)
}

func (s *Server) handleHunting(w http.ResponseWriter, r *http.Request) {
	prefixes := r.URL.Query()["prefix"]
	writeJSON(w, http.StatusOK, s.svc.ThreatHuntWithContext(r.Context(), prefixes))
}

func (s *Server) handleHuntingConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.svc.GetHuntingRuntimeConfig())
		return
	case http.MethodPost:
		var cfg model.HuntingRuntimeConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			writeError(w, http.StatusBadRequest, "invalid payload")
			return
		}
		writeJSON(w, http.StatusOK, s.svc.SetHuntingRuntimeConfig(cfg))
		return
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
}

func (s *Server) handleObjects(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.svc.ObjectsWithContext(r.Context()))
}

func (s *Server) handlePacketRaw(w http.ResponseWriter, r *http.Request) {
	packetID, err := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("id")), 10, 64)
	if err != nil || packetID <= 0 {
		writeError(w, http.StatusBadRequest, "invalid packet id")
		return
	}

	rawHex, err := s.svc.PacketRawHex(packetID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"packet_id": packetID,
		"raw_hex":   rawHex,
	})
}

func (s *Server) handlePacketLayers(w http.ResponseWriter, r *http.Request) {
	packetID, err := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("id")), 10, 64)
	if err != nil || packetID <= 0 {
		writeError(w, http.StatusBadRequest, "invalid packet id")
		return
	}

	layers, err := s.svc.PacketLayers(packetID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"packet_id": packetID,
		"layers":    layers,
	})
}

func (s *Server) handleStreamIndex(w http.ResponseWriter, r *http.Request) {
	protocol := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("protocol")))
	if protocol != "HTTP" && protocol != "TCP" && protocol != "UDP" {
		writeError(w, http.StatusBadRequest, "invalid protocol")
		return
	}

	ids := s.svc.StreamIDs(protocol)
	writeJSON(w, http.StatusOK, map[string]any{
		"protocol": protocol,
		"total":    len(ids),
		"ids":      ids,
	})
}

func (s *Server) handleGlobalTrafficStats(w http.ResponseWriter, _ *http.Request) {
	stats, err := s.svc.GlobalTrafficStats()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

func (s *Server) handleIndustrialAnalysis(w http.ResponseWriter, _ *http.Request) {
	analysis, err := s.svc.IndustrialAnalysis()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, analysis)
}

func (s *Server) handleVehicleAnalysis(w http.ResponseWriter, _ *http.Request) {
	analysis, err := s.svc.VehicleAnalysis()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, analysis)
}

func (s *Server) handleMediaAnalysis(w http.ResponseWriter, r *http.Request) {
	refreshParam := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("refresh")))
	forceRefresh := refreshParam == "1" || refreshParam == "true" || refreshParam == "yes"

	var (
		analysis model.MediaAnalysis
		err      error
	)
	if forceRefresh {
		analysis, err = s.svc.RefreshMediaAnalysis()
	} else {
		analysis, err = s.svc.MediaAnalysis()
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, analysis)
}

func (s *Server) handleUSBAnalysis(w http.ResponseWriter, _ *http.Request) {
	analysis, err := s.svc.USBAnalysis()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, analysis)
}

func (s *Server) handleC2Analysis(w http.ResponseWriter, r *http.Request) {
	analysis, err := s.svc.C2SampleAnalysis(r.Context())
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
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	result, err := s.svc.C2Decrypt(r.Context(), payload)
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
	analysis, err := s.svc.APTAnalysis(r.Context())
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

func (s *Server) handleMediaArtifactDownload(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if token == "" {
		writeError(w, http.StatusBadRequest, "missing media artifact token")
		return
	}

	path, name, err := s.svc.MediaArtifact(token)
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

	path, name, err := s.svc.MediaPlaybackWithContext(r.Context(), token)
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
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	result, err := s.svc.TranscribeMediaArtifact(payload.Token, payload.Force)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleMediaBatchTranscription(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.svc.MediaBatchTranscriptionStatus())
	case http.MethodPost:
		var payload struct {
			Force bool `json:"force"`
		}
		if r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&payload)
		}
		status, err := s.svc.StartMediaBatchTranscription(payload.Force)
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
	writeJSON(w, http.StatusOK, s.svc.CancelMediaBatchTranscription())
}

func (s *Server) handleMediaBatchTranscriptionExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	export := s.svc.ExportMediaBatchTranscription()
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
		writeJSON(w, http.StatusOK, s.svc.VehicleDBCProfiles())
	case http.MethodPost:
		var payload struct {
			Path string `json:"path"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeError(w, http.StatusBadRequest, "invalid payload")
			return
		}
		profiles, err := s.svc.AddVehicleDBC(payload.Path)
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
		writeJSON(w, http.StatusOK, s.svc.RemoveVehicleDBC(path))
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
		if err := json.NewDecoder(r.Body).Decode(&payload); err == nil {
			reqIds = payload.IDs
		}
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

	allObjects := s.svc.ObjectsWithContext(r.Context())
	var toDownload []model.ObjectFile

	if len(reqIds) == 0 {
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
			_, _ = io.Copy(zf, f)
		}
		f.Close()
	}
	zw.Close()
}

func (s *Server) handleAddPlugin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var payload model.Plugin
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}

	plugin, err := s.svc.AddPlugin(payload)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, plugin)
}

func (s *Server) handleDeletePlugin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost, http.MethodDelete:
		// allowed
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		var payload struct {
			ID string `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err == nil {
			id = strings.TrimSpace(payload.ID)
		}
	}

	if id == "" {
		writeError(w, http.StatusBadRequest, "missing plugin id")
		return
	}

	if err := s.svc.DeletePlugin(id); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"id": id, "deleted": true})
}

func (s *Server) handlePluginSource(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		id := strings.TrimSpace(r.URL.Query().Get("id"))
		if id == "" {
			writeError(w, http.StatusBadRequest, "missing plugin id")
			return
		}

		source, err := s.svc.PluginSource(id)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		writeJSON(w, http.StatusOK, source)
	case http.MethodPost:
		var payload model.PluginSource
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeError(w, http.StatusBadRequest, "invalid payload")
			return
		}
		source, err := s.svc.UpdatePluginSource(payload)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, source)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleHTTPStream(w http.ResponseWriter, r *http.Request) {
	streamID := parseInt64(r.URL.Query().Get("streamId"), 1)
	writeJSON(w, http.StatusOK, s.svc.HTTPStream(r.Context(), streamID))
}

func (s *Server) handleRawStream(w http.ResponseWriter, r *http.Request) {
	streamID := parseInt64(r.URL.Query().Get("streamId"), 1)
	protocol := r.URL.Query().Get("protocol")
	if protocol == "" {
		protocol = "TCP"
	}
	writeJSON(w, http.StatusOK, s.svc.RawStream(r.Context(), protocol, streamID))
}

type streamPageResponse struct {
	StreamID   int64                 `json:"stream_id"`
	Protocol   string                `json:"protocol"`
	From       string                `json:"from"`
	To         string                `json:"to"`
	Chunks     []model.StreamChunk   `json:"chunks"`
	LoadMeta   *model.StreamLoadMeta `json:"load_meta,omitempty"`
	NextCursor int                   `json:"next_cursor"`
	Total      int                   `json:"total"`
	HasMore    bool                  `json:"has_more"`
}

func (s *Server) handleRawStreamPage(w http.ResponseWriter, r *http.Request) {
	streamID := parseInt64(r.URL.Query().Get("streamId"), 1)
	protocol := r.URL.Query().Get("protocol")
	if protocol == "" {
		protocol = "TCP"
	}
	cursor, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("cursor")))
	limit, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("limit")))

	stream, next, total := s.svc.RawStreamPage(r.Context(), protocol, streamID, cursor, limit)
	writeJSON(w, http.StatusOK, streamPageResponse{
		StreamID:   stream.StreamID,
		Protocol:   stream.Protocol,
		From:       stream.From,
		To:         stream.To,
		Chunks:     stream.Chunks,
		LoadMeta:   stream.LoadMeta,
		NextCursor: next,
		Total:      total,
		HasMore:    next < total,
	})
}

func (s *Server) handleStreamDecode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	body := http.MaxBytesReader(w, r.Body, maxStreamDecodeBodySize)
	defer body.Close()

	var payload engine.StreamDecodeRequest
	if err := json.NewDecoder(body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	result, err := engine.DecodeStreamPayload(payload)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleStreamInspect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	body := http.MaxBytesReader(w, r.Body, maxStreamDecodeBodySize)
	defer body.Close()

	var payload struct {
		Payload string `json:"payload"`
	}
	if err := json.NewDecoder(body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	writeJSON(w, http.StatusOK, engine.InspectStreamPayload(payload.Payload))
}

func (s *Server) handleStreamPayloadSources(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	limit := 50
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid limit")
			return
		}
		limit = parsed
	}
	rows, err := s.svc.ListStreamPayloadSources(limit)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

func (s *Server) handleStreamPayloads(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var payload struct {
		Protocol string                   `json:"protocol"`
		StreamID int64                    `json:"stream_id"`
		Patches  []model.StreamChunkPatch `json:"patches"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}

	stream, err := s.svc.UpdateStreamPayloads(r.Context(), payload.Protocol, payload.StreamID, payload.Patches)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, stream)
}

func (s *Server) handleTLS(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.svc.TLSConfig())
	case http.MethodPost:
		var cfg model.TLSConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			writeError(w, http.StatusBadRequest, "invalid payload")
			return
		}
		s.svc.SetTLSConfig(cfg)
		writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleNTLMSessionMaterials(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	rows, err := s.svc.ListNTLMSessionMaterials()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

func (s *Server) handleHTTPLoginAnalysis(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	rows, err := s.svc.HTTPLoginAnalysis(r.Context())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

func (s *Server) handleSMTPAnalysis(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	rows, err := s.svc.SMTPAnalysis(r.Context())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

func (s *Server) handleMySQLAnalysis(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	rows, err := s.svc.MySQLAnalysis(r.Context())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

func (s *Server) handleShiroRememberMeAnalysis(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req model.ShiroRememberMeRequest
	if r.Method == http.MethodPost {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
			writeError(w, http.StatusBadRequest, "invalid payload")
			return
		}
	}
	rows, err := s.svc.ShiroRememberMeAnalysis(r.Context(), req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rows)
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

func (s *Server) handlePlugins(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.svc.ListPlugins())
}

func (s *Server) handleTogglePlugin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	id := r.URL.Query().Get("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing plugin id")
		return
	}
	plugin, err := s.svc.TogglePlugin(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, plugin)
}

type pluginBulkRequest struct {
	IDs     []string `json:"ids"`
	Enabled bool     `json:"enabled"`
}

func (s *Server) handleBulkPlugins(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req pluginBulkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}

	plugins, err := s.svc.SetPluginsEnabled(req.IDs, req.Enabled)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, plugins)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
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
			_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Type, string(payload))
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
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-GShark-Auth")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS")
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

		if token == "" || r.URL.Path == "/health" || isTrustedDesktopOrigin(r.Header.Get("Origin")) {
			next.ServeHTTP(w, r)
			return
		}

		candidate := strings.TrimSpace(r.Header.Get("Authorization"))
		if strings.HasPrefix(strings.ToLower(candidate), "bearer ") {
			candidate = strings.TrimSpace(candidate[7:])
		}
		if candidate == "" {
			candidate = strings.TrimSpace(r.Header.Get("X-GShark-Auth"))
		}
		if candidate == "" {
			candidate = strings.TrimSpace(r.URL.Query().Get("access_token"))
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

func writeJSON(w http.ResponseWriter, code int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, code int, message string) {
	writeJSON(w, code, apiError{Error: message})
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

func isTrustedDesktopOrigin(origin string) bool {
	parsed, err := url.Parse(strings.TrimSpace(origin))
	if err != nil {
		return false
	}
	return strings.EqualFold(parsed.Hostname(), "wails.localhost")
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
	case "/api/plugins":
		return "plugin.list"
	case "/api/plugins/add":
		return "plugin.add"
	case "/api/plugins/delete":
		return "plugin.delete"
	case "/api/plugins/source":
		if method == http.MethodPost {
			return "plugin.source.save"
		}
		return "plugin.source.read"
	case "/api/plugins/toggle":
		return "plugin.toggle"
	case "/api/plugins/bulk":
		return "plugin.bulk"
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
	case "/api/plugins/add", "/api/plugins/delete", "/api/plugins/source", "/api/plugins/bulk", "/api/tls", "/api/tools/misc/import":
		return "high"
	case "/api/capture/start", "/api/capture/upload", "/api/analysis/vehicle/dbc", "/api/tools/tshark", "/api/tools/runtime-config", "/api/hunting/config":
		if method == http.MethodGet {
			return "low"
		}
		return "medium"
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

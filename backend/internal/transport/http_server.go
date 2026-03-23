package transport

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gshark/sentinel/backend/internal/engine"
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

type Server struct {
	svc *engine.Service
	hub *Hub

	mu      sync.Mutex
	clients map[chan event]struct{}
}

func NewServer(svc *engine.Service, hub *Hub) *Server {
	s := &Server{svc: svc, hub: hub, clients: map[chan event]struct{}{}}
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

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/api/tools/tshark", s.handleTsharkConfig)
	mux.HandleFunc("/api/events", s.handleEvents)
	mux.HandleFunc("/api/capture/start", s.handleCaptureStart)
	mux.HandleFunc("/api/capture/stop", s.handleCaptureStop)
	mux.HandleFunc("/api/capture/upload", s.handleCaptureUpload)
	mux.HandleFunc("/api/packets", s.handlePackets)
	mux.HandleFunc("/api/packets/page", s.handlePacketsPage)
	mux.HandleFunc("/api/packets/locate", s.handlePacketLocate)
	mux.HandleFunc("/api/hunting", s.handleHunting)
	mux.HandleFunc("/api/hunting/config", s.handleHuntingConfig)
	mux.HandleFunc("/api/objects", s.handleObjects)
	mux.HandleFunc("/api/objects/download", s.handleObjectsDownload)
	mux.HandleFunc("/api/streams/http", s.handleHTTPStream)
	mux.HandleFunc("/api/streams/raw", s.handleRawStream)
	mux.HandleFunc("/api/streams/index", s.handleStreamIndex)
	mux.HandleFunc("/api/packet/raw", s.handlePacketRaw)
	mux.HandleFunc("/api/packet/layers", s.handlePacketLayers)
	mux.HandleFunc("/api/stats/traffic/global", s.handleGlobalTrafficStats)
	mux.HandleFunc("/api/analysis/industrial", s.handleIndustrialAnalysis)
	mux.HandleFunc("/api/analysis/vehicle", s.handleVehicleAnalysis)
	mux.HandleFunc("/api/analysis/vehicle/dbc", s.handleVehicleDBC)
	mux.HandleFunc("/api/tls", s.handleTLS)
	mux.HandleFunc("/api/plugins", s.handlePlugins)
	mux.HandleFunc("/api/plugins/add", s.handleAddPlugin)
	mux.HandleFunc("/api/plugins/delete", s.handleDeletePlugin)
	mux.HandleFunc("/api/plugins/source", s.handlePluginSource)
	mux.HandleFunc("/api/plugins/toggle", s.handleTogglePlugin)
	mux.HandleFunc("/api/plugins/bulk", s.handleBulkPlugins)

	return withCORS(mux)
}

func (s *Server) Start(ctx context.Context, addr string) error {
	httpServer := &http.Server{Addr: addr, Handler: s.Handler()}
	go func() {
		<-ctx.Done()
		_ = httpServer.Shutdown(context.Background())
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

func (s *Server) handleTsharkStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	path, err := exec.LookPath("tshark")
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"available": false,
			"path":      "",
			"message":   "未在 PATH 环境变量中找到 tshark，可安装 Wireshark 并将 tshark 加入 PATH",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"available": true,
		"path":      path,
		"message":   "ok",
	})
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
	go func() {
		if err := s.svc.LoadPCAP(context.Background(), options); err != nil {
			log.Printf("http: capture start failed file=%q err=%v", options.FilePath, err)
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
}

func (s *Server) handlePacketsPage(w http.ResponseWriter, r *http.Request) {
	cursor, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("cursor")))
	limit, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("limit")))
	filter := strings.TrimSpace(r.URL.Query().Get("filter"))

	items, next, total := s.svc.PacketsPage(cursor, limit, filter)
	writeJSON(w, http.StatusOK, packetsPageResponse{
		Items:      items,
		NextCursor: next,
		Total:      total,
		HasMore:    next < total,
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

	cursor, total, found := s.svc.PacketPageCursor(packetID, limit, filter)
	writeJSON(w, http.StatusOK, map[string]any{
		"packet_id": packetID,
		"cursor":    cursor,
		"total":     total,
		"found":     found,
	})
}

func (s *Server) handleHunting(w http.ResponseWriter, r *http.Request) {
	prefixes := r.URL.Query()["prefix"]
	writeJSON(w, http.StatusOK, s.svc.ThreatHunt(prefixes))
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

func (s *Server) handleObjects(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.svc.Objects())
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

	allObjects := s.svc.Objects()
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
	writeJSON(w, http.StatusOK, s.svc.HTTPStream(streamID))
}

func (s *Server) handleRawStream(w http.ResponseWriter, r *http.Request) {
	streamID := parseInt64(r.URL.Query().Get("streamId"), 1)
	protocol := r.URL.Query().Get("protocol")
	if protocol == "" {
		protocol = "TCP"
	}
	writeJSON(w, http.StatusOK, s.svc.RawStream(protocol, streamID))
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

	ch := make(chan event, 256)
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
		select {
		case ch <- ev:
		default:
		}
	}
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
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

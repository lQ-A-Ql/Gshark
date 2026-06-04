package transport

import (
	"context"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gshark/sentinel/backend/internal/engine"
	"github.com/gshark/sentinel/backend/internal/mcp"
	"github.com/gshark/sentinel/backend/internal/miscpkg"
	"github.com/gshark/sentinel/backend/internal/model"
)

const (
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
	playbook     PlaybookService

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

	mcpServer   *mcp.Server
	ruleManager *engine.RuleManager
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
	s.ruleManager = engine.NewRuleManager("")
	s.ruleManager.LoadBuiltinPacks()
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
		StreamDecode: func(req mcp.StreamDecodeRequest) (any, error) {
			result, err := engine.DecodeStreamPayload(engine.StreamDecodeRequest{
				Decoder: req.Decoder,
				Payload: req.Payload,
				Options: req.Options,
			})
			if err != nil {
				return nil, err
			}
			return result, nil
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
	mux.HandleFunc("/api/tools/udp-tunnel", s.handleUDPTunnelAnalysis)
	mux.HandleFunc("/api/tools/bruteforce", s.handleBruteforceAnalysis)

	// Rule management routes.
	mux.HandleFunc("/api/rules/status", s.handleRulesStatus)
	mux.HandleFunc("/api/rules/config", s.handleRulesConfig)
	mux.HandleFunc("/api/rules/pack/toggle", s.handleRulesPackToggle)
	mux.HandleFunc("/api/rules/check-updates", s.handleRulesCheckUpdates)
	mux.HandleFunc("/api/rules/download", s.handleRulesDownload)
	mux.HandleFunc("/api/rules/conflicts", s.handleRulesConflicts)
	mux.HandleFunc("/api/rules/validate", s.handleRulesValidate)

	// Playbook and hypothesis management routes.
	mux.HandleFunc("/api/playbooks", s.handlePlaybooks)
	mux.HandleFunc("/api/playbooks/", s.handlePlaybookRoute)
	mux.HandleFunc("/api/hunting/saved-searches", s.handleSavedSearches)
	mux.HandleFunc("/api/hunting/saved-searches/", s.handleSavedSearchRoute)
	mux.HandleFunc("/api/hunting/hypotheses", s.handleHypotheses)
	mux.HandleFunc("/api/hunting/hypotheses/", s.handleHypothesisRoute)

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

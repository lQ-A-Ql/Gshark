package transport

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gshark/sentinel/backend/internal/engine"
	"github.com/gshark/sentinel/backend/internal/model"
)

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
		if _, err := engine.ValidateExecutablePathWithWarning(payload.Path, []string{"tshark"}); err != nil {
			writeError(w, http.StatusBadRequest, "invalid tshark path: "+err.Error())
			return
		}
		writeJSON(w, http.StatusOK, s.toolRuntime.SetTSharkPathWithContext(r.Context(), payload.Path))
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleAllowTSharkDir(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var payload struct {
		Dir string `json:"dir"`
	}
	if err := decodeJSONBody(w, r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	status := s.toolRuntime.AllowTSharkDirWithContext(r.Context(), payload.Dir)
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) handleListTSharkAllowedDirs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string][]string{"dirs": s.toolRuntime.TSharkAllowedDirs()})
}

func (s *Server) handleRemoveTSharkAllowedDir(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var payload struct {
		Dir string `json:"dir"`
	}
	if err := decodeJSONBody(w, r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	status := s.toolRuntime.RemoveTSharkAllowedDirWithContext(r.Context(), payload.Dir)
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) handleAllowToolDir(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var payload struct {
		Tool string `json:"tool"`
		Dir  string `json:"dir"`
	}
	if err := decodeJSONBody(w, r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	toolName := normalizeToolRuntimeName(payload.Tool)
	if toolName == "" {
		writeError(w, http.StatusBadRequest, "invalid tool")
		return
	}
	writeJSON(w, http.StatusOK, s.toolRuntime.AllowToolDirWithContext(r.Context(), toolName, payload.Dir))
}

func (s *Server) handleListToolAllowedDirs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	toolName := normalizeToolRuntimeName(r.URL.Query().Get("tool"))
	if toolName == "" {
		writeError(w, http.StatusBadRequest, "invalid tool")
		return
	}
	writeJSON(w, http.StatusOK, map[string][]string{"dirs": s.toolRuntime.ToolAllowedDirs(toolName)})
}

func (s *Server) handleRemoveToolAllowedDir(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var payload struct {
		Tool string `json:"tool"`
		Dir  string `json:"dir"`
	}
	if err := decodeJSONBody(w, r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	toolName := normalizeToolRuntimeName(payload.Tool)
	if toolName == "" {
		writeError(w, http.StatusBadRequest, "invalid tool")
		return
	}
	writeJSON(w, http.StatusOK, s.toolRuntime.RemoveToolAllowedDirWithContext(r.Context(), toolName, payload.Dir))
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
		if err := validateToolRuntimeConfigPaths(&cfg); err != nil {
			writeError(w, http.StatusBadRequest, "invalid tool runtime config: "+err.Error())
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
		writeJSON(w, http.StatusOK, s.currentMCPStatus(r))
	case http.MethodPost:
		var cfg model.MCPConfig
		if err := decodeJSONBody(w, r, &cfg); err != nil {
			writeError(w, http.StatusBadRequest, "invalid payload")
			return
		}
		s.toolRuntime.SetMCPConfig(cfg)
		writeJSON(w, http.StatusOK, s.currentMCPStatus(r))
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleMCP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	status := s.currentMCPStatus(r)
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

func validateToolRuntimeConfigPaths(cfg *model.ToolRuntimeConfig) error {
	if _, err := engine.ValidateExecutablePathWithWarning(cfg.TSharkPath, []string{"tshark"}, cfg.TSharkAllowedDirs...); err != nil {
		return fmt.Errorf("tshark_path: %w", err)
	}
	if _, err := engine.ValidateExecutablePathWithWarning(cfg.FFmpegPath, []string{"ffmpeg"}, cfg.FFmpegAllowedDirs...); err != nil {
		return fmt.Errorf("ffmpeg_path: %w", err)
	}
	if _, err := engine.ValidateExecutablePathWithWarning(cfg.PythonPath, []string{"python", "python3"}, cfg.PythonAllowedDirs...); err != nil {
		return fmt.Errorf("python_path: %w", err)
	}
	if _, err := engine.ValidateExecutablePathWithWarning(cfg.YaraBin, []string{"yara", "yara64"}, cfg.YaraAllowedDirs...); err != nil {
		return fmt.Errorf("yara_bin: %w", err)
	}
	return nil
}

func normalizeToolRuntimeName(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "tshark":
		return "tshark"
	case "ffmpeg":
		return "ffmpeg"
	case "python", "speech", "speech-to-text":
		return "python"
	case "yara":
		return "yara"
	default:
		return ""
	}
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

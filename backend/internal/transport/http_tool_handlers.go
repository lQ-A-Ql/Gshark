package transport

import (
	"net/http"
	"strings"

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

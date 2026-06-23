package transport

import (
	"net/http"
	"strings"

	"github.com/gshark/sentinel/backend/internal/engine"
	"github.com/gshark/sentinel/backend/internal/model"
)

func (s *Server) handleRulesStatus(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	if s.ruleManager == nil {
		writeError(w, http.StatusServiceUnavailable, "rule manager not initialized")
		return
	}
	writeJSON(w, http.StatusOK, s.ruleManager.Status())
}

func (s *Server) handleRulesConfig(w http.ResponseWriter, r *http.Request) {
	if s.ruleManager == nil {
		writeError(w, http.StatusServiceUnavailable, "rule manager not initialized")
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.ruleManager.GetUpdateConfig())
	case http.MethodPost:
		var cfg model.RuleUpdateConfig
		if err := decodeJSONBody(w, r, &cfg); err != nil {
			writeError(w, http.StatusBadRequest, "invalid payload")
			return
		}
		s.ruleManager.SetUpdateConfig(cfg)
		writeJSON(w, http.StatusOK, s.ruleManager.GetUpdateConfig())
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleRulesPackToggle(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	if s.ruleManager == nil {
		writeError(w, http.StatusServiceUnavailable, "rule manager not initialized")
		return
	}

	var payload struct {
		PackID  string `json:"pack_id"`
		Enabled bool   `json:"enabled"`
	}
	if err := decodeJSONBody(w, r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	if strings.TrimSpace(payload.PackID) == "" {
		writeError(w, http.StatusBadRequest, "pack_id is required")
		return
	}

	if err := s.ruleManager.SetPackEnabled(payload.PackID, payload.Enabled); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"pack_id": payload.PackID,
		"enabled": payload.Enabled,
	})
}

func (s *Server) handleRulesCheckUpdates(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	if s.ruleManager == nil {
		writeError(w, http.StatusServiceUnavailable, "rule manager not initialized")
		return
	}

	results, err := s.ruleManager.CheckForUpdates()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"results": results,
	})
}

func (s *Server) handleRulesDownload(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	if s.ruleManager == nil {
		writeError(w, http.StatusServiceUnavailable, "rule manager not initialized")
		return
	}

	var payload struct {
		PackID   string `json:"pack_id"`
		URL      string `json:"url"`
		Checksum string `json:"checksum"`
	}
	if err := decodeJSONBody(w, r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	if strings.TrimSpace(payload.PackID) == "" {
		writeError(w, http.StatusBadRequest, "pack_id is required")
		return
	}
	if strings.TrimSpace(payload.URL) == "" {
		writeError(w, http.StatusBadRequest, "url is required")
		return
	}

	pack, err := s.ruleManager.DownloadPack(payload.PackID, payload.URL, payload.Checksum)
	if err != nil {
		writeError(w, http.StatusBadRequest, sanitizeErrorMessage(err))
		return
	}

	writeJSON(w, http.StatusOK, pack)
}

func (s *Server) handleRulesConflicts(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	if s.ruleManager == nil {
		writeError(w, http.StatusServiceUnavailable, "rule manager not initialized")
		return
	}

	conflicts := s.ruleManager.DetectConflicts()
	writeJSON(w, http.StatusOK, map[string]any{
		"conflicts": conflicts,
		"count":     len(conflicts),
	})
}

func (s *Server) handleRulesValidate(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	if s.ruleManager == nil {
		writeError(w, http.StatusServiceUnavailable, "rule manager not initialized")
		return
	}

	var payload struct {
		Content string `json:"content"`
	}
	if err := decodeJSONBody(w, r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}

	validationErrors := s.ruleManager.ValidateRules(payload.Content)
	writeJSON(w, http.StatusOK, map[string]any{
		"valid":  len(validationErrors) == 0,
		"errors": validationErrors,
		"count":  len(validationErrors),
	})
}

// Ensure engine.RuleManager is referenced for compilation.
var _ *engine.RuleManager

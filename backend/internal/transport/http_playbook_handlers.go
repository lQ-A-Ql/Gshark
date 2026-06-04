package transport

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

// ---------------------------------------------------------------------------
// Playbook handlers
// ---------------------------------------------------------------------------

func (s *Server) handlePlaybooks(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.playbook.ListPlaybooks())
	case http.MethodPost:
		var pb model.HuntingPlaybook
		if err := decodeJSONBody(w, r, &pb); err != nil {
			writeError(w, http.StatusBadRequest, "invalid payload")
			return
		}
		created, err := s.playbook.CreatePlaybook(pb)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, created)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handlePlaybookByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/playbooks/")
	id = strings.TrimSuffix(id, "/run")
	if id == "" {
		writeError(w, http.StatusBadRequest, "playbook ID is required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		pb, ok := s.playbook.GetPlaybook(id)
		if !ok {
			writeError(w, http.StatusNotFound, "playbook not found")
			return
		}
		writeJSON(w, http.StatusOK, pb)
	case http.MethodPut:
		var pb model.HuntingPlaybook
		if err := decodeJSONBody(w, r, &pb); err != nil {
			writeError(w, http.StatusBadRequest, "invalid payload")
			return
		}
		pb.ID = id
		updated, err := s.playbook.UpdatePlaybook(pb)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, updated)
	case http.MethodDelete:
		if !s.playbook.DeletePlaybook(id) {
			writeError(w, http.StatusNotFound, "playbook not found")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handlePlaybookRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	// Path: /api/playbooks/{id}/run
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/playbooks/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, http.StatusBadRequest, "playbook ID is required")
		return
	}
	id := parts[0]

	result, err := s.playbook.RunPlaybook(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handlePlaybookLastRun(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	// Path: /api/playbooks/{id}/last-run
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/playbooks/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, http.StatusBadRequest, "playbook ID is required")
		return
	}
	id := parts[0]

	result, ok := s.playbook.GetPlaybookLastRun(id)
	if !ok {
		writeError(w, http.StatusNotFound, "no run result found")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// ---------------------------------------------------------------------------
// Saved search handlers
// ---------------------------------------------------------------------------

func (s *Server) handleSavedSearches(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.playbook.ListSavedSearches())
	case http.MethodPost:
		var ss model.SavedSearch
		if err := decodeJSONBody(w, r, &ss); err != nil {
			writeError(w, http.StatusBadRequest, "invalid payload")
			return
		}
		created, err := s.playbook.CreateSavedSearch(ss)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, created)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleSavedSearchByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/hunting/saved-searches/")
	if id == "" {
		writeError(w, http.StatusBadRequest, "saved search ID is required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		ss, ok := s.playbook.GetSavedSearch(id)
		if !ok {
			writeError(w, http.StatusNotFound, "saved search not found")
			return
		}
		writeJSON(w, http.StatusOK, ss)
	case http.MethodPut:
		var ss model.SavedSearch
		if err := decodeJSONBody(w, r, &ss); err != nil {
			writeError(w, http.StatusBadRequest, "invalid payload")
			return
		}
		ss.ID = id
		updated, err := s.playbook.UpdateSavedSearch(ss)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, updated)
	case http.MethodDelete:
		if !s.playbook.DeleteSavedSearch(id) {
			writeError(w, http.StatusNotFound, "saved search not found")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleSavedSearchExecute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	// Path: /api/hunting/saved-searches/{id}/execute
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/hunting/saved-searches/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, http.StatusBadRequest, "saved search ID is required")
		return
	}
	id := parts[0]

	ss, hits, err := s.playbook.ExecuteSavedSearch(id)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"search": ss,
		"hits":   hits,
		"total":  len(hits),
	})
}

// ---------------------------------------------------------------------------
// Hypothesis handlers
// ---------------------------------------------------------------------------

func (s *Server) handleHypotheses(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		statusFilter := r.URL.Query().Get("status")
		writeJSON(w, http.StatusOK, s.playbook.ListHypotheses(statusFilter))
	case http.MethodPost:
		var h model.Hypothesis
		if err := decodeJSONBody(w, r, &h); err != nil {
			writeError(w, http.StatusBadRequest, "invalid payload")
			return
		}
		created, err := s.playbook.CreateHypothesis(h)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, created)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleHypothesisByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/hunting/hypotheses/")
	// Strip sub-paths like /evidence, /status
	for _, suffix := range []string{"/evidence", "/status"} {
		if strings.HasSuffix(id, suffix) {
			id = strings.TrimSuffix(id, suffix)
			break
		}
	}
	if id == "" {
		writeError(w, http.StatusBadRequest, "hypothesis ID is required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		h, ok := s.playbook.GetHypothesis(id)
		if !ok {
			writeError(w, http.StatusNotFound, "hypothesis not found")
			return
		}
		writeJSON(w, http.StatusOK, h)
	case http.MethodPut:
		var h model.Hypothesis
		if err := decodeJSONBody(w, r, &h); err != nil {
			writeError(w, http.StatusBadRequest, "invalid payload")
			return
		}
		h.ID = id
		updated, err := s.playbook.UpdateHypothesis(h)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, updated)
	case http.MethodDelete:
		if !s.playbook.DeleteHypothesis(id) {
			writeError(w, http.StatusNotFound, "hypothesis not found")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleHypothesisEvidence(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	// Path: /api/hunting/hypotheses/{id}/evidence
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/hunting/hypotheses/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, http.StatusBadRequest, "hypothesis ID is required")
		return
	}
	id := parts[0]

	var evidence model.HypothesisEvidence
	if err := decodeJSONBody(w, r, &evidence); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}

	updated, err := s.playbook.AddHypothesisEvidence(id, evidence)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) handleHypothesisStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	// Path: /api/hunting/hypotheses/{id}/status
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/hunting/hypotheses/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, http.StatusBadRequest, "hypothesis ID is required")
		return
	}
	id := parts[0]

	var payload struct {
		Status     model.HypothesisStatus `json:"status"`
		Conclusion string                 `json:"conclusion,omitempty"`
	}
	if err := decodeJSONBody(w, r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}

	updated, err := s.playbook.UpdateHypothesisStatus(id, payload.Status, payload.Conclusion)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

// decodeJSONBody is a helper that decodes a JSON request body.
// It's already defined in the transport package, so we just use it.
func decodeJSONBodyTo(w http.ResponseWriter, r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}

// ---------------------------------------------------------------------------
// Route dispatchers
// ---------------------------------------------------------------------------

// handlePlaybookRoute dispatches /api/playbooks/{id}[/*] to the correct handler.
func (s *Server) handlePlaybookRoute(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/playbooks/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, http.StatusBadRequest, "playbook ID is required")
		return
	}
	if len(parts) >= 2 && parts[1] == "run" {
		s.handlePlaybookRun(w, r)
		return
	}
	if len(parts) >= 2 && parts[1] == "last-run" {
		s.handlePlaybookLastRun(w, r)
		return
	}
	s.handlePlaybookByID(w, r)
}

// handleSavedSearchRoute dispatches /api/hunting/saved-searches/{id}[/*].
func (s *Server) handleSavedSearchRoute(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/hunting/saved-searches/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, http.StatusBadRequest, "saved search ID is required")
		return
	}
	if len(parts) >= 2 && parts[1] == "execute" {
		s.handleSavedSearchExecute(w, r)
		return
	}
	s.handleSavedSearchByID(w, r)
}

// handleHypothesisRoute dispatches /api/hunting/hypotheses/{id}[/*].
func (s *Server) handleHypothesisRoute(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/hunting/hypotheses/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, http.StatusBadRequest, "hypothesis ID is required")
		return
	}
	if len(parts) >= 2 && parts[1] == "evidence" {
		s.handleHypothesisEvidence(w, r)
		return
	}
	if len(parts) >= 2 && parts[1] == "status" {
		s.handleHypothesisStatus(w, r)
		return
	}
	s.handleHypothesisByID(w, r)
}

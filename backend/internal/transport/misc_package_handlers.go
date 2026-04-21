package transport

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/gshark/sentinel/backend/internal/miscpkg"
	"github.com/gshark/sentinel/backend/internal/model"
	"github.com/gshark/sentinel/backend/internal/tshark"
)

func (s *Server) handleImportMiscModulePackage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.miscPkgMgr == nil {
		writeError(w, http.StatusServiceUnavailable, "misc package manager unavailable")
		return
	}
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "invalid multipart payload")
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "missing zip file")
		return
	}
	defer file.Close()

	raw, err := io.ReadAll(file)
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read zip file")
		return
	}

	result, err := s.miscPkgMgr.ImportZipBytes(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handlePackagedMiscModuleRoute(w http.ResponseWriter, r *http.Request) {
	if s.miscPkgMgr == nil {
		writeError(w, http.StatusServiceUnavailable, "misc package manager unavailable")
		return
	}
	trimmed := strings.TrimPrefix(r.URL.Path, "/api/tools/misc/packages/")
	parts := strings.Split(strings.Trim(trimmed, "/"), "/")
	if len(parts) == 1 && strings.TrimSpace(parts[0]) != "" {
		s.handleDeletePackagedMiscModule(w, r, parts[0])
		return
	}
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || parts[1] != "invoke" {
		writeError(w, http.StatusNotFound, "misc package route not found")
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req model.MiscModuleRunRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}

	runtime := miscpkg.InvokeContext{}
	if s.svc != nil {
		runtime.CapturePath = s.svc.CurrentCapturePath()
		runtime.PythonPath = s.svc.ToolRuntimeSnapshot().Config.PythonPath
	}
	runtime.TSharkPath = tshark.CurrentStatus().Path
	result, err := s.miscPkgMgr.Invoke(r.Context(), parts[0], req, runtime)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleDeletePackagedMiscModule(w http.ResponseWriter, r *http.Request, id string) {
	switch r.Method {
	case http.MethodDelete, http.MethodPost:
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.miscPkgMgr == nil {
		writeError(w, http.StatusServiceUnavailable, "misc package manager unavailable")
		return
	}
	if err := s.miscPkgMgr.Delete(id); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":      strings.TrimSpace(id),
		"deleted": true,
	})
}

package transport

import (
	"net/http"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

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
	case "/api/tools/tshark/allow-dir":
		return "tools.tshark.allow_dir"
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
	case "/api/capture/start", "/api/capture/upload", "/api/analysis/vehicle/dbc", "/api/tools/tshark", "/api/tools/tshark/allow-dir", "/api/tools/runtime-config", "/api/mcp/config", "/api/hunting/config":
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

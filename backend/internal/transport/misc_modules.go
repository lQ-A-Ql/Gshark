package transport

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

type MiscModule interface {
	Descriptor() model.MiscModuleManifest
	RegisterRoutes(mux *http.ServeMux, server *Server)
}

type miscRouteModule struct {
	descriptor model.MiscModuleManifest
	register   func(mux *http.ServeMux, server *Server)
}

func NewMiscRouteModule(descriptor model.MiscModuleManifest, register func(mux *http.ServeMux, server *Server)) MiscModule {
	return miscRouteModule{
		descriptor: descriptor,
		register:   register,
	}
}

func (m miscRouteModule) Descriptor() model.MiscModuleManifest {
	return m.descriptor
}

func (m miscRouteModule) RegisterRoutes(mux *http.ServeMux, server *Server) {
	if m.register != nil {
		m.register(mux, server)
	}
}

func defaultMiscModules() []MiscModule {
	return []MiscModule{
		NewMiscRouteModule(model.MiscModuleManifest{
			ID:              "winrm-decrypt",
			Kind:            "builtin",
			Title:           "WinRM 解密辅助",
			Summary:         "使用当前已加载抓包对 WinRM over HTTP + NTLM 流量做明文提取、预览与导出。",
			Tags:            []string{"WinRM", "NTLM", "解密"},
			APIPrefix:       "/api/tools/winrm-decrypt",
			DocsPath:        "docs/misc-module-interface.md",
			RequiresCapture: true,
		}, func(mux *http.ServeMux, server *Server) {
			mux.HandleFunc("/api/tools/winrm-decrypt", server.handleWinRMDecrypt)
			mux.HandleFunc("/api/tools/winrm-decrypt/export", server.handleWinRMDecryptExport)
		}),
		NewMiscRouteModule(model.MiscModuleManifest{
			ID:              "smb3-session-key",
			Kind:            "builtin",
			Title:           "SMB3 Random Session Key",
			Summary:         "从当前抓包提取 SMB3 / NTLM 会话材料，辅助生成 Random Session Key。",
			Tags:            []string{"SMB3", "NTLM", "SessionKey"},
			APIPrefix:       "/api/tools/smb3",
			DocsPath:        "docs/misc-module-interface.md",
			RequiresCapture: true,
		}, func(mux *http.ServeMux, server *Server) {
			mux.HandleFunc("/api/tools/smb3-session-candidates", server.handleSMB3SessionCandidates)
			mux.HandleFunc("/api/tools/smb3-random-session-key", server.handleSMB3RandomSessionKey)
		}),
	}
}

func (s *Server) RegisterMiscModule(module MiscModule) error {
	if module == nil {
		return fmt.Errorf("misc module 不能为空")
	}
	descriptor := module.Descriptor()
	if strings.TrimSpace(descriptor.ID) == "" {
		return fmt.Errorf("misc module id 不能为空")
	}
	if strings.TrimSpace(descriptor.Title) == "" {
		return fmt.Errorf("misc module title 不能为空")
	}
	if strings.TrimSpace(descriptor.Kind) == "" {
		descriptor.Kind = "custom"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.miscModules {
		if strings.EqualFold(existing.Descriptor().ID, descriptor.ID) {
			return fmt.Errorf("misc module %q 已存在", descriptor.ID)
		}
	}
	s.miscModules = append(s.miscModules, NewMiscRouteModule(descriptor, func(mux *http.ServeMux, server *Server) {
		module.RegisterRoutes(mux, server)
	}))
	return nil
}

func (s *Server) handleMiscModules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, s.miscModuleManifests())
}

func (s *Server) miscModuleManifests() []model.MiscModuleManifest {
	s.mu.Lock()
	defer s.mu.Unlock()
	manifests := make([]model.MiscModuleManifest, 0, len(s.miscModules)+8)
	for _, module := range s.miscModules {
		descriptor := module.Descriptor()
		descriptor.ID = strings.TrimSpace(descriptor.ID)
		descriptor.Title = strings.TrimSpace(descriptor.Title)
		descriptor.Kind = strings.TrimSpace(descriptor.Kind)
		descriptor.Summary = strings.TrimSpace(descriptor.Summary)
		descriptor.APIPrefix = strings.TrimSpace(descriptor.APIPrefix)
		descriptor.DocsPath = strings.TrimSpace(descriptor.DocsPath)
		descriptor.Tags = append([]string(nil), descriptor.Tags...)
		manifests = append(manifests, descriptor)
	}
	if s.miscPkgMgr != nil {
		manifests = append(manifests, s.miscPkgMgr.List()...)
	}
	sort.SliceStable(manifests, func(i, j int) bool {
		if manifests[i].Kind != manifests[j].Kind {
			return manifests[i].Kind < manifests[j].Kind
		}
		return manifests[i].Title < manifests[j].Title
	})
	return manifests
}

func (s *Server) registerMiscModuleRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/tools/misc/modules", s.handleMiscModules)
	mux.HandleFunc("/api/tools/misc/import", s.handleImportMiscModulePackage)
	mux.HandleFunc("/api/tools/misc/packages/", s.handlePackagedMiscModuleRoute)
	s.mu.Lock()
	modules := append([]MiscModule(nil), s.miscModules...)
	s.mu.Unlock()
	for _, module := range modules {
		module.RegisterRoutes(mux, s)
	}
}

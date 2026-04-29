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
			ID:              "payload-webshell-decoder",
			Kind:            "builtin",
			Title:           "Payload / WebShell 解码工作台",
			Summary:         "手动识别 HTTP body、表单参数、multipart、Base64、Hex 与常见 WebShell 编码/密文候选，集中执行实验性解码和结果导出。",
			Tags:            []string{"Payload", "WebShell", "Decode", "Base64", "Behinder", "AntSword", "Godzilla"},
			APIPrefix:       "/api/streams",
			DocsPath:        "docs/misc-module-interface.md",
			RequiresCapture: false,
			ProtocolDomain:  "Payload / WebShell",
			SupportsExport:  true,
			Cancellable:     true,
			DependsOn:       []string{"payload", "decode"},
		}, nil),
		NewMiscRouteModule(model.MiscModuleManifest{
			ID:              "http-login-analysis",
			Kind:            "builtin",
			Title:           "HTTP 登录行为分析",
			Summary:         "聚合 HTTP 登录/认证请求与响应，自动识别成功、失败、验证码/二次验证以及疑似爆破行为。",
			Tags:            []string{"HTTP", "Login", "Auth", "Bruteforce"},
			APIPrefix:       "/api/tools/http-login-analysis",
			DocsPath:        "docs/misc-module-interface.md",
			RequiresCapture: true,
			ProtocolDomain:  "HTTP / Auth",
			SupportsExport:  true,
			Cancellable:     true,
			DependsOn:       []string{"capture", "http"},
		}, nil),
		NewMiscRouteModule(model.MiscModuleManifest{
			ID:              "smtp-session-analysis",
			Kind:            "builtin",
			Title:           "SMTP 会话重建",
			Summary:         "重建 SMTP 认证、MAIL FROM / RCPT TO、DATA 邮件内容与附件线索，输出结构化邮件会话视图。",
			Tags:            []string{"SMTP", "Mail", "Attachment", "Auth"},
			APIPrefix:       "/api/tools/smtp-analysis",
			DocsPath:        "docs/misc-module-interface.md",
			RequiresCapture: true,
			ProtocolDomain:  "SMTP / Mail",
			SupportsExport:  true,
			Cancellable:     true,
			DependsOn:       []string{"capture", "smtp"},
		}, nil),
		NewMiscRouteModule(model.MiscModuleManifest{
			ID:              "mysql-session-analysis",
			Kind:            "builtin",
			Title:           "MySQL 会话重建",
			Summary:         "提取 MySQL 握手、登录用户名、默认数据库、查询语句与 OK/ERR/结果集响应，形成结构化会话视图。",
			Tags:            []string{"MySQL", "DB", "Query", "Auth"},
			APIPrefix:       "/api/tools/mysql-analysis",
			DocsPath:        "docs/misc-module-interface.md",
			RequiresCapture: true,
			ProtocolDomain:  "MySQL / Database",
			SupportsExport:  true,
			Cancellable:     true,
			DependsOn:       []string{"capture", "mysql"},
		}, nil),
		NewMiscRouteModule(model.MiscModuleManifest{
			ID:              "shiro-rememberme-analysis",
			Kind:            "builtin",
			Title:           "Shiro rememberMe 分析",
			Summary:         "定位 rememberMe Cookie，判断 deleteMe 回收痕迹，测试历史默认/自定义 AES 密钥并预览疑似 Java 序列化载荷。",
			Tags:            []string{"Shiro", "rememberMe", "Cookie", "Java", "Auth"},
			APIPrefix:       "/api/tools/shiro-rememberme",
			DocsPath:        "docs/misc-module-interface.md",
			RequiresCapture: true,
			ProtocolDomain:  "HTTP / Shiro",
			SupportsExport:  true,
			Cancellable:     true,
			DependsOn:       []string{"capture", "http"},
		}, nil),
		NewMiscRouteModule(model.MiscModuleManifest{
			ID:              "winrm-decrypt",
			Kind:            "builtin",
			Title:           "WinRM 解密辅助",
			Summary:         "使用当前已加载抓包对 WinRM over HTTP + NTLM 流量做明文提取、预览与导出。",
			Tags:            []string{"WinRM", "NTLM", "解密"},
			APIPrefix:       "/api/tools/winrm-decrypt",
			DocsPath:        "docs/misc-module-interface.md",
			RequiresCapture: true,
			ProtocolDomain:  "NTLM / WinRM",
			SupportsExport:  true,
			Cancellable:     true,
			DependsOn:       []string{"capture", "http", "ntlm"},
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
			ProtocolDomain:  "SMB3 / NTLM",
			Cancellable:     false,
			DependsOn:       []string{"capture", "ntlm"},
		}, func(mux *http.ServeMux, server *Server) {
			mux.HandleFunc("/api/tools/smb3-session-candidates", server.handleSMB3SessionCandidates)
			mux.HandleFunc("/api/tools/smb3-random-session-key", server.handleSMB3RandomSessionKey)
		}),
		NewMiscRouteModule(model.MiscModuleManifest{
			ID:              "ntlm-session-materials",
			Kind:            "builtin",
			Title:           "NTLM 会话材料中心",
			Summary:         "统一提取 HTTP / WinRM / SMB3 中的 NTLM challenge、NT proof、session key 与方向信息，并支持导出复盘。",
			Tags:            []string{"NTLM", "HTTP", "WinRM", "SMB3"},
			APIPrefix:       "/api/tools/ntlm-sessions",
			DocsPath:        "docs/misc-module-interface.md",
			RequiresCapture: true,
			ProtocolDomain:  "NTLM",
			SupportsExport:  true,
			Cancellable:     false,
			DependsOn:       []string{"capture", "ntlm"},
		}, nil),
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
		descriptor.ProtocolDomain = strings.TrimSpace(descriptor.ProtocolDomain)
		descriptor.Tags = append([]string(nil), descriptor.Tags...)
		descriptor.DependsOn = append([]string(nil), descriptor.DependsOn...)
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

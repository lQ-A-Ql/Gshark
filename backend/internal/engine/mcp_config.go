package engine

import "github.com/gshark/sentinel/backend/internal/model"

const mcpEndpoint = "http://127.0.0.1:17891/api/mcp"

func (s *Service) MCPConfig() model.MCPConfig {
	s.mcpCtl.mcpMu.RLock()
	defer s.mcpCtl.mcpMu.RUnlock()
	return s.mcpCtl.mcpConfig
}

func (s *Service) SetMCPConfig(cfg model.MCPConfig) model.MCPConfig {
	s.mcpCtl.mcpMu.Lock()
	s.mcpCtl.mcpConfig = model.MCPConfig{
		Enabled: cfg.Enabled,
	}
	s.mcpCtl.mcpMu.Unlock()
	return s.MCPConfig()
}

func (s *Service) MCPStatus(authRequired bool) model.MCPStatus {
	cfg := s.MCPConfig()
	return model.MCPStatus{
		Config:          cfg,
		Enabled:         cfg.Enabled,
		Endpoint:        mcpEndpoint,
		Transport:       "streamable-http",
		AuthRequired:    authRequired,
		ReadOnly:        true,
		RemoteSupported: false,
		StdioSupported:  false,
	}
}

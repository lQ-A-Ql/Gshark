package engine

import (
	"os"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
	"github.com/gshark/sentinel/backend/internal/tshark"
)

const (
	ffmpegEnvVar    = "GSHARK_FFMPEG"
	pythonEnvVar    = "GSHARK_PYTHON"
	voskModelEnvVar = "GSHARK_VOSK_MODEL"
)

func (s *Service) ToolRuntimeConfig() model.ToolRuntimeConfig {
	s.huntMu.RLock()
	yc := s.yaraConf
	s.huntMu.RUnlock()

	timeoutMS := yc.TimeoutMS
	if timeoutMS <= 0 {
		timeoutMS = 25000
	}

	return model.ToolRuntimeConfig{
		TSharkPath:    strings.TrimSpace(tshark.ConfiguredBinaryPath()),
		FFmpegPath:    strings.TrimSpace(os.Getenv(ffmpegEnvVar)),
		PythonPath:    strings.TrimSpace(os.Getenv(pythonEnvVar)),
		VoskModelPath: strings.TrimSpace(os.Getenv(voskModelEnvVar)),
		YaraEnabled:   yc.Enabled,
		YaraBin:       strings.TrimSpace(yc.Bin),
		YaraRules:     strings.TrimSpace(yc.Rules),
		YaraTimeoutMS: timeoutMS,
	}
}

func (s *Service) SetToolRuntimeConfig(cfg model.ToolRuntimeConfig) model.ToolRuntimeConfig {
	tshark.SetBinaryPath(strings.TrimSpace(cfg.TSharkPath))
	setEnvOrUnset(ffmpegEnvVar, cfg.FFmpegPath)
	setEnvOrUnset(pythonEnvVar, cfg.PythonPath)
	setEnvOrUnset(voskModelEnvVar, cfg.VoskModelPath)

	s.huntMu.Lock()
	s.yaraConf = model.YaraConfig{
		Enabled:   cfg.YaraEnabled,
		Bin:       strings.TrimSpace(cfg.YaraBin),
		Rules:     strings.TrimSpace(cfg.YaraRules),
		TimeoutMS: cfg.YaraTimeoutMS,
	}
	s.huntMu.Unlock()

	s.yaraMu.Lock()
	s.yaraLoaded = false
	s.yaraHits = nil
	s.yaraLastError = ""
	s.yaraMu.Unlock()

	return s.ToolRuntimeConfig()
}

func (s *Service) ToolRuntimeSnapshot() model.ToolRuntimeSnapshot {
	return model.ToolRuntimeSnapshot{
		Config: s.ToolRuntimeConfig(),
		TShark: tshark.CurrentStatus(),
		FFmpeg: s.FFmpegStatus(),
		Speech: s.SpeechToTextStatus(),
		Yara:   s.YaraStatus(),
	}
}

func (s *Service) YaraStatus() model.YaraToolStatus {
	s.huntMu.RLock()
	yc := s.yaraConf
	s.huntMu.RUnlock()
	s.yaraMu.Lock()
	lastScanMessage := strings.TrimSpace(s.yaraLastError)
	s.yaraMu.Unlock()

	timeoutMS := yc.TimeoutMS
	if timeoutMS <= 0 {
		timeoutMS = 25000
	}

	status := model.YaraToolStatus{
		Enabled:          yc.Enabled,
		CustomBin:        strings.TrimSpace(yc.Bin),
		CustomRules:      strings.TrimSpace(yc.Rules),
		UsingCustomBin:   strings.TrimSpace(yc.Bin) != "",
		UsingCustomRules: strings.TrimSpace(yc.Rules) != "",
		TimeoutMS:        timeoutMS,
		LastScanMessage:  lastScanMessage,
	}

	yaraExe, err := resolveYaraExecutable(yc.Bin)
	if err != nil {
		status.Available = false
		if !status.Enabled {
			status.Message = "YARA 已关闭"
		} else {
			status.Message = err.Error()
		}
		return status
	}
	status.Path = yaraExe

	bundle, err := resolveYaraRuleBundle(yc.Rules)
	if err != nil {
		status.Available = false
		status.Message = err.Error()
		return status
	}
	status.RulePath = bundle.path
	status.Available = true
	if !status.Enabled {
		status.Message = "YARA 已关闭"
		return status
	}
	status.Message = "ok"
	if lastScanMessage != "" {
		status.Message = "ok（最近一次扫描有告警）"
	}
	return status
}

func setEnvOrUnset(key, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		_ = os.Unsetenv(key)
		return
	}
	_ = os.Setenv(key, value)
}

package engine

import (
	"context"
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

// ToolRuntimeConfig returns a coherent snapshot of the tool runtime
// configuration. Because the underlying state lives in three different
// backings (OS env vars, the tshark package global, and s.yaraConf under
// s.huntMu), the read is guarded by s.toolRuntimeMu so concurrent callers
// of SetToolRuntimeConfig cannot observe half-applied state.
func (s *Service) ToolRuntimeConfig() model.ToolRuntimeConfig {
	s.toolRuntimeMu.RLock()
	defer s.toolRuntimeMu.RUnlock()
	return s.toolRuntimeConfigLocked()
}

// toolRuntimeConfigLocked returns the current tool runtime configuration.
// Callers MUST hold s.toolRuntimeMu (read or write). The function briefly
// takes s.huntMu internally to copy the yaraConf slice; s.huntMu is a
// different mutex so there is no risk of re-entering s.toolRuntimeMu.
func (s *Service) toolRuntimeConfigLocked() model.ToolRuntimeConfig {
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

// SetToolRuntimeConfig atomically applies cfg to the three config backings
// and returns the resulting coherent snapshot. Holding s.toolRuntimeMu for
// the entire critical section — including the concluding read — guarantees
// no other reader or writer can interleave.
func (s *Service) SetToolRuntimeConfig(cfg model.ToolRuntimeConfig) model.ToolRuntimeConfig {
	s.toolRuntimeMu.Lock()
	defer s.toolRuntimeMu.Unlock()

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

	return s.toolRuntimeConfigLocked()
}

// ToolRuntimeSnapshot composes the configuration with the status reports
// of each tool. The underlying status getters (TShark/FFmpeg/Speech/Yara)
// manage their own locking on independent mutexes, so the snapshot is
// coherent for the configuration slice without re-locking them here.
func (s *Service) ToolRuntimeSnapshot() model.ToolRuntimeSnapshot {
	return s.ToolRuntimeSnapshotWithContext(context.Background())
}

func (s *Service) ToolRuntimeSnapshotWithContext(ctx context.Context) model.ToolRuntimeSnapshot {
	return model.ToolRuntimeSnapshot{
		Config: s.ToolRuntimeConfig(),
		TShark: toModelTSharkStatus(tshark.CurrentStatusWithContext(ctx)),
		FFmpeg: s.FFmpegStatus(),
		Speech: s.SpeechToTextStatus(),
		Yara:   s.YaraStatus(),
	}
}

func toModelTSharkStatus(status tshark.Status) model.TSharkToolStatus {
	return model.TSharkToolStatus{
		Available:               status.Available,
		Path:                    status.Path,
		Message:                 status.Message,
		CustomPath:              status.CustomPath,
		UsingCustomPath:         status.UsingCustomPath,
		Version:                 status.Version,
		FieldProfile:            status.FieldProfile,
		FieldCount:              status.FieldCount,
		MissingRequiredFields:   append([]string(nil), status.MissingRequiredFields...),
		MissingOptionalFields:   append([]string(nil), status.MissingOptionalFields...),
		CapabilityMessage:       status.CapabilityMessage,
		CapabilityCheckDegraded: status.CapabilityCheckDegraded,
	}
}

func toModelFFmpegStatus(status FFmpegStatus) model.FFmpegToolStatus {
	return model.FFmpegToolStatus{
		Available:       status.Available,
		Path:            status.Path,
		Message:         status.Message,
		CustomPath:      status.CustomPath,
		UsingCustomPath: status.UsingCustomPath,
	}
}

func (s *Service) TSharkStatus() model.TSharkToolStatus {
	return s.TSharkStatusWithContext(context.Background())
}

func (s *Service) TSharkStatusWithContext(ctx context.Context) model.TSharkToolStatus {
	return toModelTSharkStatus(tshark.CurrentStatusWithContext(ctx))
}

// SetTSharkPath updates the tshark binary path. It takes s.toolRuntimeMu
// so a concurrent SetToolRuntimeConfig cannot observe or clobber a
// partially-applied tshark path.
func (s *Service) SetTSharkPath(path string) model.TSharkToolStatus {
	return s.SetTSharkPathWithContext(context.Background(), path)
}

func (s *Service) SetTSharkPathWithContext(ctx context.Context, path string) model.TSharkToolStatus {
	s.toolRuntimeMu.Lock()
	defer s.toolRuntimeMu.Unlock()
	tshark.SetBinaryPath(strings.TrimSpace(path))
	return toModelTSharkStatus(tshark.CurrentStatusWithContext(ctx))
}

func (s *Service) TSharkStatusPath() string {
	return tshark.CurrentStatus().Path
}

func (s *Service) TSharkUsingCustomPath() bool {
	return tshark.CurrentStatus().UsingCustomPath
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

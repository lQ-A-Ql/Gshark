package engine

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/gshark/sentinel/backend/internal/model"
	"github.com/gshark/sentinel/backend/internal/tool"
	"github.com/gshark/sentinel/backend/internal/tshark"
)

const (
	ffmpegEnvVar    = "MEOW_TRAFFIC_FFMPEG"
	pythonEnvVar    = "MEOW_TRAFFIC_PYTHON"
	voskModelEnvVar = "MEOW_TRAFFIC_VOSK_MODEL"
)

const (
	ToolRuntimeProbeModeFast = "fast"
	ToolRuntimeProbeModeFull = "full"
)

// ToolRuntimeConfig returns a coherent snapshot of the tool runtime
// configuration. Because the underlying state lives in three different
// backings (OS env vars, the tshark package global, and s.yaraConf under
// s.huntMu), the read is guarded by s.toolRuntimeMu so concurrent callers
// of SetToolRuntimeConfig cannot observe half-applied state.
func (s *Service) ToolRuntimeConfig() model.ToolRuntimeConfig {
	return s.runtimeCtl.configWithYara(s.huntingCtl.config())
}

func (ctl *toolRuntimeController) configWithYara(yc model.YaraConfig) model.ToolRuntimeConfig {
	ctl.toolRuntimeMu.Lock()
	defer ctl.toolRuntimeMu.Unlock()
	ctl.ensureRuntimesLocked()
	return ctl.toolRuntimeConfigFromYaraLocked(yc)
}

func (ctl *toolRuntimeController) toolRuntimeConfigFromYaraLocked(yc model.YaraConfig) model.ToolRuntimeConfig {
	timeoutMS := yc.TimeoutMS
	if timeoutMS <= 0 {
		timeoutMS = 25000
	}

	return model.ToolRuntimeConfig{
		TSharkPath:        strings.TrimSpace(tshark.ConfiguredBinaryPath()),
		TSharkAllowedDirs: ctl.tsharkRuntime.AllowedDirs(),
		FFmpegPath:        configuredPathOrEnv(ctl.ffmpegRuntime, ffmpegEnvVar),
		FFmpegAllowedDirs: ctl.ffmpegRuntime.AllowedDirs(),
		PythonPath:        configuredPathOrEnv(ctl.pythonRuntime, pythonEnvVar),
		PythonAllowedDirs: ctl.pythonRuntime.AllowedDirs(),
		VoskModelPath:     strings.TrimSpace(os.Getenv(voskModelEnvVar)),
		YaraEnabled:       yc.Enabled,
		YaraBin:           configuredPathOrValue(ctl.yaraRuntime, yc.Bin),
		YaraAllowedDirs:   ctl.yaraRuntime.AllowedDirs(),
		YaraRules:         strings.TrimSpace(yc.Rules),
		YaraTimeoutMS:     timeoutMS,
	}
}

func (s *Service) SetToolRuntimeConfig(cfg model.ToolRuntimeConfig) model.ToolRuntimeConfig {
	applied := s.runtimeCtl.applyConfig(cfg)
	s.huntingCtl.setConfig(model.YaraConfig{
		Enabled:     cfg.YaraEnabled,
		Bin:         applied.YaraBin,
		AllowedDirs: applied.YaraAllowedDirs,
		Rules:       strings.TrimSpace(cfg.YaraRules),
		TimeoutMS:   cfg.YaraTimeoutMS,
	})
	s.resetYaraScanState()
	clearSpeechRuntimeProbeCache()
	tshark.ClearCapabilityCache()

	return s.ToolRuntimeConfig()
}

func (ctl *toolRuntimeController) applyConfig(cfg model.ToolRuntimeConfig) model.ToolRuntimeConfig {
	ctl.toolRuntimeMu.Lock()
	defer ctl.toolRuntimeMu.Unlock()
	ctl.ensureRuntimesLocked()

	ctl.tsharkRuntime.SetAllowedDirs(cfg.TSharkAllowedDirs)
	_, _ = ctl.tsharkRuntime.SetPath(cfg.TSharkPath)
	tshark.SetBinaryPath(ctl.tsharkRuntime.ConfiguredPath())

	ctl.ffmpegRuntime.SetAllowedDirs(cfg.FFmpegAllowedDirs)
	_, _ = ctl.ffmpegRuntime.SetPath(cfg.FFmpegPath)
	setEnvOrUnset(ffmpegEnvVar, ctl.ffmpegRuntime.ConfiguredPath())

	ctl.pythonRuntime.SetAllowedDirs(cfg.PythonAllowedDirs)
	_, _ = ctl.pythonRuntime.SetPath(cfg.PythonPath)
	setEnvOrUnset(pythonEnvVar, ctl.pythonRuntime.ConfiguredPath())

	ctl.yaraRuntime.SetAllowedDirs(cfg.YaraAllowedDirs)
	_, _ = ctl.yaraRuntime.SetPath(cfg.YaraBin)
	setEnvOrUnset(voskModelEnvVar, cfg.VoskModelPath)
	return ctl.toolRuntimeConfigFromYaraLocked(model.YaraConfig{
		Enabled:     cfg.YaraEnabled,
		Bin:         ctl.yaraRuntime.ConfiguredPath(),
		AllowedDirs: ctl.yaraRuntime.AllowedDirs(),
		Rules:       cfg.YaraRules,
		TimeoutMS:   cfg.YaraTimeoutMS,
	})
}

// ToolRuntimeSnapshot composes the configuration with the status reports
// of each tool. The underlying status getters (TShark/FFmpeg/Speech/Yara)
// manage their own locking on independent mutexes, so the snapshot is
// coherent for the configuration slice without re-locking them here.
func (s *Service) ToolRuntimeSnapshot() model.ToolRuntimeSnapshot {
	return s.ToolRuntimeSnapshotWithContext(context.Background())
}

func (s *Service) ToolRuntimeSnapshotWithContext(ctx context.Context) model.ToolRuntimeSnapshot {
	return s.ToolRuntimeSnapshotWithOptions(ctx, model.ToolRuntimeProbeOptions{Mode: ToolRuntimeProbeModeFull})
}

func (s *Service) ToolRuntimeSnapshotWithOptions(ctx context.Context, opts model.ToolRuntimeProbeOptions) model.ToolRuntimeSnapshot {
	if ctx == nil {
		ctx = context.Background()
	}
	mode := normalizeToolRuntimeProbeMode(opts.Mode)
	if mode == ToolRuntimeProbeModeFull {
		s.runtimeCtl.toolRuntimeFullProbeMu.Lock()
		defer s.runtimeCtl.toolRuntimeFullProbeMu.Unlock()
	}

	probeTimings := map[string]int64{}
	probeErrors := map[string]string{}
	snapshot := model.ToolRuntimeSnapshot{
		ProbeMode:    mode,
		ProbeState:   "partial",
		ProbeTimings: probeTimings,
		ProbeErrors:  probeErrors,
		UpdatedAt:    time.Now().Format(time.RFC3339Nano),
	}

	snapshot.Config = timedRuntimeProbe(probeTimings, "config", func() model.ToolRuntimeConfig {
		return s.ToolRuntimeConfig()
	})

	probeCapabilities := mode == ToolRuntimeProbeModeFull
	snapshot.TShark = timedRuntimeProbe(probeTimings, "tshark", func() model.TSharkToolStatus {
		status := toModelTSharkStatus(tshark.CurrentStatusWithOptions(ctx, tshark.StatusOptions{ProbeCapabilities: probeCapabilities}))
		status.PathWarning = s.runtimeCtl.tsharkRuntime.PathWarning()
		if status.PathWarning == "" && status.ExtraAllowedDir == "" {
			status.ExtraAllowedDir = s.runtimeCtl.tsharkRuntime.ExtraAllowedDir(tshark.ConfiguredBinaryPath())
		}
		return status
	})
	recordRuntimeStatusError(probeErrors, "tshark", snapshot.TShark.Available, snapshot.TShark.Message)
	if snapshot.TShark.PathWarning != "" && probeErrors["tshark"] == "" {
		probeErrors["tshark"] = snapshot.TShark.PathWarning
	}

	ffmpegInternal := timedRuntimeProbe(probeTimings, "ffmpeg", func() FFmpegStatus {
		return s.ffmpegStatus()
	})
	snapshot.FFmpeg = toModelFFmpegStatus(ffmpegInternal)
	recordRuntimeStatusError(probeErrors, "ffmpeg", snapshot.FFmpeg.Available, snapshot.FFmpeg.Message)

	ffmpegAvailable := ffmpegInternal.Available
	snapshot.Speech = timedRuntimeProbe(probeTimings, "speech", func() model.SpeechToTextStatus {
		return s.SpeechToTextStatusWithContext(ctx, SpeechStatusOptions{
			Fast:            mode == ToolRuntimeProbeModeFast,
			FFmpegAvailable: &ffmpegAvailable,
		})
	})
	recordRuntimeStatusError(probeErrors, "speech", snapshot.Speech.Available, snapshot.Speech.Message)

	snapshot.Yara = timedRuntimeProbe(probeTimings, "yara", func() model.YaraToolStatus {
		return s.YaraStatus()
	})
	recordRuntimeStatusError(probeErrors, "yara", snapshot.Yara.Available || !snapshot.Yara.Enabled, snapshot.Yara.Message)

	if err := ctx.Err(); err != nil {
		if err == context.DeadlineExceeded {
			snapshot.ProbeState = "timeout"
		} else {
			snapshot.ProbeState = "failed"
		}
		probeErrors["snapshot"] = err.Error()
		return snapshot
	}
	if mode == ToolRuntimeProbeModeFast {
		snapshot.ProbeState = "fast_ready"
	} else {
		snapshot.ProbeState = "full_ready"
	}
	return snapshot
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
		PathWarning:     status.PathWarning,
		ExtraAllowedDir: status.ExtraAllowedDir,
	}
}

func (s *Service) TSharkStatus() model.TSharkToolStatus {
	return s.TSharkStatusWithContext(context.Background())
}

func (s *Service) TSharkStatusWithContext(ctx context.Context) model.TSharkToolStatus {
	status := toModelTSharkStatus(tshark.CurrentStatusWithContext(ctx))
	status.PathWarning = s.runtimeCtl.tsharkRuntime.PathWarning()
	if status.PathWarning == "" && status.ExtraAllowedDir == "" {
		status.ExtraAllowedDir = s.runtimeCtl.tsharkRuntime.ExtraAllowedDir(tshark.ConfiguredBinaryPath())
	}
	return status
}

func toolExtraAllowedDirForStatus(path string, extraAllowedDirs []string) string {
	return tool.NewAllowedDirList(extraAllowedDirs).MatchingDir(path)
}

func tsharkExtraAllowedDirForStatus(path string, extraAllowedDirs []string) string {
	return toolExtraAllowedDirForStatus(path, extraAllowedDirs)
}

// SetTSharkPath updates the tshark binary path. It takes s.toolRuntimeMu
// so a concurrent SetToolRuntimeConfig cannot observe or clobber a
// partially-applied tshark path.
func (s *Service) SetTSharkPath(path string) model.TSharkToolStatus {
	return s.SetTSharkPathWithContext(context.Background(), path)
}

func (s *Service) SetTSharkPathWithContext(ctx context.Context, path string) model.TSharkToolStatus {
	return s.runtimeCtl.setTSharkPath(ctx, path)
}

func (s *Service) AllowTSharkDirWithContext(ctx context.Context, dir string) model.TSharkToolStatus {
	return s.runtimeCtl.allowTSharkDir(ctx, dir)
}

func (s *Service) TSharkAllowedDirs() []string {
	return s.runtimeCtl.tsharkAllowedDirs()
}

func (s *Service) RemoveTSharkAllowedDirWithContext(ctx context.Context, dir string) model.TSharkToolStatus {
	return s.runtimeCtl.removeTSharkAllowedDir(ctx, dir)
}

func (s *Service) AllowToolDirWithContext(ctx context.Context, toolName string, dir string) model.ToolRuntimeSnapshot {
	s.runtimeCtl.allowToolDir(toolName, dir)
	clearSpeechRuntimeProbeCache()
	tshark.ClearCapabilityCache()
	return s.ToolRuntimeSnapshotWithOptions(ctx, model.ToolRuntimeProbeOptions{Mode: ToolRuntimeProbeModeFast})
}

func (s *Service) ToolAllowedDirs(toolName string) []string {
	return s.runtimeCtl.toolAllowedDirs(toolName)
}

func (s *Service) RemoveToolAllowedDirWithContext(ctx context.Context, toolName string, dir string) model.ToolRuntimeSnapshot {
	s.runtimeCtl.removeToolAllowedDir(toolName, dir)
	clearSpeechRuntimeProbeCache()
	tshark.ClearCapabilityCache()
	return s.ToolRuntimeSnapshotWithOptions(ctx, model.ToolRuntimeProbeOptions{Mode: ToolRuntimeProbeModeFast})
}

func (s *Service) TSharkStatusPath() string {
	return tshark.CurrentStatus().Path
}

func (s *Service) TSharkUsingCustomPath() bool {
	return tshark.CurrentStatus().UsingCustomPath
}

func (s *Service) YaraStatus() model.YaraToolStatus {
	return s.huntingCtl.statusWithAllowedDirs(s.runtimeCtl.yaraAllowedDirs())
}

func (s *Service) pythonRuntimeWarnings() (string, string) {
	s.runtimeCtl.toolRuntimeMu.Lock()
	defer s.runtimeCtl.toolRuntimeMu.Unlock()
	s.runtimeCtl.ensureRuntimesLocked()
	path := configuredPathOrEnv(s.runtimeCtl.pythonRuntime, pythonEnvVar)
	return s.runtimeCtl.pythonRuntime.PathWarning(), s.runtimeCtl.pythonRuntime.ExtraAllowedDir(path)
}

func (ctl *toolRuntimeController) setTSharkPath(ctx context.Context, path string) model.TSharkToolStatus {
	ctl.toolRuntimeMu.Lock()
	defer ctl.toolRuntimeMu.Unlock()
	ctl.ensureRuntimesLocked()

	warning, err := ctl.tsharkRuntime.SetPath(path)
	if err != nil {
		return model.TSharkToolStatus{
			Available:       false,
			Message:         err.Error(),
			CustomPath:      strings.TrimSpace(path),
			UsingCustomPath: false,
			PathWarning:     "",
		}
	}
	tshark.SetBinaryPath(ctl.tsharkRuntime.ConfiguredPath())
	tshark.ClearCapabilityCache()
	status := toModelTSharkStatus(tshark.CurrentStatusWithContext(ctx))
	status.PathWarning = warning
	if warning == "" && status.ExtraAllowedDir == "" {
		status.ExtraAllowedDir = ctl.tsharkRuntime.ExtraAllowedDir(ctl.tsharkRuntime.ConfiguredPath())
	}
	return status
}

func (ctl *toolRuntimeController) allowTSharkDir(ctx context.Context, dir string) model.TSharkToolStatus {
	ctl.toolRuntimeMu.Lock()
	defer ctl.toolRuntimeMu.Unlock()
	ctl.ensureRuntimesLocked()
	ctl.tsharkRuntime.AllowDir(dir)
	return ctl.revalidateTSharkPathLocked(ctx)
}

func (ctl *toolRuntimeController) tsharkAllowedDirs() []string {
	ctl.toolRuntimeMu.Lock()
	defer ctl.toolRuntimeMu.Unlock()
	ctl.ensureRuntimesLocked()
	return ctl.tsharkRuntime.AllowedDirs()
}

func (ctl *toolRuntimeController) removeTSharkAllowedDir(ctx context.Context, dir string) model.TSharkToolStatus {
	ctl.toolRuntimeMu.Lock()
	defer ctl.toolRuntimeMu.Unlock()
	ctl.ensureRuntimesLocked()
	ctl.tsharkRuntime.RemoveDir(dir)
	return ctl.revalidateTSharkPathLocked(ctx)
}

func (ctl *toolRuntimeController) revalidateTSharkPathLocked(ctx context.Context) model.TSharkToolStatus {
	trimmed := ctl.tsharkRuntime.ConfiguredPath()
	warning, err := ctl.tsharkRuntime.Revalidate()
	if err != nil {
		// Hard validation error on the configured path: surface it as an
		// unavailable status and drop the stale path so subsequent probes
		// don't keep using it.
		ctl.tsharkRuntime.ClearPath()
		tshark.SetBinaryPath("")
		return model.TSharkToolStatus{
			Available:       false,
			Message:         err.Error(),
			CustomPath:      trimmed,
			UsingCustomPath: tshark.CurrentStatus().UsingCustomPath,
			PathWarning:     "",
		}
	}
	status := toModelTSharkStatus(tshark.CurrentStatusWithContext(ctx))
	status.PathWarning = warning
	if warning == "" && status.ExtraAllowedDir == "" {
		status.ExtraAllowedDir = ctl.tsharkRuntime.ExtraAllowedDir(trimmed)
	}
	return status
}

func (ctl *yaraHuntingController) config() model.YaraConfig {
	ctl.huntMu.RLock()
	defer ctl.huntMu.RUnlock()
	return ctl.yaraConf
}

func (ctl *yaraHuntingController) setConfig(yc model.YaraConfig) {
	ctl.huntMu.Lock()
	ctl.yaraConf = yc
	ctl.huntMu.Unlock()
}

func (ctl *yaraHuntingController) statusWithAllowedDirs(allowedDirs []string) model.YaraToolStatus {
	yc := ctl.config()
	if len(allowedDirs) > 0 {
		yc.AllowedDirs = append([]string(nil), allowedDirs...)
	}
	ctl.yaraMu.Lock()
	lastScanMessage := strings.TrimSpace(ctl.yaraLastError)
	ctl.yaraMu.Unlock()
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

	yaraExe, binWarning, err := resolveYaraExecutableWithAllowedDirs(yc.Bin, yc.AllowedDirs)
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
	status.PathWarning = binWarning
	if binWarning == "" {
		status.ExtraAllowedDir = toolExtraAllowedDirForStatus(yaraExe, yc.AllowedDirs)
	}
	if binWarning != "" {
		status.Message = binWarning
	}

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

func (ctl *toolRuntimeController) yaraAllowedDirs() []string {
	return ctl.toolAllowedDirs("yara")
}

func (ctl *toolRuntimeController) runtimeByToolNameLocked(toolName string) *tool.Runtime {
	ctl.ensureRuntimesLocked()
	switch strings.ToLower(strings.TrimSpace(toolName)) {
	case "tshark":
		return ctl.tsharkRuntime
	case "ffmpeg":
		return ctl.ffmpegRuntime
	case "python", "speech", "speech-to-text":
		return ctl.pythonRuntime
	case "yara":
		return ctl.yaraRuntime
	default:
		return nil
	}
}

func (ctl *toolRuntimeController) allowToolDir(toolName string, dir string) {
	ctl.toolRuntimeMu.Lock()
	defer ctl.toolRuntimeMu.Unlock()
	if rt := ctl.runtimeByToolNameLocked(toolName); rt != nil {
		rt.AllowDir(dir)
		_, _ = rt.Revalidate()
		ctl.syncConfiguredPathLocked(rt)
	}
}

func (ctl *toolRuntimeController) removeToolAllowedDir(toolName string, dir string) {
	ctl.toolRuntimeMu.Lock()
	defer ctl.toolRuntimeMu.Unlock()
	if rt := ctl.runtimeByToolNameLocked(toolName); rt != nil {
		rt.RemoveDir(dir)
		_, _ = rt.Revalidate()
		ctl.syncConfiguredPathLocked(rt)
	}
}

func (ctl *toolRuntimeController) setYaraRuntimePath(path string) (string, []string) {
	ctl.toolRuntimeMu.Lock()
	defer ctl.toolRuntimeMu.Unlock()
	ctl.ensureRuntimesLocked()
	if _, err := ctl.yaraRuntime.SetPath(path); err != nil {
		ctl.yaraRuntime.ClearPath()
	}
	return ctl.yaraRuntime.ConfiguredPath(), ctl.yaraRuntime.AllowedDirs()
}

func (ctl *toolRuntimeController) toolAllowedDirs(toolName string) []string {
	ctl.toolRuntimeMu.Lock()
	defer ctl.toolRuntimeMu.Unlock()
	if rt := ctl.runtimeByToolNameLocked(toolName); rt != nil {
		return rt.AllowedDirs()
	}
	return nil
}

func (ctl *toolRuntimeController) syncConfiguredPathLocked(rt *tool.Runtime) {
	if rt == nil {
		return
	}
	switch rt.Name() {
	case "tshark":
		tshark.SetBinaryPath(rt.ConfiguredPath())
	case "ffmpeg":
		setEnvOrUnset(ffmpegEnvVar, rt.ConfiguredPath())
	case "python":
		setEnvOrUnset(pythonEnvVar, rt.ConfiguredPath())
	}
}

func (ctl *toolRuntimeController) ensureRuntimesLocked() {
	if ctl.tsharkRuntime == nil {
		ctl.tsharkRuntime = tool.NewRuntime("tshark", []string{"tshark"}, nil)
	}
	if ctl.ffmpegRuntime == nil {
		ctl.ffmpegRuntime = tool.NewRuntime("ffmpeg", []string{"ffmpeg"}, nil)
	}
	if ctl.pythonRuntime == nil {
		ctl.pythonRuntime = tool.NewRuntime("python", []string{"python", "python3"}, nil)
	}
	if ctl.yaraRuntime == nil {
		ctl.yaraRuntime = tool.NewRuntime("yara", []string{"yara", "yara64"}, nil)
	}
}

func configuredPathOrEnv(rt *tool.Runtime, envKey string) string {
	if rt != nil {
		if configured := strings.TrimSpace(rt.ConfiguredPath()); configured != "" {
			return configured
		}
	}
	return strings.TrimSpace(os.Getenv(envKey))
}

func configuredPathOrValue(rt *tool.Runtime, fallback string) string {
	if rt != nil {
		if configured := strings.TrimSpace(rt.ConfiguredPath()); configured != "" {
			return configured
		}
	}
	return strings.TrimSpace(fallback)
}

func setEnvOrUnset(key, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		_ = os.Unsetenv(key)
		return
	}
	_ = os.Setenv(key, value)
}

func normalizeToolRuntimeProbeMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case ToolRuntimeProbeModeFast:
		return ToolRuntimeProbeModeFast
	default:
		return ToolRuntimeProbeModeFull
	}
}

func timedRuntimeProbe[T any](timings map[string]int64, name string, fn func() T) T {
	start := time.Now()
	value := fn()
	if timings != nil {
		timings[name] = time.Since(start).Milliseconds()
	}
	return value
}

func recordRuntimeStatusError(errors map[string]string, component string, ok bool, message string) {
	message = strings.TrimSpace(message)
	if errors == nil || ok || message == "" || message == "ok" {
		return
	}
	errors[component] = message
}

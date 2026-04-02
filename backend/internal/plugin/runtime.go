package plugin

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dop251/goja"
	"github.com/gshark/sentinel/backend/internal/model"
)

var pluginExportRE = regexp.MustCompile(`(?m)^\s*export\s+`)

const defaultPluginRuntimeTimeout = 10 * time.Second

type PacketPluginRunner struct {
	sessions []packetPluginSession
	warnings []string
}

type packetPluginSession interface {
	ProcessBatch([]model.Packet)
	Close() ([]model.ThreatHit, error)
	Name() string
	Warnings() []string
}

type runtimeCandidate struct {
	meta      model.Plugin
	logicPath string
}

func (m *Manager) NewPacketPluginRunner() *PacketPluginRunner {
	candidates := m.runtimeCandidates()
	if len(candidates) == 0 {
		return nil
	}

	sessions := make([]packetPluginSession, 0, len(candidates))
	warnings := make([]string, 0)
	for _, candidate := range candidates {
		session, err := newPacketPluginSession(candidate.meta, candidate.logicPath)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: %v", candidate.meta.ID, err))
			continue
		}
		sessions = append(sessions, session)
	}
	if len(sessions) == 0 && len(warnings) == 0 {
		return nil
	}
	return &PacketPluginRunner{sessions: sessions, warnings: warnings}
}

func (r *PacketPluginRunner) ProcessBatch(packets []model.Packet) {
	if r == nil || len(r.sessions) == 0 || len(packets) == 0 {
		return
	}
	for _, session := range r.sessions {
		session.ProcessBatch(packets)
	}
}

func (r *PacketPluginRunner) Close(startID int64) []model.ThreatHit {
	if r == nil || len(r.sessions) == 0 {
		return nil
	}
	if startID <= 0 {
		startID = 1
	}

	hits := make([]model.ThreatHit, 0, 32)
	nextID := startID
	for _, session := range r.sessions {
		sessionHits, err := session.Close()
		r.warnings = append(r.warnings, session.Warnings()...)
		if err != nil {
			r.warnings = append(r.warnings, fmt.Sprintf("%s: %v", session.Name(), err))
			continue
		}
		for _, hit := range sessionHits {
			hit.ID = nextID
			nextID++
			hits = append(hits, hit)
		}
	}
	return hits
}

func (r *PacketPluginRunner) Warnings() []string {
	if r == nil || len(r.warnings) == 0 {
		return nil
	}
	out := make([]string, len(r.warnings))
	copy(out, r.warnings)
	return out
}

func (m *Manager) RunEnabledPacketPlugins(packets []model.Packet, startID int64) []model.ThreatHit {
	runner := m.NewPacketPluginRunner()
	if runner == nil {
		return nil
	}
	runner.ProcessBatch(packets)
	return runner.Close(startID)
}

func (m *Manager) runtimeCandidates() []runtimeCandidate {
	m.mu.RLock()
	candidates := make([]runtimeCandidate, 0, len(m.plugins))
	for id, plugin := range m.plugins {
		if !plugin.Enabled {
			continue
		}
		logicPath := strings.TrimSpace(m.logicFiles[id])
		if logicPath == "" {
			continue
		}
		candidates = append(candidates, runtimeCandidate{meta: plugin, logicPath: logicPath})
	}
	m.mu.RUnlock()

	sort.Slice(candidates, func(i, j int) bool {
		left := strings.ToLower(strings.TrimSpace(candidates[i].meta.Name))
		right := strings.ToLower(strings.TrimSpace(candidates[j].meta.Name))
		if left == right {
			return candidates[i].meta.ID < candidates[j].meta.ID
		}
		return left < right
	})
	return candidates
}

func newPacketPluginSession(meta model.Plugin, logicPath string) (packetPluginSession, error) {
	switch strings.ToLower(filepath.Ext(logicPath)) {
	case ".js", ".mjs", ".cjs":
		return newJSPacketSession(meta, logicPath)
	case ".py":
		return newPythonPacketSession(meta, logicPath)
	default:
		return nil, fmt.Errorf("unsupported plugin runtime: %s", logicPath)
	}
}

type jsPacketSession struct {
	name     string
	vm       *goja.Runtime
	ctx      *goja.Object
	onPacket goja.Callable
	onFinish goja.Callable
	hits     []model.ThreatHit
	timeout  time.Duration
	runErr   error
	warnings []string
	warned   map[string]struct{}
}

func newJSPacketSession(meta model.Plugin, logicPath string) (*jsPacketSession, error) {
	if !pluginHasCapability(meta, "packet.read") {
		return nil, fmt.Errorf("plugin %s is missing required capability packet.read", meta.ID)
	}

	source, err := os.ReadFile(logicPath)
	if err != nil {
		return nil, err
	}

	vm := goja.New()
	session := &jsPacketSession{
		name:     meta.ID,
		vm:       vm,
		ctx:      vm.NewObject(),
		hits:     make([]model.ThreatHit, 0, 8),
		timeout:  pluginRuntimeTimeout(),
		warnings: make([]string, 0, 4),
		warned:   map[string]struct{}{},
	}

	_ = session.ctx.Set("emitHit", func(call goja.FunctionCall) goja.Value {
		if !pluginHasCapability(meta, "threat.emit") {
			session.warnOnce("missing capability threat.emit; emitted hits are ignored")
			return goja.Undefined()
		}
		if len(call.Arguments) == 0 {
			return goja.Undefined()
		}
		hit, ok := pluginThreatHit(meta, call.Argument(0).Export())
		if ok {
			session.hits = append(session.hits, hit)
		}
		return goja.Undefined()
	})
	_ = session.ctx.Set("log", func(goja.FunctionCall) goja.Value {
		if !pluginHasCapability(meta, "logging") {
			session.warnOnce("missing capability logging; ctx.log calls are ignored")
		}
		return goja.Undefined()
	})

	cleaned := pluginExportRE.ReplaceAllString(string(source), "")
	if _, err := vm.RunString(cleaned); err != nil {
		return nil, err
	}

	onPacketValue := vm.Get("onPacket")
	onPacket, ok := goja.AssertFunction(onPacketValue)
	if !ok {
		return nil, fmt.Errorf("onPacket not found")
	}
	session.onPacket = onPacket

	if onFinishValue := vm.Get("onFinish"); onFinishValue != nil {
		if onFinish, ok := goja.AssertFunction(onFinishValue); ok {
			if pluginHasCapability(meta, "finish.hook") {
				session.onFinish = onFinish
			} else {
				session.warnOnce("missing capability finish.hook; onFinish handler is skipped")
			}
		}
	}

	return session, nil
}

func (s *jsPacketSession) ProcessBatch(packets []model.Packet) {
	if s.runErr != nil {
		return
	}
	err := s.runWithTimeout("packet batch", func() error {
		for _, packet := range packets {
			_, err := s.onPacket(goja.Undefined(), s.vm.ToValue(packetForPlugin(packet)), s.ctx)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		s.runErr = err
	}
}

func (s *jsPacketSession) Close() ([]model.ThreatHit, error) {
	if s.runErr != nil {
		return nil, s.runErr
	}
	if s.onFinish != nil {
		if err := s.runWithTimeout("onFinish", func() error {
			_, err := s.onFinish(goja.Undefined(), s.ctx)
			return err
		}); err != nil {
			return nil, err
		}
	}
	out := make([]model.ThreatHit, len(s.hits))
	copy(out, s.hits)
	return out, nil
}

func (s *jsPacketSession) Name() string {
	return s.name
}

func (s *jsPacketSession) Warnings() []string {
	if len(s.warnings) == 0 {
		return nil
	}
	out := make([]string, len(s.warnings))
	copy(out, s.warnings)
	return out
}

func (s *jsPacketSession) runWithTimeout(stage string, fn func() error) error {
	if s.timeout <= 0 {
		return fn()
	}

	timer := time.AfterFunc(s.timeout, func() {
		s.vm.Interrupt(fmt.Errorf("plugin %s exceeded timeout during %s", s.name, stage))
	})
	err := fn()
	_ = timer.Stop()
	s.vm.ClearInterrupt()
	if interrupted, ok := err.(*goja.InterruptedError); ok {
		if valueErr, ok := interrupted.Value().(error); ok {
			return valueErr
		}
		return fmt.Errorf("plugin %s interrupted during %s", s.name, stage)
	}
	return err
}

func (s *jsPacketSession) warnOnce(message string) {
	if _, exists := s.warned[message]; exists {
		return
	}
	s.warned[message] = struct{}{}
	s.warnings = append(s.warnings, fmt.Sprintf("%s: %s", s.name, message))
}

type pythonPacketSession struct {
	name      string
	cmd       *exec.Cmd
	stdin     io.WriteCloser
	encoder   *json.Encoder
	scanDone  chan error
	hitsMu    sync.Mutex
	hits      []model.ThreatHit
	writeErr  error
	writeErrM sync.Mutex
	cancel    context.CancelFunc
	timeout   time.Duration
	canEmit   bool
	warnings  []string
	warned    map[string]struct{}
}

func newPythonPacketSession(meta model.Plugin, logicPath string) (*pythonPacketSession, error) {
	if !pluginHasCapability(meta, "packet.read") {
		return nil, fmt.Errorf("plugin %s is missing required capability packet.read", meta.ID)
	}

	args, err := resolvePythonCommand()
	if err != nil {
		return nil, err
	}

	cmdCtx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(cmdCtx, args[0], append(args[1:], logicPath)...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	cmd.Stderr = io.Discard

	session := &pythonPacketSession{
		name:     meta.ID,
		cmd:      cmd,
		stdin:    stdin,
		encoder:  json.NewEncoder(stdin),
		scanDone: make(chan error, 1),
		hits:     make([]model.ThreatHit, 0, 8),
		cancel:   cancel,
		timeout:  pluginRuntimeTimeout(),
		canEmit:  pluginHasCapability(meta, "threat.emit"),
		warnings: make([]string, 0, 4),
		warned:   map[string]struct{}{},
	}
	if !session.canEmit {
		session.warnOnce("missing capability threat.emit; emitted hits are ignored")
	}

	if err := cmd.Start(); err != nil {
		cancel()
		return nil, err
	}

	go session.collectHits(meta, stdout)
	return session, nil
}

func (s *pythonPacketSession) collectHits(meta model.Plugin, stdout io.Reader) {
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var payload any
		if err := json.Unmarshal([]byte(line), &payload); err != nil {
			continue
		}

		switch typed := payload.(type) {
		case []any:
			for _, item := range typed {
				hit, ok := pluginThreatHit(meta, item)
				if ok {
					s.appendHit(hit)
				}
			}
		default:
			hit, ok := pluginThreatHit(meta, typed)
			if ok {
				s.appendHit(hit)
			}
		}
	}
	s.scanDone <- scanner.Err()
}

func (s *pythonPacketSession) appendHit(hit model.ThreatHit) {
	if !s.canEmit {
		return
	}
	s.hitsMu.Lock()
	s.hits = append(s.hits, hit)
	s.hitsMu.Unlock()
}

func (s *pythonPacketSession) ProcessBatch(packets []model.Packet) {
	if s == nil {
		return
	}
	for _, packet := range packets {
		if err := s.encoder.Encode(packetForPlugin(packet)); err != nil {
			s.writeErrM.Lock()
			if s.writeErr == nil {
				s.writeErr = err
			}
			s.writeErrM.Unlock()
			return
		}
	}
}

func (s *pythonPacketSession) Close() ([]model.ThreatHit, error) {
	if s.stdin != nil {
		_ = s.stdin.Close()
	}
	waitDone := make(chan error, 1)
	go func() {
		waitDone <- s.cmd.Wait()
	}()

	var waitErr error
	if s.timeout > 0 {
		select {
		case waitErr = <-waitDone:
		case <-time.After(s.timeout):
			if s.cancel != nil {
				s.cancel()
			}
			if s.cmd.Process != nil {
				_ = s.cmd.Process.Kill()
			}
			waitErr = <-waitDone
			return nil, fmt.Errorf("plugin %s exceeded timeout during shutdown", s.name)
		}
	} else {
		waitErr = <-waitDone
	}
	scanErr := <-s.scanDone

	s.writeErrM.Lock()
	writeErr := s.writeErr
	s.writeErrM.Unlock()

	if writeErr != nil {
		return nil, writeErr
	}
	if scanErr != nil {
		return nil, scanErr
	}
	if waitErr != nil {
		return nil, waitErr
	}

	s.hitsMu.Lock()
	out := make([]model.ThreatHit, len(s.hits))
	copy(out, s.hits)
	s.hitsMu.Unlock()
	return out, nil
}

func (s *pythonPacketSession) Name() string {
	return s.name
}

func (s *pythonPacketSession) Warnings() []string {
	if len(s.warnings) == 0 {
		return nil
	}
	out := make([]string, len(s.warnings))
	copy(out, s.warnings)
	return out
}

func (s *pythonPacketSession) warnOnce(message string) {
	if _, exists := s.warned[message]; exists {
		return
	}
	s.warned[message] = struct{}{}
	s.warnings = append(s.warnings, fmt.Sprintf("%s: %s", s.name, message))
}

func packetForPlugin(packet model.Packet) map[string]any {
	return map[string]any{
		"id":          packet.ID,
		"time":        packet.Timestamp,
		"src":         packet.SourceIP,
		"srcPort":     packet.SourcePort,
		"dst":         packet.DestIP,
		"dstPort":     packet.DestPort,
		"protocol":    packet.Protocol,
		"length":      packet.Length,
		"info":        packet.Info,
		"payload":     packet.Payload,
		"rawHex":      packet.RawHex,
		"streamId":    packet.StreamID,
		"ipHeaderLen": packet.IPHeaderLen,
		"l4HeaderLen": packet.L4HeaderLen,
	}
}

func pluginThreatHit(meta model.Plugin, exported any) (model.ThreatHit, bool) {
	node, ok := exported.(map[string]any)
	if !ok {
		return model.ThreatHit{}, false
	}

	packetID := int64FromAny(node["packetId"])
	if packetID == 0 {
		packetID = int64FromAny(node["packet_id"])
	}

	rule := strings.TrimSpace(stringFromAny(node["rule"]))
	if rule == "" {
		rule = meta.ID
	}

	level := strings.ToLower(strings.TrimSpace(stringFromAny(node["level"])))
	switch level {
	case "critical", "high", "medium", "low":
	default:
		level = "low"
	}

	category := strings.TrimSpace(stringFromAny(node["category"]))
	if category == "" {
		category = "Anomaly"
	}

	preview := strings.TrimSpace(stringFromAny(node["preview"]))
	match := strings.TrimSpace(stringFromAny(node["match"]))
	if match == "" {
		match = meta.ID
	}

	return model.ThreatHit{
		PacketID: packetID,
		Category: category,
		Rule:     rule,
		Level:    level,
		Preview:  preview,
		Match:    match,
	}, true
}

func resolvePythonCommand() ([]string, error) {
	candidates := [][]string{
		{"python3"},
		{"python"},
		{"py", "-3"},
	}
	if runtime.GOOS == "windows" {
		candidates = [][]string{
			{"py", "-3"},
			{"python"},
			{"python3"},
		}
	}

	for _, candidate := range candidates {
		if _, err := exec.LookPath(candidate[0]); err == nil {
			return candidate, nil
		}
	}
	return nil, fmt.Errorf("python executable not found")
}

func stringFromAny(value any) string {
	switch v := value.(type) {
	case string:
		return v
	default:
		return ""
	}
}

func int64FromAny(value any) int64 {
	switch v := value.(type) {
	case int:
		return int64(v)
	case int32:
		return int64(v)
	case int64:
		return v
	case float64:
		return int64(v)
	default:
		return 0
	}
}

func pluginRuntimeTimeout() time.Duration {
	raw := strings.TrimSpace(os.Getenv("GSHARK_PLUGIN_TIMEOUT_MS"))
	if raw == "" {
		return defaultPluginRuntimeTimeout
	}
	ms, err := strconv.Atoi(raw)
	if err != nil || ms <= 0 {
		return defaultPluginRuntimeTimeout
	}
	return time.Duration(ms) * time.Millisecond
}

func pluginHasCapability(meta model.Plugin, capability string) bool {
	target := strings.ToLower(strings.TrimSpace(capability))
	if target == "" {
		return false
	}
	capabilities := meta.Capabilities
	if len(capabilities) == 0 {
		capabilities = defaultPluginCapabilities
	}
	for _, item := range capabilities {
		if strings.EqualFold(strings.TrimSpace(item), target) {
			return true
		}
	}
	return false
}

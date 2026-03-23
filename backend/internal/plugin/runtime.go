package plugin

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/dop251/goja"
	"github.com/gshark/sentinel/backend/internal/model"
)

var pluginExportRE = regexp.MustCompile(`(?m)^\s*export\s+`)

type PacketPluginRunner struct {
	sessions []packetPluginSession
	warnings []string
}

type packetPluginSession interface {
	ProcessBatch([]model.Packet)
	Close() ([]model.ThreatHit, error)
	Name() string
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
}

func newJSPacketSession(meta model.Plugin, logicPath string) (*jsPacketSession, error) {
	source, err := os.ReadFile(logicPath)
	if err != nil {
		return nil, err
	}

	vm := goja.New()
	session := &jsPacketSession{
		name: meta.ID,
		vm:   vm,
		ctx:  vm.NewObject(),
		hits: make([]model.ThreatHit, 0, 8),
	}

	_ = session.ctx.Set("emitHit", func(call goja.FunctionCall) goja.Value {
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
			session.onFinish = onFinish
		}
	}

	return session, nil
}

func (s *jsPacketSession) ProcessBatch(packets []model.Packet) {
	for _, packet := range packets {
		_, err := s.onPacket(goja.Undefined(), s.vm.ToValue(packetForPlugin(packet)), s.ctx)
		if err != nil {
			continue
		}
	}
}

func (s *jsPacketSession) Close() ([]model.ThreatHit, error) {
	if s.onFinish != nil {
		_, _ = s.onFinish(goja.Undefined(), s.ctx)
	}
	out := make([]model.ThreatHit, len(s.hits))
	copy(out, s.hits)
	return out, nil
}

func (s *jsPacketSession) Name() string {
	return s.name
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
}

func newPythonPacketSession(meta model.Plugin, logicPath string) (*pythonPacketSession, error) {
	args, err := resolvePythonCommand()
	if err != nil {
		return nil, err
	}

	cmd := exec.Command(args[0], append(args[1:], logicPath)...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
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
	}

	if err := cmd.Start(); err != nil {
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
	waitErr := s.cmd.Wait()
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

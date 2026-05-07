package plugin

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestLoadFromDirInfersStandaloneLogicPlugin(t *testing.T) {
	dir := t.TempDir()
	logicPath := filepath.Join(dir, "flag_probe.js")
	source := `export function onPacket(packet, ctx) {
  if (String(packet.info || "").includes("flag{")) {
    ctx.emitHit({
      packetId: packet.id,
      category: "CTF",
      rule: "flag-probe",
      level: "high",
      preview: String(packet.info || ""),
      match: "flag{"
    });
  }
}`
	if err := os.WriteFile(logicPath, []byte(source), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	manager := NewManager()
	if err := manager.LoadFromDir(dir); err != nil {
		t.Fatalf("LoadFromDir() error = %v", err)
	}

	plugins := manager.List()
	if len(plugins) != 1 {
		t.Fatalf("expected 1 inferred plugin, got %d", len(plugins))
	}
	if plugins[0].ID != "flag_probe" {
		t.Fatalf("expected inferred plugin id flag_probe, got %q", plugins[0].ID)
	}
	if plugins[0].Entry != "flag_probe.js" || plugins[0].Runtime != "javascript" {
		t.Fatalf("expected js metadata, got %+v", plugins[0])
	}

	sourceView, err := manager.Source("flag_probe")
	if err != nil {
		t.Fatalf("Source() error = %v", err)
	}
	if sourceView.LogicPath == "" || sourceView.ConfigContent == "" {
		t.Fatalf("expected both logic and generated config content, got %+v", sourceView)
	}
}

func TestRunEnabledPacketPluginsExecutesJSLogic(t *testing.T) {
	dir := t.TempDir()
	logicPath := filepath.Join(dir, "flag_probe.js")
	source := `export function onPacket(packet, ctx) {
  if (String(packet.info || "").includes("flag{")) {
    ctx.emitHit({
      packetId: packet.id,
      category: "CTF",
      rule: "flag-probe",
      level: "high",
      preview: String(packet.info || ""),
      match: "flag{"
    });
  }
}`
	if err := os.WriteFile(logicPath, []byte(source), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	manager := NewManager()
	if err := manager.LoadFromDir(dir); err != nil {
		t.Fatalf("LoadFromDir() error = %v", err)
	}

	hits := manager.RunEnabledPacketPlugins(context.Background(), []model.Packet{
		{ID: 41, Protocol: "TCP", Info: "leaked flag{demo_token}"},
		{ID: 42, Protocol: "TCP", Info: "normal payload"},
	}, 100)
	if len(hits) != 1 {
		t.Fatalf("expected 1 plugin hit, got %d", len(hits))
	}
	if hits[0].ID != 100 || hits[0].PacketID != 41 || hits[0].Rule != "flag-probe" {
		t.Fatalf("unexpected hit: %+v", hits[0])
	}
}

func TestRunEnabledPacketPluginsExecutesPythonLogic(t *testing.T) {
	if _, err := resolvePythonCommand(); err != nil {
		t.Skip("python is not available in test environment")
	}

	dir := t.TempDir()
	logicPath := filepath.Join(dir, "flag_probe.py")
	source := `import json
import sys

for raw in sys.stdin:
    raw = raw.strip()
    if not raw:
        continue
    packet = json.loads(raw)
    text = str(packet.get("info", ""))
    if "flag{" in text:
        sys.stdout.write(json.dumps({
            "packetId": packet.get("id"),
            "category": "CTF",
            "rule": "py-flag-probe",
            "level": "high",
            "preview": text,
            "match": "flag{"
        }) + "\n")
        sys.stdout.flush()
`
	if err := os.WriteFile(logicPath, []byte(source), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	manager := NewManager()
	if err := manager.LoadFromDir(dir); err != nil {
		t.Fatalf("LoadFromDir() error = %v", err)
	}

	plugins := manager.List()
	if len(plugins) != 1 || plugins[0].Runtime != "python" {
		t.Fatalf("expected a python plugin, got %+v", plugins)
	}

	hits := manager.RunEnabledPacketPlugins(context.Background(), []model.Packet{
		{ID: 7, Protocol: "TCP", Info: "flag{python_runtime}"},
		{ID: 8, Protocol: "TCP", Info: "normal payload"},
	}, 200)
	if len(hits) != 1 {
		t.Fatalf("expected 1 python plugin hit, got %d", len(hits))
	}
	if hits[0].ID != 200 || hits[0].PacketID != 7 || hits[0].Rule != "py-flag-probe" {
		t.Fatalf("unexpected python hit: %+v", hits[0])
	}
}

func TestUpdateSourcePersistsEntryAndLogic(t *testing.T) {
	dir := t.TempDir()
	manager := NewManager()
	if err := manager.LoadFromDir(dir); err != nil {
		t.Fatalf("LoadFromDir() error = %v", err)
	}

	if _, err := manager.Add(RulePlugin{
		ID:      "editor-demo",
		Name:    "Editor Demo",
		Version: "1.0.0",
		Tag:     "custom",
		Author:  "tester",
		Enabled: true,
		Entry:   "editor-demo.py",
	}); err != nil {
		t.Fatalf("Add() error = %v", err)
	}

	updated, err := manager.UpdateSource(model.PluginSource{
		ID:            "editor-demo",
		ConfigContent: `{"id":"editor-demo","name":"Editor Demo","version":"1.0.1","tag":"custom","author":"tester","enabled":true,"entry":"editor-demo.py"}`,
		LogicContent:  "print('hello from python')\n",
		Entry:         "editor-demo.py",
	})
	if err != nil {
		t.Fatalf("UpdateSource() error = %v", err)
	}
	if updated.Entry != "editor-demo.py" || !strings.HasSuffix(updated.LogicPath, "editor-demo.py") {
		t.Fatalf("unexpected updated source: %+v", updated)
	}

	source, err := manager.Source("editor-demo")
	if err != nil {
		t.Fatalf("Source() error = %v", err)
	}
	if !strings.Contains(source.ConfigContent, `"version": "1.0.1"`) {
		t.Fatalf("expected updated config version, got %q", source.ConfigContent)
	}
	if source.LogicContent != "print('hello from python')\n" {
		t.Fatalf("expected updated logic content, got %q", source.LogicContent)
	}
}

func TestUpdateSourcePersistsCapabilities(t *testing.T) {
	dir := t.TempDir()
	manager := NewManager()
	if err := manager.LoadFromDir(dir); err != nil {
		t.Fatalf("LoadFromDir() error = %v", err)
	}

	updated, err := manager.UpdateSource(model.PluginSource{
		ID:            "capability-demo",
		ConfigContent: `{"id":"capability-demo","name":"Capability Demo","version":"1.0.1","tag":"custom","author":"tester","enabled":true,"entry":"capability-demo.js","capabilities":["logging","packet.read","packet.read","unknown"]}`,
		LogicContent:  "export function onPacket() {}\n",
		Entry:         "capability-demo.js",
	})
	if err != nil {
		t.Fatalf("UpdateSource() error = %v", err)
	}
	if updated.Entry != "capability-demo.js" {
		t.Fatalf("unexpected updated source: %+v", updated)
	}

	plugins := manager.List()
	if len(plugins) != 1 {
		t.Fatalf("expected 1 plugin, got %d", len(plugins))
	}
	if got := strings.Join(plugins[0].Capabilities, ","); got != "logging,packet.read" {
		t.Fatalf("unexpected capabilities %q", got)
	}

	source, err := manager.Source("capability-demo")
	if err != nil {
		t.Fatalf("Source() error = %v", err)
	}
	if !strings.Contains(source.ConfigContent, `"capabilities": [`) {
		t.Fatalf("expected capabilities to be persisted, got %q", source.ConfigContent)
	}
}

func TestAddRejectsEscapingEntry(t *testing.T) {
	dir := t.TempDir()
	manager := NewManager()
	if err := manager.LoadFromDir(dir); err != nil {
		t.Fatalf("LoadFromDir() error = %v", err)
	}

	_, err := manager.Add(RulePlugin{
		ID:      "unsafe-demo",
		Name:    "Unsafe Demo",
		Version: "1.0.0",
		Tag:     "custom",
		Author:  "tester",
		Enabled: true,
		Entry:   "../escape.py",
	})
	if err == nil {
		t.Fatal("expected Add() to reject escaping entry")
	}
}

func TestUpdateSourceRejectsEscapingPaths(t *testing.T) {
	dir := t.TempDir()
	manager := NewManager()
	if err := manager.LoadFromDir(dir); err != nil {
		t.Fatalf("LoadFromDir() error = %v", err)
	}

	outside := filepath.Join(filepath.Dir(dir), "escape.py")
	_, err := manager.UpdateSource(model.PluginSource{
		ID:            "unsafe-editor",
		ConfigContent: `{"id":"unsafe-editor","name":"Unsafe","version":"1.0.0","tag":"custom","author":"tester","enabled":true,"entry":"unsafe-editor.py"}`,
		LogicPath:     outside,
		LogicContent:  "print('escape')\n",
		Entry:         "unsafe-editor.py",
	})
	if err == nil {
		t.Fatal("expected UpdateSource() to reject escaping logic path")
	}
	if _, statErr := os.Stat(outside); !os.IsNotExist(statErr) {
		t.Fatalf("expected outside file to stay untouched, stat error = %v", statErr)
	}
}

func TestRunEnabledPacketPluginsTimesOutHungJS(t *testing.T) {
	t.Setenv("GSHARK_PLUGIN_TIMEOUT_MS", "50")

	dir := t.TempDir()
	logicPath := filepath.Join(dir, "hung.js")
	source := `export function onPacket() {
  while (true) {}
}`
	if err := os.WriteFile(logicPath, []byte(source), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	manager := NewManager()
	if err := manager.LoadFromDir(dir); err != nil {
		t.Fatalf("LoadFromDir() error = %v", err)
	}

	runner := manager.NewPacketPluginRunner(context.Background())
	if runner == nil {
		t.Fatal("expected runner to be created")
	}
	runner.ProcessBatch([]model.Packet{{ID: 1, Info: "test"}})
	hits := runner.Close(1)
	if len(hits) != 0 {
		t.Fatalf("expected no hits from timed out plugin, got %+v", hits)
	}
	if warnings := strings.Join(runner.Warnings(), "\n"); !strings.Contains(warnings, "exceeded timeout") {
		t.Fatalf("expected timeout warning, got %q", warnings)
	}
}

func TestRunEnabledPacketPluginsTimesOutHungPython(t *testing.T) {
	if _, err := resolvePythonCommand(); err != nil {
		t.Skip("python is not available in test environment")
	}
	t.Setenv("GSHARK_PLUGIN_TIMEOUT_MS", "50")

	dir := t.TempDir()
	logicPath := filepath.Join(dir, "hung.py")
	source := `import sys
import time

for _ in sys.stdin:
    pass

time.sleep(1)
`
	if err := os.WriteFile(logicPath, []byte(source), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	manager := NewManager()
	if err := manager.LoadFromDir(dir); err != nil {
		t.Fatalf("LoadFromDir() error = %v", err)
	}

	runner := manager.NewPacketPluginRunner(context.Background())
	if runner == nil {
		t.Fatal("expected runner to be created")
	}
	runner.ProcessBatch([]model.Packet{{ID: 1, Info: "test"}})
	hits := runner.Close(1)
	if len(hits) != 0 {
		t.Fatalf("expected no hits from timed out plugin, got %+v", hits)
	}
	if warnings := strings.Join(runner.Warnings(), "\n"); !strings.Contains(warnings, "exceeded timeout") {
		t.Fatalf("expected timeout warning, got %q", warnings)
	}
}

func TestRunEnabledPacketPluginsEnforcesThreatEmitCapability(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "limited.json")
	logicPath := filepath.Join(dir, "limited.js")

	if err := os.WriteFile(configPath, []byte(`{
  "id": "limited",
  "name": "Limited",
  "version": "1.0.0",
  "tag": "custom",
  "author": "tester",
  "enabled": true,
  "entry": "limited.js",
  "capabilities": ["packet.read"]
}
`), 0o644); err != nil {
		t.Fatalf("WriteFile(config) error = %v", err)
	}
	if err := os.WriteFile(logicPath, []byte(`export function onPacket(packet, ctx) {
  ctx.emitHit({
    packetId: packet.id,
    category: "CTF",
    rule: "limited",
    level: "high",
    preview: "blocked",
    match: "blocked"
  });
}`), 0o644); err != nil {
		t.Fatalf("WriteFile(logic) error = %v", err)
	}

	manager := NewManager()
	if err := manager.LoadFromDir(dir); err != nil {
		t.Fatalf("LoadFromDir() error = %v", err)
	}

	runner := manager.NewPacketPluginRunner(context.Background())
	if runner == nil {
		t.Fatal("expected runner to be created")
	}
	runner.ProcessBatch([]model.Packet{{ID: 1, Info: "flag{test}"}})
	hits := runner.Close(1)
	if len(hits) != 0 {
		t.Fatalf("expected capability-gated plugin to emit no hits, got %+v", hits)
	}
	if warnings := strings.Join(runner.Warnings(), "\n"); !strings.Contains(warnings, "threat.emit") {
		t.Fatalf("expected capability warning, got %q", warnings)
	}
}

func TestRunEnabledPacketPluginsRequiresPacketReadCapability(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "broken.json")
	logicPath := filepath.Join(dir, "broken.js")

	if err := os.WriteFile(configPath, []byte(`{
  "id": "broken",
  "name": "Broken",
  "version": "1.0.0",
  "tag": "custom",
  "author": "tester",
  "enabled": true,
  "entry": "broken.js",
  "capabilities": ["threat.emit"]
}
`), 0o644); err != nil {
		t.Fatalf("WriteFile(config) error = %v", err)
	}
	if err := os.WriteFile(logicPath, []byte(`export function onPacket() {}`), 0o644); err != nil {
		t.Fatalf("WriteFile(logic) error = %v", err)
	}

	manager := NewManager()
	if err := manager.LoadFromDir(dir); err != nil {
		t.Fatalf("LoadFromDir() error = %v", err)
	}

	runner := manager.NewPacketPluginRunner(context.Background())
	if runner == nil {
		t.Fatal("expected runner to be created with warning")
	}
	if warnings := strings.Join(runner.Warnings(), "\n"); !strings.Contains(warnings, "packet.read") {
		t.Fatalf("expected missing packet.read warning, got %q", warnings)
	}
}

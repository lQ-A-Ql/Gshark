package plugin

import (
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

	hits := manager.RunEnabledPacketPlugins([]model.Packet{
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

	hits := manager.RunEnabledPacketPlugins([]model.Packet{
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

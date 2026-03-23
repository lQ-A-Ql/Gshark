package plugin

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/gshark/sentinel/backend/internal/model"
)

type RulePlugin struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Tag     string `json:"tag"`
	Author  string `json:"author"`
	Enabled bool   `json:"enabled"`
	Entry   string `json:"entry,omitempty"`
}

type Manager struct {
	mu          sync.RWMutex
	plugins     map[string]model.Plugin
	pluginFiles map[string]string
	logicFiles  map[string]string
	entries     map[string]string
	baseDir     string
}

func NewManager() *Manager {
	return &Manager{
		plugins:     map[string]model.Plugin{},
		pluginFiles: map[string]string{},
		logicFiles:  map[string]string{},
		entries:     map[string]string{},
	}
}

func (m *Manager) LoadFromDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read plugins dir: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.baseDir = dir
	m.plugins = map[string]model.Plugin{}
	m.pluginFiles = map[string]string{}
	m.logicFiles = map[string]string{}
	m.entries = map[string]string{}

	configs := map[string]RulePlugin{}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			continue
		}

		var rule RulePlugin
		if unmarshalErr := json.Unmarshal(raw, &rule); unmarshalErr != nil {
			continue
		}
		rule.ID = strings.TrimSpace(rule.ID)
		if rule.ID == "" {
			rule.ID = strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name()))
		}
		if rule.ID == "" {
			continue
		}
		configs[rule.ID] = normalizeRulePlugin(rule)
		m.pluginFiles[rule.ID] = path
	}

	for _, entry := range entries {
		if entry.IsDir() || !isLogicFile(entry.Name()) {
			continue
		}

		id := strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name()))
		logicPath := filepath.Join(dir, entry.Name())
		if id == "" {
			continue
		}

		rule, ok := configs[id]
		if !ok {
			rule = normalizeRulePlugin(RulePlugin{
				ID:      id,
				Name:    humanizePluginName(id),
				Version: "0.1.0",
				Tag:     "custom",
				Author:  "User",
				Enabled: true,
				Entry:   entry.Name(),
			})
		}
		if strings.TrimSpace(rule.Entry) == "" {
			rule.Entry = entry.Name()
		}

		m.plugins[id] = model.Plugin{
			ID:      rule.ID,
			Name:    rule.Name,
			Version: rule.Version,
			Tag:     rule.Tag,
			Author:  rule.Author,
			Enabled: rule.Enabled,
			Entry:   rule.Entry,
			Runtime: pluginRuntimeFromPaths(rule.Entry, logicPath),
		}
		m.logicFiles[id] = logicPath
		m.entries[id] = rule.Entry
	}

	for id, rule := range configs {
		if _, ok := m.plugins[id]; ok {
			continue
		}
		m.plugins[id] = model.Plugin{
			ID:      rule.ID,
			Name:    rule.Name,
			Version: rule.Version,
			Tag:     rule.Tag,
			Author:  rule.Author,
			Enabled: rule.Enabled,
			Entry:   rule.Entry,
			Runtime: pluginRuntimeFromPaths(rule.Entry, m.logicFiles[id]),
		}
		m.entries[id] = rule.Entry
	}

	return nil
}

func (m *Manager) Add(rule RulePlugin) (model.Plugin, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	id := strings.TrimSpace(rule.ID)
	if id == "" {
		return model.Plugin{}, fmt.Errorf("plugin id is required")
	}
	if _, exists := m.plugins[id]; exists {
		return model.Plugin{}, fmt.Errorf("plugin %s already exists", id)
	}
	if m.baseDir == "" {
		return model.Plugin{}, fmt.Errorf("plugin directory not initialized")
	}

	rule = normalizeRulePlugin(rule)
	if strings.TrimSpace(rule.ID) == "" {
		rule.ID = id
	}
	if strings.TrimSpace(rule.Entry) == "" {
		rule.Entry = id + ".js"
	}

	plugin := model.Plugin{
		ID:      id,
		Name:    rule.Name,
		Version: rule.Version,
		Tag:     rule.Tag,
		Author:  rule.Author,
		Enabled: rule.Enabled,
		Entry:   rule.Entry,
		Runtime: pluginRuntimeFromPaths(rule.Entry, rule.Entry),
	}

	filePath := filepath.Join(m.baseDir, id+".json")
	if err := writePluginConfig(filePath, plugin, rule.Entry); err != nil {
		return model.Plugin{}, err
	}

	logicPath := filepath.Join(m.baseDir, rule.Entry)
	if !filepath.IsAbs(rule.Entry) {
		logicPath = filepath.Join(filepath.Dir(filePath), rule.Entry)
	}
	if _, err := os.Stat(logicPath); os.IsNotExist(err) {
		tpl := defaultLogicTemplateForEntry(id, rule.Entry)
		if writeErr := os.WriteFile(logicPath, []byte(tpl), 0o644); writeErr != nil {
			return model.Plugin{}, fmt.Errorf("write plugin logic file: %w", writeErr)
		}
	}
	plugin.Runtime = pluginRuntimeFromPaths(rule.Entry, logicPath)

	m.plugins[id] = plugin
	m.pluginFiles[id] = filePath
	m.logicFiles[id] = logicPath
	m.entries[id] = rule.Entry
	return plugin, nil
}

func (m *Manager) Delete(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("plugin id is required")
	}
	if _, exists := m.plugins[id]; !exists {
		return fmt.Errorf("plugin %s not found", id)
	}

	if path := strings.TrimSpace(m.pluginFiles[id]); path != "" {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("delete plugin file: %w", err)
		}
	}
	if path := strings.TrimSpace(m.logicFiles[id]); path != "" {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("delete plugin logic file: %w", err)
		}
	}

	delete(m.plugins, id)
	delete(m.pluginFiles, id)
	delete(m.logicFiles, id)
	delete(m.entries, id)
	return nil
}

func (m *Manager) Source(id string) (model.PluginSource, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	id = strings.TrimSpace(id)
	if id == "" {
		return model.PluginSource{}, fmt.Errorf("plugin id is required")
	}

	return m.sourceLocked(id)
}

func (m *Manager) UpdateSource(source model.PluginSource) (model.PluginSource, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	id := strings.TrimSpace(source.ID)
	if id == "" {
		return model.PluginSource{}, fmt.Errorf("plugin id is required")
	}
	if m.baseDir == "" {
		return model.PluginSource{}, fmt.Errorf("plugin directory not initialized")
	}

	current, exists := m.plugins[id]
	if !exists {
		current = model.Plugin{
			ID:      id,
			Name:    humanizePluginName(id),
			Version: "0.1.0",
			Tag:     "custom",
			Author:  "User",
			Enabled: true,
		}
	}

	entry := strings.TrimSpace(source.Entry)
	configPath := strings.TrimSpace(source.ConfigPath)
	if configPath == "" {
		configPath = strings.TrimSpace(m.pluginFiles[id])
	}
	if configPath == "" {
		configPath = filepath.Join(m.baseDir, id+".json")
	}

	rule := RulePlugin{
		ID:      id,
		Name:    current.Name,
		Version: current.Version,
		Tag:     current.Tag,
		Author:  current.Author,
		Enabled: current.Enabled,
		Entry:   current.Entry,
	}
	if content := strings.TrimSpace(source.ConfigContent); content != "" {
		if err := json.Unmarshal([]byte(content), &rule); err != nil {
			return model.PluginSource{}, fmt.Errorf("invalid plugin config json: %w", err)
		}
	}
	if entry != "" {
		rule.Entry = entry
	}
	rule = normalizeRulePlugin(rule)
	if strings.TrimSpace(rule.ID) == "" {
		rule.ID = id
	}
	if strings.TrimSpace(rule.Entry) == "" {
		rule.Entry = id + ".js"
	}

	logicPath := strings.TrimSpace(source.LogicPath)
	if logicPath == "" {
		logicPath = strings.TrimSpace(m.logicFiles[id])
	}
	if logicPath == "" {
		logicPath = filepath.Join(filepath.Dir(configPath), rule.Entry)
	} else if !filepath.IsAbs(logicPath) {
		logicPath = filepath.Join(filepath.Dir(configPath), logicPath)
	}

	plugin := model.Plugin{
		ID:      rule.ID,
		Name:    rule.Name,
		Version: rule.Version,
		Tag:     rule.Tag,
		Author:  rule.Author,
		Enabled: rule.Enabled,
		Entry:   rule.Entry,
		Runtime: pluginRuntimeFromPaths(rule.Entry, logicPath),
	}

	if err := writePluginConfig(configPath, plugin, rule.Entry); err != nil {
		return model.PluginSource{}, err
	}
	if writeErr := os.WriteFile(logicPath, []byte(source.LogicContent), 0o644); writeErr != nil {
		return model.PluginSource{}, fmt.Errorf("write plugin logic file: %w", writeErr)
	}

	m.plugins[id] = plugin
	m.pluginFiles[id] = configPath
	m.logicFiles[id] = logicPath
	m.entries[id] = rule.Entry

	return m.sourceLocked(id)
}

func (m *Manager) sourceLocked(id string) (model.PluginSource, error) {

	plugin, ok := m.plugins[id]
	if !ok {
		return model.PluginSource{}, fmt.Errorf("plugin %s source not found", id)
	}

	configPath := strings.TrimSpace(m.pluginFiles[id])
	entry := strings.TrimSpace(m.entries[id])
	logicPath := strings.TrimSpace(m.logicFiles[id])

	configContent := ""
	if configPath != "" {
		raw, err := os.ReadFile(configPath)
		if err != nil {
			return model.PluginSource{}, fmt.Errorf("read plugin source: %w", err)
		}
		configContent = string(raw)
	} else {
		raw, _ := json.MarshalIndent(map[string]any{
			"id":      plugin.ID,
			"name":    plugin.Name,
			"version": plugin.Version,
			"tag":     plugin.Tag,
			"author":  plugin.Author,
			"enabled": plugin.Enabled,
			"entry":   entry,
			"runtime": pluginRuntimeFromPaths(entry, logicPath),
		}, "", "  ")
		configContent = string(append(raw, '\n'))
	}

	logicContent := ""
	if logicPath != "" {
		raw, err := os.ReadFile(logicPath)
		if err == nil {
			logicContent = string(raw)
		}
	}

	return model.PluginSource{
		ID:            id,
		ConfigPath:    configPath,
		ConfigContent: configContent,
		LogicPath:     logicPath,
		LogicContent:  logicContent,
		Entry:         entry,
	}, nil
}

func (m *Manager) LogicPath(id string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return strings.TrimSpace(m.logicFiles[id])
}

func (m *Manager) List() []model.Plugin {
	m.mu.RLock()
	defer m.mu.RUnlock()

	items := make([]model.Plugin, 0, len(m.plugins))
	for _, p := range m.plugins {
		items = append(items, p)
	}
	sort.Slice(items, func(i, j int) bool {
		return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name)
	})
	return items
}

func (m *Manager) Toggle(id string) (model.Plugin, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	p, ok := m.plugins[id]
	if !ok {
		return model.Plugin{}, fmt.Errorf("plugin %s not found", id)
	}
	p.Enabled = !p.Enabled
	if err := m.persistLocked(id, p, m.entries[id]); err != nil {
		return model.Plugin{}, err
	}
	m.plugins[id] = p
	return p, nil
}

func (m *Manager) SetEnabled(ids []string, enabled bool) ([]model.Plugin, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	selected := map[string]struct{}{}
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id != "" {
			selected[id] = struct{}{}
		}
	}

	updated := make([]model.Plugin, 0, len(m.plugins))
	for id, p := range m.plugins {
		if len(selected) > 0 {
			if _, ok := selected[id]; !ok {
				continue
			}
		}
		if p.Enabled != enabled {
			p.Enabled = enabled
			if err := m.persistLocked(id, p, m.entries[id]); err != nil {
				return nil, err
			}
			m.plugins[id] = p
		}
		updated = append(updated, p)
	}

	sort.Slice(updated, func(i, j int) bool {
		return strings.ToLower(updated[i].Name) < strings.ToLower(updated[j].Name)
	})
	return updated, nil
}

func (m *Manager) persistLocked(id string, plugin model.Plugin, entry string) error {
	path := strings.TrimSpace(m.pluginFiles[id])
	if path == "" {
		if m.baseDir == "" {
			return nil
		}
		path = filepath.Join(m.baseDir, id+".json")
		m.pluginFiles[id] = path
	}
	if strings.TrimSpace(entry) == "" {
		entry = id + ".js"
	}
	plugin.Entry = entry
	plugin.Runtime = pluginRuntimeFromPaths(entry, m.logicFiles[id])
	if err := writePluginConfig(path, plugin, entry); err != nil {
		return err
	}
	return nil
}

func writePluginConfig(path string, plugin model.Plugin, entry string) error {
	node := map[string]any{
		"id":      plugin.ID,
		"name":    plugin.Name,
		"version": plugin.Version,
		"tag":     plugin.Tag,
		"author":  plugin.Author,
		"enabled": plugin.Enabled,
		"entry":   entry,
		"runtime": pluginRuntimeFromPaths(entry, ""),
	}
	out, err := json.MarshalIndent(node, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal plugin file: %w", err)
	}
	out = append(out, '\n')
	if err := os.WriteFile(path, out, 0o644); err != nil {
		return fmt.Errorf("write plugin file: %w", err)
	}
	return nil
}

func normalizeRulePlugin(rule RulePlugin) RulePlugin {
	rule.ID = strings.TrimSpace(rule.ID)
	rule.Name = strings.TrimSpace(rule.Name)
	rule.Version = strings.TrimSpace(rule.Version)
	rule.Tag = strings.TrimSpace(rule.Tag)
	rule.Author = strings.TrimSpace(rule.Author)
	rule.Entry = strings.TrimSpace(rule.Entry)

	if rule.Name == "" {
		rule.Name = humanizePluginName(rule.ID)
	}
	if rule.Version == "" {
		rule.Version = "0.1.0"
	}
	if rule.Tag == "" {
		rule.Tag = "custom"
	}
	if rule.Author == "" {
		rule.Author = "User"
	}
	return rule
}

func humanizePluginName(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return "Unnamed Plugin"
	}
	id = strings.ReplaceAll(id, "-", " ")
	id = strings.ReplaceAll(id, "_", " ")
	fields := strings.Fields(id)
	if len(fields) == 0 {
		return "Unnamed Plugin"
	}
	for i, field := range fields {
		fields[i] = strings.ToUpper(field[:1]) + field[1:]
	}
	return strings.Join(fields, " ")
}

func isLogicFile(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".js", ".mjs", ".cjs", ".ts", ".py", ".lua", ".go":
		return true
	default:
		return false
	}
}

func defaultLogicTemplate(pluginID string) string {
	return defaultLogicTemplateForEntry(pluginID, pluginID+".js")
}

func defaultLogicTemplateForEntry(pluginID, entry string) string {
	switch strings.ToLower(filepath.Ext(entry)) {
	case ".py":
		return fmt.Sprintf(`#!/usr/bin/env python3
# Plugin contract: docs/plugin-interface.md
import json
import sys


def emit_hit(packet_id: int, preview: str, match: str) -> None:
    sys.stdout.write(json.dumps({
        "category": "CTF",
        "rule": "%s-flag-detect",
        "level": "high",
        "packetId": packet_id,
        "preview": preview[:120],
        "match": match,
    }, ensure_ascii=False) + "\n")
    sys.stdout.flush()


for raw in sys.stdin:
    raw = raw.strip()
    if not raw:
        continue
    packet = json.loads(raw)
    info = str(packet.get("info", ""))
    payload = str(packet.get("payload", ""))
    text = info + "\n" + payload
    if "flag{" in text or "ctf{" in text:
        emit_hit(int(packet.get("id", 0) or 0), text, "flag")
`, pluginID)
	default:
		return fmt.Sprintf(`// %s logic template
// Plugin contract: docs/plugin-interface.md
// Called by the plugin runtime during threat hunting.

export function onPacket(packet, ctx) {
  const info = String(packet.info || "");
  if (info.includes("flag{") || info.includes("ctf{")) {
    ctx.emitHit({
      category: "CTF",
      rule: "%s-flag-detect",
      level: "high",
      packetId: packet.id,
      preview: info.slice(0, 120),
      match: "flag",
    });
  }
}

export function onFinish(ctx) {
  ctx.log("%s finished");
}
`, pluginID, pluginID, pluginID)
	}
}

func pluginRuntimeFromPaths(entry, logicPath string) string {
	candidate := strings.TrimSpace(logicPath)
	if candidate == "" {
		candidate = strings.TrimSpace(entry)
	}
	switch strings.ToLower(filepath.Ext(candidate)) {
	case ".py":
		return "python"
	case ".js", ".mjs", ".cjs":
		return "javascript"
	case ".ts":
		return "typescript"
	case ".lua":
		return "lua"
	case ".go":
		return "go"
	default:
		return ""
	}
}

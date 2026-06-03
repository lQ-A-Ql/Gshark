package miscpkg

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

func cloneManifest(in model.MiscModuleManifest) model.MiscModuleManifest {
	out := in
	out.Tags = append([]string(nil), in.Tags...)
	if in.FormSchema != nil {
		schema := *in.FormSchema
		schema.Fields = append([]model.MiscModuleFormField(nil), in.FormSchema.Fields...)
		for idx := range schema.Fields {
			schema.Fields[idx].Options = append([]model.MiscModuleFieldOption(nil), schema.Fields[idx].Options...)
		}
		out.FormSchema = &schema
	}
	if in.InterfaceSchema != nil {
		schema := *in.InterfaceSchema
		out.InterfaceSchema = &schema
	}
	return out
}

func runtimeFromPath(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".py":
		return "python"
	case ".js", ".mjs", ".cjs":
		return "javascript"
	default:
		return "unknown"
	}
}

func joinPythonPath(paths ...string) string {
	items := make([]string, 0, len(paths))
	for _, item := range paths {
		item = strings.TrimSpace(item)
		if item != "" {
			items = append(items, item)
		}
	}
	return strings.Join(items, string(os.PathListSeparator))
}

func resolveManagedPath(baseDir, requested string) (string, error) {
	baseDir, err := filepath.Abs(strings.TrimSpace(baseDir))
	if err != nil {
		return "", fmt.Errorf("resolve base dir: %w", err)
	}
	target, err := filepath.Abs(filepath.Join(baseDir, filepath.FromSlash(strings.TrimSpace(requested))))
	if err != nil {
		return "", fmt.Errorf("resolve module path: %w", err)
	}
	rel, err := filepath.Rel(baseDir, target)
	if err != nil {
		return "", fmt.Errorf("resolve relative path: %w", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes managed misc module dir", requested)
	}
	return target, nil
}

func validateModuleID(id string) error {
	if strings.TrimSpace(id) == "" {
		return fmt.Errorf("misc module id is required")
	}
	if !moduleIDPattern.MatchString(id) {
		return fmt.Errorf("invalid misc module id %q", id)
	}
	return nil
}

func normalizeValues(values map[string]string) map[string]string {
	if len(values) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[strings.TrimSpace(key)] = value
	}
	return out
}

func asString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	default:
		return ""
	}
}

func defaultIfEmpty(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

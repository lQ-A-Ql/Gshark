package transport

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestHandleTsharkConfigRejectsDangerousPath(t *testing.T) {
	runtime := &pathValidationToolRuntimeService{}
	server := &Server{toolRuntime: runtime}

	rec := httptest.NewRecorder()
	server.handleTsharkConfig(rec, httptest.NewRequest(http.MethodPost, "/api/tools/tshark", strings.NewReader(`{"path":"../evil/tshark"}`)))
	requireStatus(t, rec, http.StatusBadRequest)
	if runtime.setTSharkPathCalled {
		t.Fatal("SetTSharkPath should not be called for invalid path")
	}
}

func TestHandleToolRuntimeConfigRejectsDangerousPaths(t *testing.T) {
	runtime := &pathValidationToolRuntimeService{}
	server := &Server{toolRuntime: runtime}

	rec := httptest.NewRecorder()
	body := `{
		"tshark_path":"C:\\tmp\\evil.bat",
		"ffmpeg_path":"C:\\tmp\\ffmpeg.exe",
		"python_path":"C:\\tmp\\python.exe",
		"yara_bin":"C:\\tmp\\yara.exe"
	}`
	server.handleToolRuntimeConfig(rec, httptest.NewRequest(http.MethodPost, "/api/tools/runtime-config", strings.NewReader(body)))
	requireStatus(t, rec, http.StatusBadRequest)
	if runtime.setToolRuntimeConfigCalled {
		t.Fatal("SetToolRuntimeConfig should not be called for invalid paths")
	}
}

func TestHandleToolRuntimeConfigAcceptsEmptyPaths(t *testing.T) {
	runtime := &pathValidationToolRuntimeService{}
	server := &Server{toolRuntime: runtime}

	rec := httptest.NewRecorder()
	body := `{
		"tshark_path":"",
		"ffmpeg_path":"",
		"python_path":"",
		"vosk_model_path":"",
		"yara_enabled":true,
		"yara_bin":"",
		"yara_rules":"",
		"yara_timeout_ms":25000
	}`
	server.handleToolRuntimeConfig(rec, httptest.NewRequest(http.MethodPost, "/api/tools/runtime-config", strings.NewReader(body)))
	requireStatus(t, rec, http.StatusOK)
	if !runtime.setToolRuntimeConfigCalled {
		t.Fatal("SetToolRuntimeConfig should be called for empty paths")
	}
}

func TestHandleTsharkConfigAcceptsOutsideTrustedDir(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "tshark.exe")
	if err := os.WriteFile(bin, []byte("fake"), 0o644); err != nil {
		t.Fatalf("write fake binary: %v", err)
	}
	binJSON := bin

	runtime := &pathValidationToolRuntimeService{}
	server := &Server{toolRuntime: runtime}

	rec := httptest.NewRecorder()
	body := fmt.Sprintf(`{"path":%q}`, binJSON)
	server.handleTsharkConfig(rec, httptest.NewRequest(http.MethodPost, "/api/tools/tshark", strings.NewReader(body)))
	requireStatus(t, rec, http.StatusOK)
	if !runtime.setTSharkPathCalled {
		t.Fatal("SetTSharkPath should be called for absolute path outside default dirs")
	}
	if runtime.lastSetTSharkPath != bin {
		t.Fatalf("unexpected path passed to SetTSharkPath: %q", runtime.lastSetTSharkPath)
	}
}

func TestHandleAllowTSharkDir(t *testing.T) {
	runtime := &pathValidationToolRuntimeService{}
	server := &Server{toolRuntime: runtime}

	rec := httptest.NewRecorder()
	server.handleAllowTSharkDir(rec, httptest.NewRequest(http.MethodPost, "/api/tools/tshark/allow-dir", strings.NewReader(`{"dir":"C:\\Tools"}`)))
	requireStatus(t, rec, http.StatusOK)
	if !runtime.allowTSharkDirCalled {
		t.Fatal("AllowTSharkDirWithContext should be called")
	}
	if runtime.lastAllowTSharkDir != `C:\Tools` {
		t.Fatalf("unexpected dir passed to AllowTSharkDirWithContext: %q", runtime.lastAllowTSharkDir)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"available"`) {
		t.Fatalf("response should contain TSharkToolStatus, got %s", body)
	}
}

func TestHandleAllowTSharkDirRejectsEmptyDir(t *testing.T) {
	runtime := &pathValidationToolRuntimeService{}
	server := &Server{toolRuntime: runtime}

	rec := httptest.NewRecorder()
	server.handleAllowTSharkDir(rec, httptest.NewRequest(http.MethodPost, "/api/tools/tshark/allow-dir", strings.NewReader(`{"dir":""}`)))
	requireStatus(t, rec, http.StatusOK)
	if !runtime.allowTSharkDirCalled {
		t.Fatal("AllowTSharkDirWithContext should be called even for empty dir")
	}
}

func TestHandleListTSharkAllowedDirs(t *testing.T) {
	runtime := &pathValidationToolRuntimeService{}
	server := &Server{toolRuntime: runtime}

	rec := httptest.NewRecorder()
	server.handleListTSharkAllowedDirs(rec, httptest.NewRequest(http.MethodGet, "/api/tools/tshark/allowed-dirs", nil))
	requireStatus(t, rec, http.StatusOK)
	body := rec.Body.String()
	if !strings.Contains(body, `"dirs"`) {
		t.Fatalf("response should contain dirs list, got %s", body)
	}
}

func TestHandleRemoveTSharkAllowedDir(t *testing.T) {
	runtime := &pathValidationToolRuntimeService{}
	server := &Server{toolRuntime: runtime}

	rec := httptest.NewRecorder()
	server.handleRemoveTSharkAllowedDir(rec, httptest.NewRequest(http.MethodDelete, "/api/tools/tshark/allowed-dirs/remove", strings.NewReader(`{"dir":"C:\\Tools"}`)))
	requireStatus(t, rec, http.StatusOK)
	if !runtime.removeTSharkAllowedDirCalled {
		t.Fatal("RemoveTSharkAllowedDirWithContext should be called")
	}
	if runtime.lastRemoveTSharkAllowedDir != `C:\Tools` {
		t.Fatalf("unexpected dir passed to RemoveTSharkAllowedDirWithContext: %q", runtime.lastRemoveTSharkAllowedDir)
	}
}

func TestHandleToolRuntimeConfigAcceptsOutsideTrustedDirsWithWarnings(t *testing.T) {
	dir := t.TempDir()
	paths := map[string]string{
		"tshark_path": filepath.Join(dir, "tshark.exe"),
		"ffmpeg_path": filepath.Join(dir, "ffmpeg.exe"),
		"python_path": filepath.Join(dir, "python.exe"),
		"yara_bin":    filepath.Join(dir, "yara.exe"),
	}
	for _, path := range paths {
		if err := os.WriteFile(path, []byte("fake"), 0o755); err != nil {
			t.Fatalf("write fake binary %s: %v", path, err)
		}
	}

	runtime := &pathValidationToolRuntimeService{}
	server := &Server{toolRuntime: runtime}
	rec := httptest.NewRecorder()
	body := fmt.Sprintf(`{
		"tshark_path":%q,
		"ffmpeg_path":%q,
		"python_path":%q,
		"yara_bin":%q,
		"yara_enabled":true
	}`, paths["tshark_path"], paths["ffmpeg_path"], paths["python_path"], paths["yara_bin"])

	server.handleToolRuntimeConfig(rec, httptest.NewRequest(http.MethodPost, "/api/tools/runtime-config", strings.NewReader(body)))
	requireStatus(t, rec, http.StatusOK)
	if !runtime.setToolRuntimeConfigCalled {
		t.Fatal("SetToolRuntimeConfig should be called for valid outside-dir tool paths")
	}
	if runtime.lastConfig.FFmpegPath != paths["ffmpeg_path"] || runtime.lastConfig.PythonPath != paths["python_path"] || runtime.lastConfig.YaraBin != paths["yara_bin"] {
		t.Fatalf("unexpected config passed through: %+v", runtime.lastConfig)
	}
}

func TestHandleGenericToolAllowDir(t *testing.T) {
	runtime := &pathValidationToolRuntimeService{}
	server := &Server{toolRuntime: runtime}

	rec := httptest.NewRecorder()
	server.handleAllowToolDir(rec, httptest.NewRequest(http.MethodPost, "/api/tools/allow-dir", strings.NewReader(`{"tool":"speech-to-text","dir":"C:\\Python"}`)))
	requireStatus(t, rec, http.StatusOK)
	if !runtime.allowToolDirCalled || runtime.lastAllowTool != "python" || runtime.lastAllowToolDir != `C:\Python` {
		t.Fatalf("generic allow-dir not routed correctly: called=%v tool=%q dir=%q", runtime.allowToolDirCalled, runtime.lastAllowTool, runtime.lastAllowToolDir)
	}
}

func TestHandleGenericToolAllowDirRejectsUnknownTool(t *testing.T) {
	runtime := &pathValidationToolRuntimeService{}
	server := &Server{toolRuntime: runtime}

	rec := httptest.NewRecorder()
	server.handleAllowToolDir(rec, httptest.NewRequest(http.MethodPost, "/api/tools/allow-dir", strings.NewReader(`{"tool":"unknown","dir":"C:\\Tools"}`)))
	requireStatus(t, rec, http.StatusBadRequest)
	if runtime.allowToolDirCalled {
		t.Fatal("unknown tool should not call AllowToolDirWithContext")
	}
}

type pathValidationToolRuntimeService struct {
	contractToolRuntimeService
	setTSharkPathCalled          bool
	setToolRuntimeConfigCalled   bool
	allowTSharkDirCalled         bool
	removeTSharkAllowedDirCalled bool
	allowToolDirCalled           bool
	removeToolAllowedDirCalled   bool
	lastSetTSharkPath            string
	lastConfig                   model.ToolRuntimeConfig
	lastAllowTSharkDir           string
	lastRemoveTSharkAllowedDir   string
	lastAllowTool                string
	lastAllowToolDir             string
	lastRemoveTool               string
	lastRemoveToolDir            string
}

func (r *pathValidationToolRuntimeService) SetTSharkPathWithContext(_ context.Context, path string) model.TSharkToolStatus {
	r.setTSharkPathCalled = true
	r.lastSetTSharkPath = path
	return model.TSharkToolStatus{}
}

func (r *pathValidationToolRuntimeService) SetToolRuntimeConfig(cfg model.ToolRuntimeConfig) model.ToolRuntimeConfig {
	r.setToolRuntimeConfigCalled = true
	r.lastConfig = cfg
	return cfg
}

func (r *pathValidationToolRuntimeService) AllowTSharkDirWithContext(_ context.Context, dir string) model.TSharkToolStatus {
	r.allowTSharkDirCalled = true
	r.lastAllowTSharkDir = dir
	return model.TSharkToolStatus{}
}

func (r *pathValidationToolRuntimeService) TSharkAllowedDirs() []string { return nil }

func (r *pathValidationToolRuntimeService) RemoveTSharkAllowedDirWithContext(_ context.Context, dir string) model.TSharkToolStatus {
	r.removeTSharkAllowedDirCalled = true
	r.lastRemoveTSharkAllowedDir = dir
	return model.TSharkToolStatus{}
}

func (r *pathValidationToolRuntimeService) AllowToolDirWithContext(_ context.Context, toolName string, dir string) model.ToolRuntimeSnapshot {
	r.allowToolDirCalled = true
	r.lastAllowTool = toolName
	r.lastAllowToolDir = dir
	return model.ToolRuntimeSnapshot{}
}

func (r *pathValidationToolRuntimeService) ToolAllowedDirs(string) []string { return nil }

func (r *pathValidationToolRuntimeService) RemoveToolAllowedDirWithContext(_ context.Context, toolName string, dir string) model.ToolRuntimeSnapshot {
	r.removeToolAllowedDirCalled = true
	r.lastRemoveTool = toolName
	r.lastRemoveToolDir = dir
	return model.ToolRuntimeSnapshot{}
}

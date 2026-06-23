package miscpkg

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gshark/sentinel/backend/internal/model"
)

var (
	moduleIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

const (
	maxModuleZipFiles      = 128
	maxModuleZipFileBytes  = 8 << 20
	maxModuleZipTotalBytes = 32 << 20
)

var miscModuleExecutionTimeout = 10 * time.Second

type InvokeContext struct {
	CapturePath           string
	PythonPath            string
	TSharkPath            string
	Permissions           []string
	ScanFields            func(filePath string, fields []string, displayFilter string) ([]map[string]string, error)
	ScanFieldsWithContext func(ctx context.Context, filePath string, fields []string, displayFilter string) ([]map[string]string, error)
}

type loadedModule struct {
	manifest    model.MiscModuleManifest
	backendPath string
	api         packageAPI
}

type packageAPI struct {
	Method      string   `json:"method"`
	Entry       string   `json:"entry"`
	HostBridge  bool     `json:"host_bridge,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

type Manager struct {
	mu        sync.RWMutex
	baseDir   string
	modules   map[string]loadedModule
	publicKey ed25519.PublicKey
}

func NewManager() *Manager {
	publicKey, _ := loadMISCPublicKey()
	return &Manager{
		modules:   map[string]loadedModule{},
		publicKey: publicKey,
	}
}

func (m *Manager) verifySignature(reader *zip.Reader) error {
	if m.publicKey != nil {
		return verifyMISCPackageSignature(reader, m.publicKey)
	}
	if allowUnsignedMISC() {
		return nil
	}
	return fmt.Errorf("MISC packages must be signed (set %s or MEOW_TRAFFIC_ALLOW_UNSIGNED_MISC=1 for development)", miscPublicKeyEnvVar)
}

func (m *Manager) verifyModuleDir(dir string) error {
	if m.publicKey != nil {
		return verifyModuleDirSignature(dir, m.publicKey)
	}
	if allowUnsignedMISC() {
		return nil
	}
	return fmt.Errorf("MISC modules must be signed (set %s or MEOW_TRAFFIC_ALLOW_UNSIGNED_MISC=1 for development)", miscPublicKeyEnvVar)
}

func (m *Manager) LoadFromDir(dir string) error {
	baseDir, err := filepath.Abs(strings.TrimSpace(dir))
	if err != nil {
		return fmt.Errorf("resolve misc module dir: %w", err)
	}
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		return fmt.Errorf("create misc module dir: %w", err)
	}

	entries, err := os.ReadDir(baseDir)
	if err != nil {
		return fmt.Errorf("read misc module dir: %w", err)
	}

	loaded := make(map[string]loadedModule)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		moduleDir := filepath.Join(baseDir, entry.Name())
		if sigErr := m.verifyModuleDir(moduleDir); sigErr != nil {
			log.Printf("misc module %q skipped: signature verification failed: %v", entry.Name(), sigErr)
			continue
		}
		module, loadErr := loadModuleFromDir(moduleDir)
		if loadErr != nil {
			log.Printf("misc module %q skipped: %v", entry.Name(), loadErr)
			continue
		}
		loaded[module.manifest.ID] = module
	}

	m.mu.Lock()
	m.baseDir = baseDir
	m.modules = loaded
	m.mu.Unlock()
	return nil
}

func (m *Manager) List() []model.MiscModuleManifest {
	m.mu.RLock()
	defer m.mu.RUnlock()

	items := make([]model.MiscModuleManifest, 0, len(m.modules))
	for _, module := range m.modules {
		items = append(items, cloneManifest(module.manifest))
	}
	sort.SliceStable(items, func(i, j int) bool {
		return strings.ToLower(items[i].Title) < strings.ToLower(items[j].Title)
	})
	return items
}

func (m *Manager) Delete(id string) error {
	id = strings.TrimSpace(id)
	if err := validateModuleID(id); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	module, ok := m.modules[id]
	if !ok {
		return fmt.Errorf("misc module %s not found", id)
	}
	moduleDir, err := resolveManagedPath(m.baseDir, module.manifest.ID)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(moduleDir); err != nil {
		return fmt.Errorf("delete module dir: %w", err)
	}
	delete(m.modules, id)
	return nil
}

// ErrModuleZipTooLarge is returned when a module zip upload exceeds the
// configured size limit.
var ErrModuleZipTooLarge = errors.New("module zip exceeds size limit")

func (m *Manager) ImportZip(r io.Reader, sizeLimit int64) (model.MiscModulePackageImportResult, error) {
	m.mu.RLock()
	baseDir := m.baseDir
	m.mu.RUnlock()
	if strings.TrimSpace(baseDir) == "" {
		return model.MiscModulePackageImportResult{}, fmt.Errorf("misc module directory not initialized")
	}

	var buf bytes.Buffer
	// Read one byte past the limit so we can distinguish "exactly at limit"
	// from "over limit".
	limited := io.LimitReader(r, sizeLimit+1)
	n, err := io.Copy(&buf, limited)
	if err != nil {
		return model.MiscModulePackageImportResult{}, fmt.Errorf("read module zip: %w", err)
	}
	if n > sizeLimit {
		return model.MiscModulePackageImportResult{}, fmt.Errorf("%w %d bytes", ErrModuleZipTooLarge, sizeLimit)
	}

	return m.ImportZipBytes(buf.Bytes())
}

func (m *Manager) ImportZipBytes(data []byte) (model.MiscModulePackageImportResult, error) {
	m.mu.RLock()
	baseDir := m.baseDir
	m.mu.RUnlock()
	if strings.TrimSpace(baseDir) == "" {
		return model.MiscModulePackageImportResult{}, fmt.Errorf("misc module directory not initialized")
	}

	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return model.MiscModulePackageImportResult{}, fmt.Errorf("open module zip: %w", err)
	}

	pkgManifest, err := readPackageManifest(reader)
	if err != nil {
		return model.MiscModulePackageImportResult{}, err
	}
	if err := validateModuleID(pkgManifest.ID); err != nil {
		return model.MiscModulePackageImportResult{}, err
	}

	if err := m.verifySignature(reader); err != nil {
		return model.MiscModulePackageImportResult{}, err
	}

	moduleDir, err := resolveManagedPath(baseDir, pkgManifest.ID)
	if err != nil {
		return model.MiscModulePackageImportResult{}, err
	}
	if _, statErr := os.Stat(moduleDir); statErr == nil {
		return model.MiscModulePackageImportResult{}, fmt.Errorf("misc module %s already exists", pkgManifest.ID)
	}
	if err := os.MkdirAll(moduleDir, 0o755); err != nil {
		return model.MiscModulePackageImportResult{}, fmt.Errorf("create module dir: %w", err)
	}

	if err := extractZipToDir(reader, moduleDir); err != nil {
		_ = os.RemoveAll(moduleDir)
		return model.MiscModulePackageImportResult{}, err
	}

	module, err := loadModuleFromDir(moduleDir)
	if err != nil {
		_ = os.RemoveAll(moduleDir)
		return model.MiscModulePackageImportResult{}, err
	}

	m.mu.Lock()
	m.modules[module.manifest.ID] = module
	m.mu.Unlock()

	return model.MiscModulePackageImportResult{
		Module:        cloneManifest(module.manifest),
		InstalledPath: moduleDir,
		Message:       "模块包导入成功",
	}, nil
}

func (m *Manager) Invoke(ctx context.Context, id string, req model.MiscModuleRunRequest, runtime InvokeContext) (model.MiscModuleRunResult, error) {
	m.mu.RLock()
	module, ok := m.modules[strings.TrimSpace(id)]
	m.mu.RUnlock()
	if !ok {
		return model.MiscModuleRunResult{}, fmt.Errorf("misc module %s not found", id)
	}
	permissions := modulePermissions(module.manifest)
	if !hasModulePermission(permissions, "exec.local") {
		return model.MiscModuleRunResult{}, fmt.Errorf("misc module %s missing required permission: exec.local", id)
	}
	runtime.Permissions = permissions
	capturePath := ""
	if hasModulePermission(permissions, "capture.read") {
		capturePath = strings.TrimSpace(runtime.CapturePath)
	}

	input := map[string]any{
		"values":       normalizeValues(req.Values),
		"capture_path": capturePath,
		"tshark_path":  strings.TrimSpace(runtime.TSharkPath),
		"python_path":  strings.TrimSpace(runtime.PythonPath),
		"host_context": map[string]any{
			"capture_path": capturePath,
			"tshark_path":  strings.TrimSpace(runtime.TSharkPath),
			"python_path":  strings.TrimSpace(runtime.PythonPath),
		},
		"module": map[string]any{
			"id":         module.manifest.ID,
			"title":      module.manifest.Title,
			"api_prefix": module.manifest.APIPrefix,
		},
	}

	var result any
	var err error
	switch strings.ToLower(filepath.Ext(module.backendPath)) {
	case ".js", ".mjs", ".cjs":
		result, err = invokeJavaScript(ctx, module.backendPath, input, runtime)
	case ".py":
		if module.api.HostBridge {
			result, err = invokePythonWithHostBridge(ctx, module.backendPath, input, runtime)
		} else {
			result, err = invokePython(ctx, module.backendPath, input, runtime.PythonPath)
		}
	default:
		err = fmt.Errorf("unsupported misc module runtime: %s", module.backendPath)
	}
	if err != nil {
		return model.MiscModuleRunResult{}, err
	}
	return normalizeRunResult(result), nil
}

func modulePermissions(manifest model.MiscModuleManifest) []string {
	if manifest.InterfaceSchema == nil || len(manifest.InterfaceSchema.Permissions) == 0 {
		return []string{"exec.local"}
	}
	return append([]string(nil), manifest.InterfaceSchema.Permissions...)
}

func hasModulePermission(permissions []string, permission string) bool {
	permission = strings.ToLower(strings.TrimSpace(permission))
	for _, item := range permissions {
		if strings.ToLower(strings.TrimSpace(item)) == permission {
			return true
		}
	}
	return false
}

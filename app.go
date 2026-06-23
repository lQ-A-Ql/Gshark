//go:build dev || production || bindings

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/gshark/sentinel/backend/desktopruntime"
	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

type DesktopApp struct {
	ctx              context.Context
	backendAuthToken string
	backendStatus    string
	backendRuntime   *desktopruntime.Runtime
	mu               sync.Mutex
	eventMu          sync.Mutex
	eventCancel      context.CancelFunc
	updateMu         sync.Mutex
	updateInProgress bool
}

type openCaptureDialogResult struct {
	FilePath string `json:"filePath"`
	FileSize int64  `json:"fileSize"`
	FileName string `json:"fileName"`
}

type desktopWebviewSmokeConfig struct {
	Enabled                     bool   `json:"enabled"`
	CapturePath                 string `json:"capture_path,omitempty"`
	MiscPackageDir              string `json:"misc_package_dir,omitempty"`
	GenericIPCDisableExperiment bool   `json:"generic_ipc_disable_experiment,omitempty"`
}

func NewDesktopApp() *DesktopApp {
	return &DesktopApp{
		backendStatus: "not-started",
	}
}

func (a *DesktopApp) Startup(ctx context.Context) {
	a.ctx = ctx
	a.setBackendStatus("starting")
	if err := a.startBackendRuntime(); err != nil {
		a.setBackendStatus("failed: " + err.Error())
		fmt.Fprintf(os.Stderr, "desktop startup: backend runtime bootstrap failed: %v\n", err)
		if os.Getenv("MEOW_TRAFFIC_RELEASE_SMOKE_CHECK") == "1" {
			os.Exit(1)
		}
		return
	}
	a.startBackendEventBridge()
	if os.Getenv("MEOW_TRAFFIC_RELEASE_SMOKE_CHECK") == "1" {
		writeReleaseSmokeResult("release smoke check: ok")
		a.stopBackendRuntime()
		os.Exit(0)
	}
}

func (a *DesktopApp) Shutdown(_ context.Context) {
	a.setBackendStatus("stopped")
	a.stopBackendEventBridge()
	a.stopBackendRuntime()
}

func (a *DesktopApp) GetDesktopWebviewSmokeConfig() desktopWebviewSmokeConfig {
	resultPath := strings.TrimSpace(os.Getenv("MEOW_TRAFFIC_DESKTOP_WEBVIEW_SMOKE_RESULT_PATH"))
	if resultPath == "" {
		return desktopWebviewSmokeConfig{}
	}
	miscPackageDir := strings.TrimSpace(os.Getenv("MEOW_TRAFFIC_DESKTOP_WEBVIEW_SMOKE_MISC_PACKAGE_DIR"))
	if miscPackageDir == "" {
		miscPackageDir = strings.TrimSpace(os.Getenv("MEOW_TRAFFIC_MISC_PACKAGE_DIR"))
	}
	return desktopWebviewSmokeConfig{
		Enabled:                     true,
		CapturePath:                 strings.TrimSpace(os.Getenv("MEOW_TRAFFIC_DESKTOP_WEBVIEW_SMOKE_CAPTURE_PATH")),
		MiscPackageDir:              miscPackageDir,
		GenericIPCDisableExperiment: isTruthyEnv("MEOW_TRAFFIC_DESKTOP_DISABLE_GENERIC_IPC_EXPERIMENT"),
	}
}

func isTruthyEnv(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func (a *DesktopApp) WriteDesktopWebviewSmokeResult(payload map[string]any) error {
	resultPath := strings.TrimSpace(os.Getenv("MEOW_TRAFFIC_DESKTOP_WEBVIEW_SMOKE_RESULT_PATH"))
	if resultPath == "" {
		return fmt.Errorf("desktop webview smoke result path is not configured")
	}
	if err := os.MkdirAll(filepath.Dir(resultPath), 0o755); err != nil {
		return fmt.Errorf("create desktop webview smoke result dir: %w", err)
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal desktop webview smoke result: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(resultPath, data, 0o644); err != nil {
		return fmt.Errorf("write desktop webview smoke result: %w", err)
	}
	return nil
}

func (a *DesktopApp) BackendStatus() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.backendStatus
}

func (a *DesktopApp) GetBackendAuthToken() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.backendAuthToken
}

func (a *DesktopApp) setBackendStatus(status string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.backendStatus = strings.TrimSpace(status)
}

func (a *DesktopApp) startBackendRuntime() error {
	a.mu.Lock()
	if a.backendRuntime != nil {
		a.backendStatus = "running (in-process)"
		a.mu.Unlock()
		return nil
	}
	a.mu.Unlock()

	rt, err := desktopruntime.New(desktopruntime.Options{
		MiscPackageDir: strings.TrimSpace(os.Getenv("MEOW_TRAFFIC_MISC_PACKAGE_DIR")),
	})
	if err != nil {
		return err
	}

	a.mu.Lock()
	a.backendRuntime = rt
	a.backendStatus = "running (in-process)"
	a.mu.Unlock()
	fmt.Fprintln(os.Stdout, "desktop startup: backend runtime mounted in Wails process")
	return nil
}

func (a *DesktopApp) stopBackendRuntime() {
	a.stopBackendEventBridge()
	a.mu.Lock()
	rt := a.backendRuntime
	a.backendRuntime = nil
	a.mu.Unlock()
	if rt != nil {
		_ = rt.Close(context.Background())
	}
}

func (a *DesktopApp) getBackendRuntime() *desktopruntime.Runtime {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.backendRuntime
}

func (a *DesktopApp) OpenCaptureDialog() (openCaptureDialogResult, error) {
	if a.ctx == nil {
		return openCaptureDialogResult{}, fmt.Errorf("desktop context is not ready")
	}

	selected, err := wruntime.OpenFileDialog(a.ctx, wruntime.OpenDialogOptions{
		Title: "选择流量包",
		Filters: []wruntime.FileFilter{
			{
				DisplayName: "Capture Files (*.pcap;*.pcapng;*.cap)",
				Pattern:     "*.pcap;*.pcapng;*.cap",
			},
			{
				DisplayName: "All Files (*.*)",
				Pattern:     "*.*",
			},
		},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "desktop dialog: open capture dialog failed: %v\n", err)
		return openCaptureDialogResult{}, err
	}

	selected = strings.TrimSpace(selected)
	if selected == "" {
		fmt.Fprintln(os.Stdout, "desktop dialog: capture selection canceled")
		return openCaptureDialogResult{}, nil
	}

	info, err := os.Stat(selected)
	if err != nil {
		return openCaptureDialogResult{}, fmt.Errorf("read selected capture file: %w", err)
	}
	if info.IsDir() {
		return openCaptureDialogResult{}, fmt.Errorf("selected path is a directory: %s", selected)
	}

	result := openCaptureDialogResult{
		FilePath: selected,
		FileSize: info.Size(),
		FileName: filepath.Base(selected),
	}
	fmt.Fprintf(os.Stdout, "desktop dialog: selected capture file %q (%d bytes)\n", result.FilePath, result.FileSize)
	return result, nil
}

func (a *DesktopApp) OpenDBCDialog() (openCaptureDialogResult, error) {
	if a.ctx == nil {
		return openCaptureDialogResult{}, fmt.Errorf("desktop context is not ready")
	}

	selected, err := wruntime.OpenFileDialog(a.ctx, wruntime.OpenDialogOptions{
		Title: "选择 DBC 文件",
		Filters: []wruntime.FileFilter{
			{
				DisplayName: "DBC Files (*.dbc)",
				Pattern:     "*.dbc",
			},
			{
				DisplayName: "All Files (*.*)",
				Pattern:     "*.*",
			},
		},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "desktop dialog: open dbc dialog failed: %v\n", err)
		return openCaptureDialogResult{}, err
	}

	selected = strings.TrimSpace(selected)
	if selected == "" {
		fmt.Fprintln(os.Stdout, "desktop dialog: dbc selection canceled")
		return openCaptureDialogResult{}, nil
	}

	info, err := os.Stat(selected)
	if err != nil {
		return openCaptureDialogResult{}, fmt.Errorf("read selected dbc file: %w", err)
	}
	if info.IsDir() {
		return openCaptureDialogResult{}, fmt.Errorf("selected path is a directory: %s", selected)
	}

	result := openCaptureDialogResult{
		FilePath: selected,
		FileSize: info.Size(),
		FileName: filepath.Base(selected),
	}
	fmt.Fprintf(os.Stdout, "desktop dialog: selected dbc file %q (%d bytes)\n", result.FilePath, result.FileSize)
	return result, nil
}

func (a *DesktopApp) SelectMiscModulePackage() (openCaptureDialogResult, error) {
	if a.ctx == nil {
		return openCaptureDialogResult{}, fmt.Errorf("desktop context is not ready")
	}

	selected, err := wruntime.OpenFileDialog(a.ctx, wruntime.OpenDialogOptions{
		Title: "选择 MISC 模块 ZIP 包",
		Filters: []wruntime.FileFilter{
			{
				DisplayName: "MISC Module Package (*.zip)",
				Pattern:     "*.zip",
			},
			{
				DisplayName: "All Files (*.*)",
				Pattern:     "*.*",
			},
		},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "desktop dialog: open misc module package dialog failed: %v\n", err)
		return openCaptureDialogResult{}, err
	}

	selected = strings.TrimSpace(selected)
	if selected == "" {
		fmt.Fprintln(os.Stdout, "desktop dialog: misc module package selection canceled")
		return openCaptureDialogResult{}, nil
	}

	info, err := os.Stat(selected)
	if err != nil {
		return openCaptureDialogResult{}, fmt.Errorf("read selected misc module package: %w", err)
	}
	if info.IsDir() {
		return openCaptureDialogResult{}, fmt.Errorf("selected path is a directory: %s", selected)
	}

	result := openCaptureDialogResult{
		FilePath: selected,
		FileSize: info.Size(),
		FileName: filepath.Base(selected),
	}
	fmt.Fprintf(os.Stdout, "desktop dialog: selected misc module package %q (%d bytes)\n", result.FilePath, result.FileSize)
	return result, nil
}

func writeReleaseSmokeResult(message string) {
	fmt.Fprintln(os.Stdout, message)
	resultPath := strings.TrimSpace(os.Getenv("MEOW_TRAFFIC_RELEASE_SMOKE_RESULT_PATH"))
	if resultPath == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(resultPath), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "release smoke check: create result dir failed: %v\n", err)
		return
	}
	if err := os.WriteFile(resultPath, []byte(message+"\n"), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "release smoke check: write result failed: %v\n", err)
	}
}

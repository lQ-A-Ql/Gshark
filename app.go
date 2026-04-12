//go:build dev || production

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

type DesktopApp struct {
	ctx              context.Context
	backendCmd       *exec.Cmd
	backendAuthToken string
	backendStatus    string
	mu               sync.Mutex
	updateMu         sync.Mutex
	updateInProgress bool
}

type openCaptureDialogResult struct {
	FilePath string `json:"filePath"`
	FileSize int64  `json:"fileSize"`
	FileName string `json:"fileName"`
}

func NewDesktopApp() *DesktopApp {
	return &DesktopApp{
		backendStatus: "not-started",
	}
}

func (a *DesktopApp) Startup(ctx context.Context) {
	a.ctx = ctx
	a.setBackendStatus("starting")
	if err := a.startBackendIfPossible(); err != nil {
		a.setBackendStatus("failed: " + err.Error())
		fmt.Fprintf(os.Stderr, "desktop startup: backend bootstrap failed: %v\n", err)
	}
}

func (a *DesktopApp) Shutdown(_ context.Context) {
	a.setBackendStatus("stopped")
	a.stopBackend()
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

func (a *DesktopApp) startBackendIfPossible() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.backendAuthToken == "" {
		a.backendAuthToken = strings.TrimSpace(os.Getenv("GSHARK_BACKEND_TOKEN"))
	}
	if a.backendCmd != nil {
		a.backendStatus = "running"
		fmt.Fprintln(os.Stdout, "desktop startup: backend process already started in this app instance")
		return nil
	}
	if isBackendAlive("127.0.0.1:17891") {
		if allowReuseExistingBackend() {
			a.backendStatus = "running (reused-existing)"
			fmt.Fprintln(os.Stdout, "desktop startup: reusing existing backend on 127.0.0.1:17891 due to GSHARK_ALLOW_EXISTING_BACKEND=1")
			return nil
		}
		return fmt.Errorf("backend port 127.0.0.1:17891 is already in use; close the existing process or set GSHARK_ALLOW_EXISTING_BACKEND=1 to reuse it")
	}

	cmd, err := buildBackendCommand()
	if err != nil {
		return err
	}
	if a.backendAuthToken == "" {
		token, tokenErr := generateBackendAuthToken()
		if tokenErr != nil {
			return tokenErr
		}
		a.backendAuthToken = token
	}
	cmd.Env = append(os.Environ(), "GSHARK_BACKEND_TOKEN="+a.backendAuthToken)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	fmt.Fprintf(os.Stdout, "desktop startup: launching backend command %q in %q\n", strings.Join(cmd.Args, " "), cmd.Dir)

	if startErr := cmd.Start(); startErr != nil {
		return fmt.Errorf("start backend process: %w", startErr)
	}
	fmt.Fprintf(os.Stdout, "desktop startup: backend process started with pid=%d\n", cmd.Process.Pid)
	a.backendCmd = cmd
	a.backendStatus = "running"
	return nil
}

func buildBackendCommand() (*exec.Cmd, error) {
	if binaryPath, err := resolveBundledBackendBinary(); err == nil {
		cmd := exec.Command(binaryPath, "serve", "127.0.0.1:17891")
		cmd.Dir = filepath.Dir(binaryPath)
		fmt.Fprintf(os.Stdout, "desktop startup: using bundled backend binary %q\n", binaryPath)
		return cmd, nil
	}

	backendDir, err := resolveBackendDir()
	if err != nil {
		return nil, err
	}

	cmd := exec.Command("go", "run", "./cmd/sentinel", "serve", "127.0.0.1:17891")
	cmd.Dir = backendDir
	fmt.Fprintf(os.Stdout, "desktop startup: using go run backend from %q\n", backendDir)
	return cmd, nil
}

func resolveBundledBackendBinary() (string, error) {
	name := "sentinel-backend"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}

	exePath, err := os.Executable()
	if err != nil {
		return "", err
	}
	exeDir := filepath.Dir(exePath)

	candidates := []string{
		filepath.Join(exeDir, name),
		filepath.Join(exeDir, "backend", name),
		filepath.Join(exeDir, "..", name),
		filepath.Join(exeDir, "..", "backend", name),
	}

	for _, candidate := range candidates {
		clean := filepath.Clean(candidate)
		if st, err := os.Stat(clean); err == nil && !st.IsDir() {
			return clean, nil
		}
	}

	if extracted, err := extractBundledBackendFromAssets(name); err == nil {
		return extracted, nil
	}

	return "", fmt.Errorf("bundled backend binary not found near %q", exeDir)
}

func extractBundledBackendFromAssets(filename string) (string, error) {
	embeddedPath := filepath.ToSlash(filepath.Join("frontend", "dist", filename))
	data, err := assets.ReadFile(embeddedPath)
	if err != nil {
		return "", err
	}

	targetDir := filepath.Join(os.TempDir(), "gshark-sentinel", "backend")
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return "", err
	}

	target := filepath.Join(targetDir, filename)
	if writeErr := os.WriteFile(target, data, 0o755); writeErr != nil {
		return "", writeErr
	}
	if runtime.GOOS != "windows" {
		_ = os.Chmod(target, 0o755)
	}

	_ = extractOptionalBundledRules(targetDir)

	return target, nil
}

func extractOptionalBundledRules(targetDir string) error {
	rulesAssetPath := filepath.ToSlash(filepath.Join("frontend", "dist", "rules", "yara", "default.yar"))
	data, err := assets.ReadFile(rulesAssetPath)
	if err != nil {
		return err
	}
	rulesDir := filepath.Join(targetDir, "rules", "yara")
	if mkErr := os.MkdirAll(rulesDir, 0o755); mkErr != nil {
		return mkErr
	}
	ruleFile := filepath.Join(rulesDir, "default.yar")
	return os.WriteFile(ruleFile, data, 0o644)
}

func resolveBackendDir() (string, error) {
	cwd, _ := os.Getwd()
	exePath, _ := os.Executable()
	exeDir := filepath.Dir(exePath)

	candidates := []string{}
	if cwd != "" {
		candidates = append(candidates, filepath.Join(cwd, "backend"))
	}
	if exeDir != "" {
		candidates = append(candidates,
			filepath.Join(exeDir, "backend"),
			filepath.Join(exeDir, "..", "backend"),
			filepath.Join(exeDir, "..", "..", "backend"),
		)
	}

	seen := map[string]struct{}{}
	for _, candidate := range candidates {
		clean := filepath.Clean(candidate)
		if clean == "" {
			continue
		}
		if _, ok := seen[clean]; ok {
			continue
		}
		seen[clean] = struct{}{}

		if st, err := os.Stat(clean); err == nil && st.IsDir() {
			if _, err := os.Stat(filepath.Join(clean, "go.mod")); err == nil {
				return clean, nil
			}
		}
	}

	return "", fmt.Errorf("backend directory not found from cwd=%q exe=%q", cwd, exeDir)
}

func isBackendAlive(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, 400*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func (a *DesktopApp) stopBackend() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.backendCmd == nil || a.backendCmd.Process == nil {
		return
	}
	terminateProcessTree(a.backendCmd.Process.Pid)
	_, _ = a.backendCmd.Process.Wait()
	a.backendCmd = nil
}

func terminateProcessTree(pid int) {
	if pid <= 0 {
		return
	}
	if runtime.GOOS == "windows" {
		_ = exec.Command("taskkill", "/PID", fmt.Sprint(pid), "/T", "/F").Run()
		return
	}
	_ = exec.Command("kill", "-TERM", fmt.Sprint(pid)).Run()
}

func generateBackendAuthToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate backend auth token: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

func allowReuseExistingBackend() bool {
	raw := strings.TrimSpace(os.Getenv("GSHARK_ALLOW_EXISTING_BACKEND"))
	switch strings.ToLower(raw) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

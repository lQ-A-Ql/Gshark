//go:build dev || production

package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
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
	backendBaseURL   string
	backendStatus    string
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

func NewDesktopApp() *DesktopApp {
	return &DesktopApp{
		backendStatus:  "not-started",
		backendBaseURL: backendBaseURL,
	}
}

func (a *DesktopApp) Startup(ctx context.Context) {
	a.ctx = ctx
	a.setBackendStatus("starting")
	if err := a.startBackendIfPossible(); err != nil {
		a.setBackendStatus("failed: " + err.Error())
		fmt.Fprintf(os.Stderr, "desktop startup: backend bootstrap failed: %v\n", err)
		if os.Getenv("GSHARK_RELEASE_SMOKE_CHECK") == "1" {
			os.Exit(1)
		}
		return
	}
	a.startBackendEventBridge()
	if os.Getenv("GSHARK_RELEASE_SMOKE_CHECK") == "1" {
		writeReleaseSmokeResult("release smoke check: ok")
		a.stopBackend()
		os.Exit(0)
	}
}

func (a *DesktopApp) Shutdown(_ context.Context) {
	a.setBackendStatus("stopped")
	a.stopBackendEventBridge()
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
	if isLoopbackBackendListening("127.0.0.1:17891") {
		if allowReuseExistingBackend() {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := probeReusableBackend(ctx, a.backendAuthToken); err != nil {
				return fmt.Errorf("backend port 127.0.0.1:17891 is occupied by an incompatible instance: %w", err)
			}
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
	buildID := backendCommandBuildID(cmd)
	cmd.Env = append(os.Environ(), "GSHARK_BACKEND_TOKEN="+a.backendAuthToken, "GSHARK_BACKEND_BUILD_ID="+buildID)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	fmt.Fprintf(os.Stdout, "desktop startup: launching backend command %q in %q build_id=%q\n", strings.Join(cmd.Args, " "), cmd.Dir, buildID)

	if startErr := cmd.Start(); startErr != nil {
		return fmt.Errorf("start backend process: %w", startErr)
	}
	fmt.Fprintf(os.Stdout, "desktop startup: backend process started with pid=%d\n", cmd.Process.Pid)
	a.backendCmd = cmd
	a.backendStatus = "running"
	return nil
}

func buildBackendCommand() (*exec.Cmd, error) {
	bundledBinaryPath, bundledErr := resolveBundledBackendBinary()
	if bundledErr == nil {
		cmd := exec.Command(bundledBinaryPath, "serve", "127.0.0.1:17891")
		cmd.Dir = filepath.Dir(bundledBinaryPath)
		fmt.Fprintf(os.Stdout, "desktop startup: using bundled backend binary %q\n", bundledBinaryPath)
		return cmd, nil
	}

	packaged, packagedHint := detectPackagedDesktopRuntime()
	if packaged {
		return nil, fmt.Errorf("packaged desktop backend bootstrap failed: %w (runtime=%s)", bundledErr, packagedHint)
	}

	backendDir, err := resolveBackendDir()
	if err != nil {
		return nil, fmt.Errorf("bundled backend unavailable: %v; source backend unavailable: %w", bundledErr, err)
	}

	cmd := exec.Command("go", "run", "./cmd/sentinel", "serve", "127.0.0.1:17891")
	cmd.Dir = backendDir
	fmt.Fprintf(os.Stdout, "desktop startup: bundled backend unavailable (%v); using go run backend from %q\n", bundledErr, backendDir)
	return cmd, nil
}

func backendCommandBuildID(cmd *exec.Cmd) string {
	if cmd == nil || len(cmd.Args) == 0 {
		return "unknown"
	}
	if filepath.Base(cmd.Args[0]) == "go" || strings.EqualFold(filepath.Base(cmd.Args[0]), "go.exe") {
		return "source-go-run"
	}
	binaryPath := cmd.Args[0]
	if !filepath.IsAbs(binaryPath) {
		if resolved, err := exec.LookPath(binaryPath); err == nil {
			binaryPath = resolved
		}
	}
	data, err := os.ReadFile(binaryPath)
	if err != nil {
		return "file-unavailable:" + filepath.Base(binaryPath)
	}
	digest := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(digest[:8])
}

func detectPackagedDesktopRuntime() (bool, string) {
	exePath, err := os.Executable()
	if err != nil {
		return false, "executable-unavailable"
	}
	return detectPackagedDesktopRuntimeForDir(filepath.Dir(exePath))
}

func detectPackagedDesktopRuntimeForDir(exeDir string) (bool, string) {
	cleanDir := strings.ToLower(filepath.Clean(exeDir))
	if strings.Contains(cleanDir, strings.ToLower(filepath.Clean(filepath.Join("release", "out")))) {
		return true, "release-out"
	}
	for _, marker := range []string{
		filepath.Join(exeDir, "backend"),
		filepath.Join(exeDir, "..", "backend"),
		filepath.Join(exeDir, "..", "..", "backend"),
	} {
		cleanMarker := filepath.Clean(marker)
		if st, statErr := os.Stat(filepath.Join(cleanMarker, "go.mod")); statErr == nil && !st.IsDir() {
			return false, "source-checkout"
		}
	}
	return true, "packaged-external"
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
		fmt.Fprintf(os.Stdout, "desktop startup: checking bundled backend candidate %q\n", clean)
		if st, statErr := os.Stat(clean); statErr == nil && !st.IsDir() {
			return clean, nil
		}
	}

	extracted, extractErr := extractBundledBackendFromAssets(name)
	if extractErr == nil {
		return extracted, nil
	}
	return "", fmt.Errorf("bundled backend binary not found near %q: %w", exeDir, extractErr)
}

func extractBundledBackendFromAssets(filename string) (string, error) {
	embeddedPath := filepath.ToSlash(filepath.Join("frontend", "dist", filename))
	data, err := assets.ReadFile(embeddedPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "desktop startup: bundled backend asset read failed path=%q err=%v\n", embeddedPath, err)
		return "", fmt.Errorf("read embedded backend asset %q: %w", embeddedPath, err)
	}

	digest := sha256.Sum256(data)
	targetDir := filepath.Join(os.TempDir(), "gshark-sentinel", "backend", hex.EncodeToString(digest[:8]))
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return "", fmt.Errorf("create backend extraction directory %q: %w", targetDir, err)
	}

	target := filepath.Join(targetDir, filename)
	fmt.Fprintf(os.Stdout, "desktop startup: extracting bundled backend asset path=%q target=%q\n", embeddedPath, target)
	if st, statErr := os.Stat(target); statErr == nil && !st.IsDir() {
		fmt.Fprintf(os.Stdout, "desktop startup: reusing extracted bundled backend %q\n", target)
		_ = extractOptionalBundledRules(targetDir)
		return target, nil
	}

	tempFile, err := os.CreateTemp(targetDir, filename+".*.tmp")
	if err != nil {
		return "", fmt.Errorf("create temporary backend file in %q: %w", targetDir, err)
	}
	tempPath := tempFile.Name()
	if _, err := tempFile.Write(data); err != nil {
		_ = tempFile.Close()
		_ = os.Remove(tempPath)
		return "", fmt.Errorf("write extracted backend temp file %q: %w", tempPath, err)
	}
	if err := tempFile.Close(); err != nil {
		_ = os.Remove(tempPath)
		return "", fmt.Errorf("close extracted backend temp file %q: %w", tempPath, err)
	}
	if runtime.GOOS != "windows" {
		_ = os.Chmod(tempPath, 0o755)
	}
	_ = os.Remove(target)
	if err := os.Rename(tempPath, target); err != nil {
		_ = os.Remove(tempPath)
		return "", fmt.Errorf("promote extracted backend from %q to %q: %w", tempPath, target, err)
	}
	if runtime.GOOS != "windows" {
		_ = os.Chmod(target, 0o755)
	}

	if err := extractOptionalBundledRules(targetDir); err != nil {
		fmt.Fprintf(os.Stderr, "desktop startup: optional bundled rules extraction failed target=%q err=%v\n", targetDir, err)
	}
	return target, nil
}

func extractOptionalBundledRules(targetDir string) error {
	rulesAssetPath := filepath.ToSlash(filepath.Join("frontend", "dist", "rules", "yara", "default.yar"))
	data, err := assets.ReadFile(rulesAssetPath)
	if err != nil {
		return fmt.Errorf("read embedded rules asset %q: %w", rulesAssetPath, err)
	}
	rulesDir := filepath.Join(targetDir, "rules", "yara")
	if mkErr := os.MkdirAll(rulesDir, 0o755); mkErr != nil {
		return fmt.Errorf("create extracted rules directory %q: %w", rulesDir, mkErr)
	}
	ruleFile := filepath.Join(rulesDir, "default.yar")
	tmpRule, err := os.CreateTemp(rulesDir, "default.yar.*.tmp")
	if err != nil {
		return fmt.Errorf("create rules temp file in %q: %w", rulesDir, err)
	}
	tmpRulePath := tmpRule.Name()
	if _, err := tmpRule.Write(data); err != nil {
		_ = tmpRule.Close()
		_ = os.Remove(tmpRulePath)
		return fmt.Errorf("write rules temp file %q: %w", tmpRulePath, err)
	}
	if err := tmpRule.Close(); err != nil {
		_ = os.Remove(tmpRulePath)
		return fmt.Errorf("close rules temp file %q: %w", tmpRulePath, err)
	}
	_ = os.Remove(ruleFile)
	if err := os.Rename(tmpRulePath, ruleFile); err != nil {
		_ = os.Remove(tmpRulePath)
		return fmt.Errorf("promote extracted rules to %q: %w", ruleFile, err)
	}
	return nil
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

func isLoopbackBackendListening(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, 400*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func (a *DesktopApp) stopBackend() {
	a.stopBackendEventBridge()
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

func writeReleaseSmokeResult(message string) {
	fmt.Fprintln(os.Stdout, message)
	resultPath := strings.TrimSpace(os.Getenv("GSHARK_RELEASE_SMOKE_RESULT_PATH"))
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

func allowReuseExistingBackend() bool {
	raw := strings.TrimSpace(os.Getenv("GSHARK_ALLOW_EXISTING_BACKEND"))
	switch strings.ToLower(raw) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

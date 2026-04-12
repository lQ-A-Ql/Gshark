//go:build dev || production

package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

var (
	appVersion     = ""
	appCommit      = ""
	appReleaseRepo = ""
	appManifestURL = ""
)

const (
	defaultReleaseRepo = "lQ-A-Ql/Gshark"
	defaultManifestRef = "master/release/version.json"
	updaterUserAgent   = "GShark-Sentinel-Updater"
)

var (
	semanticVersionPattern = regexp.MustCompile(`(?i)\bv?(\d+)\.(\d+)\.(\d+)\b`)
	githubRepoPattern      = regexp.MustCompile(`(?i)github\.com[:/]+([^/]+)/([^/.]+?)(?:\.git)?$`)
)

type githubReleaseAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
	ContentType        string `json:"content_type"`
	SHA256             string `json:"sha256,omitempty"`
}

type githubRelease struct {
	TagName     string               `json:"tag_name"`
	Name        string               `json:"name"`
	Body        string               `json:"body"`
	HTMLURL     string               `json:"html_url"`
	PublishedAt string               `json:"published_at"`
	Draft       bool                 `json:"draft"`
	Prerelease  bool                 `json:"prerelease"`
	Assets      []githubReleaseAsset `json:"assets"`
}

type updateManifestAsset struct {
	Name        string `json:"name"`
	DownloadURL string `json:"download_url"`
	Size        int64  `json:"size"`
	ContentType string `json:"content_type"`
	SHA256      string `json:"sha256"`
	OS          string `json:"os"`
	Arch        string `json:"arch"`
}

type updateManifest struct {
	Version     string                `json:"version"`
	Name        string                `json:"name"`
	PublishedAt string                `json:"published_at"`
	ReleaseURL  string                `json:"release_url"`
	Notes       string                `json:"notes"`
	Channel     string                `json:"channel"`
	GeneratedAt string                `json:"generated_at"`
	Assets      []updateManifestAsset `json:"assets"`
}

type AppUpdateAsset struct {
	Name        string `json:"name"`
	DownloadURL string `json:"downloadUrl"`
	SizeBytes   int64  `json:"sizeBytes"`
	ContentType string `json:"contentType"`
}

type AppUpdateStatus struct {
	CurrentVersion        string          `json:"currentVersion"`
	CurrentVersionDisplay string          `json:"currentVersionDisplay"`
	CurrentVersionSource  string          `json:"currentVersionSource"`
	CurrentExecutable     string          `json:"currentExecutable"`
	LocalHash             string          `json:"localHash"`
	Repo                  string          `json:"repo"`
	AuthMode              string          `json:"authMode"`
	CheckedAt             string          `json:"checkedAt"`
	APIURL                string          `json:"apiUrl"`
	HasUpdate             bool            `json:"hasUpdate"`
	UpToDate              bool            `json:"upToDate"`
	HashMismatch          bool            `json:"hashMismatch"`
	LatestTag             string          `json:"latestTag"`
	LatestName            string          `json:"latestName"`
	LatestPublishedAt     string          `json:"latestPublishedAt"`
	ReleaseURL            string          `json:"releaseUrl"`
	ReleaseNotes          string          `json:"releaseNotes"`
	SelectedAsset         *AppUpdateAsset `json:"selectedAsset,omitempty"`
	CanInstall            bool            `json:"canInstall"`
	Message               string          `json:"message"`
}

type semanticVersion struct {
	Major int
	Minor int
	Patch int
}

func (a *DesktopApp) CheckAppUpdate() (AppUpdateStatus, error) {
	updateLogf("check-start")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	status, _, _, err := a.checkAppUpdateDetailed(ctx)
	if err != nil {
		updateLogf("check-failed err=%v", err)
		return status, err
	}
	updateLogf(
		"check-success current=%q latest=%q has_update=%t can_install=%t repo=%q asset=%q",
		status.CurrentVersionDisplay,
		status.LatestTag,
		status.HasUpdate,
		status.CanInstall,
		status.Repo,
		func() string {
			if status.SelectedAsset == nil {
				return ""
			}
			return status.SelectedAsset.Name
		}(),
	)
	return status, err
}

func (a *DesktopApp) InstallAppUpdate() (err error) {
	updateLogf("install-start")
	a.updateMu.Lock()
	if a.updateInProgress {
		a.updateMu.Unlock()
		updateLogf("install-skipped reason=%q", "task already in progress")
		return fmt.Errorf("更新任务已在进行中")
	}
	a.updateInProgress = true
	a.updateMu.Unlock()

	defer func() {
		if err == nil {
			return
		}
		updateLogf("install-failed err=%v", err)
		a.updateMu.Lock()
		a.updateInProgress = false
		a.updateMu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	status, _, asset, err := a.checkAppUpdateDetailed(ctx)
	if err != nil {
		return err
	}
	updateLogf(
		"install-check-result has_update=%t can_install=%t asset=%q current_exe=%q",
		status.HasUpdate,
		status.CanInstall,
		func() string {
			if asset == nil {
				return ""
			}
			return asset.Name
		}(),
		status.CurrentExecutable,
	)
	if !status.HasUpdate {
		return fmt.Errorf("当前已经是最新版本")
	}
	if !status.CanInstall {
		return fmt.Errorf(status.Message)
	}
	if asset == nil || strings.TrimSpace(asset.BrowserDownloadURL) == "" {
		return fmt.Errorf("未找到可安装的更新包")
	}

	targetPath := filepath.Clean(status.CurrentExecutable)
	tempDir, err := os.MkdirTemp("", "gshark-update-*")
	if err != nil {
		return fmt.Errorf("创建更新目录失败: %w", err)
	}

	downloadPath := filepath.Join(tempDir, sanitizeFilename(asset.Name))
	updateLogf("install-download asset=%q url=%q target=%q", asset.Name, asset.BrowserDownloadURL, downloadPath)
	if err := downloadReleaseAsset(ctx, asset.BrowserDownloadURL, downloadPath); err != nil {
		return err
	}
	if err := verifyDownloadedAssetSHA256(downloadPath, asset.SHA256); err != nil {
		updateLogf("install-download-verify-failed asset=%q err=%v", asset.Name, err)
		return err
	}
	if normalized := normalizeSHA256(asset.SHA256); normalized != "" {
		updateLogf("install-download-verified asset=%q sha256=%q", asset.Name, normalized)
	}

	stagedPath, err := prepareDownloadedExecutable(downloadPath, tempDir)
	if err != nil {
		return err
	}
	updateLogf("install-stage-ready staged=%q", stagedPath)

	if err := spawnWindowsUpdater(stagedPath, targetPath, os.Getpid()); err != nil {
		return err
	}
	updateLogf("install-updater-spawned target=%q pid=%d", targetPath, os.Getpid())

	a.stopBackend()
	if a.ctx != nil {
		wruntime.Quit(a.ctx)
	}
	return nil
}

func (a *DesktopApp) checkAppUpdateDetailed(ctx context.Context) (AppUpdateStatus, *githubRelease, *githubReleaseAsset, error) {
	currentVersion, currentDisplay, currentSource, currentExecutable := resolveCurrentVersion()
	repo := resolveReleaseRepo()
	localHash := computeExecutableHash(currentExecutable)
	manifestURL := resolveUpdateManifestURL(repo)
	status := AppUpdateStatus{
		CurrentVersion:        currentVersion,
		CurrentVersionDisplay: currentDisplay,
		CurrentVersionSource:  currentSource,
		CurrentExecutable:     currentExecutable,
		LocalHash:             localHash,
		Repo:                  repo,
		AuthMode:              "version.json (public)",
		CheckedAt:             time.Now().UTC().Format(time.RFC3339),
		APIURL:                manifestURL,
	}
	updateLogf(
		"check-detailed current=%q display=%q source=%q exe=%q repo=%q manifest=%q",
		currentVersion,
		currentDisplay,
		currentSource,
		currentExecutable,
		repo,
		status.APIURL,
	)

	manifest, err := fetchLatestUpdateManifest(ctx, manifestURL)
	if err != nil {
		return status, nil, nil, err
	}
	release := manifestToRelease(*manifest)

	latestVersion := extractReleaseVersion(*release)
	selectedAsset := selectReleaseAsset(*release)
	canInstall, reason := selfUpdateSupport(currentExecutable, selectedAsset)
	hasUpdate := hasNewerRelease(currentVersion, latestVersion)
	updateLogf(
		"release-resolved tag=%q name=%q published=%q asset_count=%d selected_asset=%q latest_version=%q",
		release.TagName,
		release.Name,
		release.PublishedAt,
		len(release.Assets),
		func() string {
			if selectedAsset == nil {
				return ""
			}
			return selectedAsset.Name
		}(),
		latestVersion,
	)

	// Hash-based fallback: when semver says "up to date" but the local binary
	// differs in size from the release asset, flag hashMismatch so the UI can
	// inform the user that the binary may be outdated or modified.
	hashMismatch := false
	if !hasUpdate && selectedAsset != nil && localHash != "" {
		// We cannot cheaply download the remote asset just to hash it, but we
		// can compare the file size as a lightweight mismatch indicator.
		if fi, err := os.Stat(currentExecutable); err == nil {
			if fi.Size() != selectedAsset.Size {
				hashMismatch = true
			}
		}
	}

	status.LatestTag = release.TagName
	status.LatestName = release.Name
	status.LatestPublishedAt = release.PublishedAt
	status.ReleaseURL = release.HTMLURL
	status.ReleaseNotes = strings.TrimSpace(release.Body)
	status.HasUpdate = hasUpdate || hashMismatch
	status.UpToDate = !hasUpdate && !hashMismatch
	status.HashMismatch = hashMismatch
	status.CanInstall = (hasUpdate || hashMismatch) && canInstall
	if selectedAsset != nil {
		status.SelectedAsset = &AppUpdateAsset{
			Name:        selectedAsset.Name,
			DownloadURL: selectedAsset.BrowserDownloadURL,
			SizeBytes:   selectedAsset.Size,
			ContentType: selectedAsset.ContentType,
		}
	}

	switch {
	case hashMismatch && !canInstall:
		status.Message = fmt.Sprintf("本地程序与 Release 资产大小不一致（可能已修改或版本不同），但%s", reason)
	case hashMismatch:
		status.Message = fmt.Sprintf("版本号相同 (%s) 但本地程序与 Release 资产大小不一致，建议重新下载。", latestVersion)
	case hasUpdate && !canInstall:
		status.Message = reason
	case hasUpdate:
		status.Message = fmt.Sprintf("检测到新版本 %s，可直接下载并替换当前程序。", latestVersion)
	default:
		status.Message = "当前已经是最新版本。"
	}
	updateLogf(
		"check-summary has_update=%t up_to_date=%t hash_mismatch=%t can_install=%t message=%q",
		status.HasUpdate,
		status.UpToDate,
		status.HashMismatch,
		status.CanInstall,
		status.Message,
	)

	return status, release, selectedAsset, nil
}

func resolveCurrentVersion() (string, string, string, string) {
	exePath, _ := os.Executable()
	exePath = filepath.Clean(strings.TrimSpace(exePath))

	candidates := []struct {
		Value  string
		Source string
	}{
		{Value: strings.TrimSpace(appVersion), Source: "build"},
		{Value: strings.TrimSpace(os.Getenv("GSHARK_VERSION")), Source: "env"},
		{Value: extractVersionCandidate(filepath.Base(exePath)), Source: "filename"},
		{Value: detectGitTag(), Source: "git-tag"},
		{Value: detectBuildInfoVersion(), Source: "build-info"},
		{Value: strings.TrimSpace(appCommit), Source: "build-commit"},
		{Value: detectGitCommit(), Source: "git-commit"},
	}

	for _, candidate := range candidates {
		value := strings.TrimSpace(candidate.Value)
		if value == "" || isUnknownVersion(value) {
			continue
		}
		display := value
		if normalized := normalizeSemanticVersion(value); normalized != "" {
			display = normalized
		}
		return value, display, candidate.Source, exePath
	}

	return "dev", "dev", "fallback", exePath
}

func resolveReleaseRepo() string {
	if repo := strings.TrimSpace(appReleaseRepo); repo != "" {
		return repo
	}
	if repo := strings.TrimSpace(os.Getenv("GSHARK_RELEASE_REPO")); repo != "" {
		return repo
	}
	for _, remoteName := range []string{"gshark", "origin"} {
		if repo := detectGitHubRepoFromRemote(remoteName); repo != "" {
			return repo
		}
	}
	return defaultReleaseRepo
}

func resolveUpdateManifestURL(repo string) string {
	if value := strings.TrimSpace(appManifestURL); value != "" {
		return value
	}
	if value := strings.TrimSpace(os.Getenv("GSHARK_UPDATE_MANIFEST_URL")); value != "" {
		return value
	}
	ref := strings.TrimSpace(os.Getenv("GSHARK_UPDATE_MANIFEST_REF"))
	if ref == "" {
		ref = defaultManifestRef
	}
	ref = strings.TrimPrefix(ref, "/")
	repo = strings.Trim(strings.TrimSpace(repo), "/")
	return fmt.Sprintf("https://raw.githubusercontent.com/%s/%s", repo, ref)
}

func fetchLatestUpdateManifest(ctx context.Context, manifestURL string) (*updateManifest, error) {
	startedAt := time.Now()
	updateLogf("http-request stage=%q method=%s url=%q access=%q", "update-manifest", http.MethodGet, manifestURL, "public")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, manifestURL, nil)
	if err != nil {
		updateLogf("http-request-build-failed stage=%q err=%v", "update-manifest", err)
		return nil, fmt.Errorf("创建更新清单请求失败: %w", err)
	}
	applyUpdateRequestHeaders(req)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		updateLogf("http-request-failed stage=%q elapsed_ms=%d err=%v", "update-manifest", time.Since(startedAt).Milliseconds(), err)
		return nil, describeUpdateRequestError("查询更新清单", err)
	}
	defer resp.Body.Close()
	updateLogf("http-response stage=%q status=%d elapsed_ms=%d", "update-manifest", resp.StatusCode, time.Since(startedAt).Milliseconds())

	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		body := strings.TrimSpace(string(snippet))
		if body == "" {
			body = resp.Status
		}
		updateLogf("http-response-error stage=%q status=%d body=%q", "update-manifest", resp.StatusCode, body)
		return nil, fmt.Errorf("更新清单查询失败: HTTP %d: %s", resp.StatusCode, body)
	}

	var manifest updateManifest
	if err := json.NewDecoder(resp.Body).Decode(&manifest); err != nil {
		updateLogf("http-response-parse-failed stage=%q err=%v", "update-manifest", err)
		return nil, fmt.Errorf("解析更新清单失败: %w", err)
	}
	if strings.TrimSpace(manifest.Version) == "" {
		return nil, fmt.Errorf("更新清单缺少 version 字段")
	}
	if strings.TrimSpace(manifest.Name) == "" {
		manifest.Name = fmt.Sprintf("GShark %s", strings.TrimSpace(manifest.Version))
	}
	updateLogf("http-response-parsed stage=%q version=%q asset_count=%d", "update-manifest", manifest.Version, len(manifest.Assets))
	return &manifest, nil
}

func manifestToRelease(manifest updateManifest) *githubRelease {
	release := &githubRelease{
		TagName:     strings.TrimSpace(manifest.Version),
		Name:        strings.TrimSpace(manifest.Name),
		Body:        strings.TrimSpace(manifest.Notes),
		HTMLURL:     strings.TrimSpace(manifest.ReleaseURL),
		PublishedAt: strings.TrimSpace(manifest.PublishedAt),
		Assets:      make([]githubReleaseAsset, 0, len(manifest.Assets)),
	}
	for _, asset := range manifest.Assets {
		release.Assets = append(release.Assets, githubReleaseAsset{
			Name:               strings.TrimSpace(asset.Name),
			BrowserDownloadURL: strings.TrimSpace(asset.DownloadURL),
			Size:               asset.Size,
			ContentType:        strings.TrimSpace(asset.ContentType),
			SHA256:             normalizeSHA256(asset.SHA256),
		})
	}
	return release
}

func extractReleaseVersion(release githubRelease) string {
	if normalized := normalizeSemanticVersion(release.TagName); normalized != "" {
		return normalized
	}
	if normalized := normalizeSemanticVersion(release.Name); normalized != "" {
		return normalized
	}
	for _, asset := range release.Assets {
		if normalized := normalizeSemanticVersion(asset.Name); normalized != "" {
			return normalized
		}
	}
	return strings.TrimSpace(release.TagName)
}

func selectReleaseAsset(release githubRelease) *githubReleaseAsset {
	if len(release.Assets) == 0 {
		return nil
	}

	bestIndex := -1
	bestScore := -1
	for i := range release.Assets {
		score := scoreReleaseAsset(release.Assets[i])
		if score > bestScore {
			bestIndex = i
			bestScore = score
		}
	}
	if bestIndex < 0 || bestScore < 0 {
		return nil
	}
	return &release.Assets[bestIndex]
}

func scoreReleaseAsset(asset githubReleaseAsset) int {
	name := strings.ToLower(strings.TrimSpace(asset.Name))
	if name == "" || strings.TrimSpace(asset.BrowserDownloadURL) == "" {
		return -1
	}

	score := 0
	switch runtime.GOOS {
	case "windows":
		if strings.HasSuffix(name, ".exe") {
			score += 100
		}
		if strings.HasSuffix(name, ".zip") {
			score += 70
		}
		if strings.Contains(name, "windows") || strings.Contains(name, "win") {
			score += 15
		}
	case "darwin":
		if strings.HasSuffix(name, ".dmg") || strings.HasSuffix(name, ".pkg") || strings.HasSuffix(name, ".zip") {
			score += 90
		}
	case "linux":
		if strings.HasSuffix(name, ".appimage") || strings.HasSuffix(name, ".tar.gz") || strings.HasSuffix(name, ".deb") {
			score += 90
		}
	}

	for _, token := range archTokens(runtime.GOARCH) {
		if strings.Contains(name, token) {
			score += 12
			break
		}
	}

	if !containsAnyArchToken(name) {
		score += 4
	}

	return score
}

func archTokens(arch string) []string {
	switch arch {
	case "amd64":
		return []string{"amd64", "x64", "64"}
	case "arm64":
		return []string{"arm64", "aarch64"}
	case "386":
		return []string{"386", "x86"}
	default:
		return []string{strings.ToLower(arch)}
	}
}

func containsAnyArchToken(name string) bool {
	for _, token := range []string{"amd64", "x64", "arm64", "aarch64", "x86", "386"} {
		if strings.Contains(name, token) {
			return true
		}
	}
	return false
}

func selfUpdateSupport(executablePath string, asset *githubReleaseAsset) (bool, string) {
	if !selfUpdateEnabledBuild {
		return false, fmt.Sprintf("当前为 %s 构建，已禁用自更新，请使用生产版程序执行更新。", currentBuildMode)
	}
	if runtime.GOOS != "windows" {
		return false, "当前仅支持 Windows 发布版程序自更新。"
	}
	if strings.TrimSpace(executablePath) == "" {
		return false, "无法确定当前程序路径。"
	}
	if asset == nil {
		return false, "当前 Release 没有匹配到可安装资产。"
	}
	lowerPath := strings.ToLower(executablePath)
	if strings.Contains(lowerPath, `\go-build\`) || strings.Contains(lowerPath, `\temp\`) {
		return false, "当前为开发态临时程序，请在发布版中使用自更新。"
	}
	if !strings.HasSuffix(lowerPath, ".exe") {
		return false, "当前程序不是 Windows 可执行文件，无法直接替换。"
	}
	return true, ""
}

// computeExecutableHash returns the SHA-256 hex digest of the file at the given path.
// On any error it returns an empty string silently.
func computeExecutableHash(path string) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func hasNewerRelease(currentVersion string, latestVersion string) bool {
	currentVersion = strings.TrimSpace(currentVersion)
	latestVersion = strings.TrimSpace(latestVersion)
	if latestVersion == "" {
		return false
	}

	currentSemantic, okCurrent := parseSemanticVersion(currentVersion)
	latestSemantic, okLatest := parseSemanticVersion(latestVersion)
	if okCurrent && okLatest {
		return compareSemanticVersion(currentSemantic, latestSemantic) < 0
	}

	currentNormalized := normalizeSemanticVersion(currentVersion)
	latestNormalized := normalizeSemanticVersion(latestVersion)
	if currentNormalized != "" && latestNormalized != "" {
		return currentNormalized != latestNormalized
	}

	if strings.EqualFold(currentVersion, latestVersion) {
		return false
	}

	return true
}

func compareSemanticVersion(left, right semanticVersion) int {
	switch {
	case left.Major != right.Major:
		if left.Major < right.Major {
			return -1
		}
		return 1
	case left.Minor != right.Minor:
		if left.Minor < right.Minor {
			return -1
		}
		return 1
	case left.Patch != right.Patch:
		if left.Patch < right.Patch {
			return -1
		}
		return 1
	default:
		return 0
	}
}

func normalizeSemanticVersion(value string) string {
	version, ok := parseSemanticVersion(value)
	if !ok {
		return ""
	}
	return fmt.Sprintf("v%d.%d.%d", version.Major, version.Minor, version.Patch)
}

func parseSemanticVersion(value string) (semanticVersion, bool) {
	matches := semanticVersionPattern.FindStringSubmatch(strings.TrimSpace(value))
	if len(matches) != 4 {
		return semanticVersion{}, false
	}

	major, err := strconv.Atoi(matches[1])
	if err != nil {
		return semanticVersion{}, false
	}
	minor, err := strconv.Atoi(matches[2])
	if err != nil {
		return semanticVersion{}, false
	}
	patch, err := strconv.Atoi(matches[3])
	if err != nil {
		return semanticVersion{}, false
	}

	return semanticVersion{Major: major, Minor: minor, Patch: patch}, true
}

func extractVersionCandidate(value string) string {
	if normalized := normalizeSemanticVersion(value); normalized != "" {
		return normalized
	}
	match := semanticVersionPattern.FindString(strings.TrimSpace(value))
	return strings.TrimSpace(match)
}

func isUnknownVersion(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	return lower == "" || lower == "dev" || lower == "unknown" || lower == "(devel)"
}

func detectBuildInfoVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok || info == nil {
		return ""
	}
	version := strings.TrimSpace(info.Main.Version)
	if isUnknownVersion(version) {
		return ""
	}
	return version
}

func detectGitTag() string {
	return runGitOutput("describe", "--tags", "--abbrev=0")
}

func detectGitCommit() string {
	return runGitOutput("rev-parse", "--short", "HEAD")
}

func detectGitHubRepoFromRemote(name string) string {
	output := runGitOutput("remote", "get-url", name)
	matches := githubRepoPattern.FindStringSubmatch(strings.TrimSpace(output))
	if len(matches) != 3 {
		return ""
	}
	return fmt.Sprintf("%s/%s", matches[1], matches[2])
}

func runGitOutput(args ...string) string {
	repoDir := findRepositoryRoot()
	if repoDir == "" {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = repoDir
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func findRepositoryRoot() string {
	candidates := []string{}
	if cwd, err := os.Getwd(); err == nil && cwd != "" {
		candidates = append(candidates, cwd)
	}
	if exePath, err := os.Executable(); err == nil && exePath != "" {
		candidates = append(candidates, filepath.Dir(exePath))
	}

	seen := map[string]struct{}{}
	for _, candidate := range candidates {
		dir := filepath.Clean(candidate)
		for depth := 0; depth < 6 && dir != "." && dir != string(filepath.Separator); depth++ {
			if _, ok := seen[dir]; ok {
				break
			}
			seen[dir] = struct{}{}
			if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
				return dir
			}
			next := filepath.Dir(dir)
			if next == dir {
				break
			}
			dir = next
		}
	}
	return ""
}

func downloadReleaseAsset(ctx context.Context, url string, destination string) error {
	startedAt := time.Now()
	updateLogf("http-request stage=%q method=%s url=%q destination=%q access=%q", "download-asset", http.MethodGet, url, destination, "public")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		updateLogf("http-request-build-failed stage=%q err=%v", "download-asset", err)
		return fmt.Errorf("创建更新下载请求失败: %w", err)
	}
	applyUpdateRequestHeaders(req)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		updateLogf("http-request-failed stage=%q elapsed_ms=%d err=%v", "download-asset", time.Since(startedAt).Milliseconds(), err)
		return describeUpdateRequestError("下载更新包", err)
	}
	defer resp.Body.Close()
	updateLogf("http-response stage=%q status=%d elapsed_ms=%d", "download-asset", resp.StatusCode, time.Since(startedAt).Milliseconds())

	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		body := strings.TrimSpace(string(snippet))
		if body == "" {
			body = resp.Status
		}
		updateLogf("http-response-error stage=%q status=%d body=%q", "download-asset", resp.StatusCode, body)
		return fmt.Errorf("下载更新包失败: HTTP %d: %s", resp.StatusCode, body)
	}

	file, err := os.Create(destination)
	if err != nil {
		return fmt.Errorf("创建更新文件失败: %w", err)
	}
	defer file.Close()

	if _, err := io.Copy(file, resp.Body); err != nil {
		updateLogf("download-write-failed destination=%q err=%v", destination, err)
		return fmt.Errorf("写入更新文件失败: %w", err)
	}
	if info, statErr := file.Stat(); statErr == nil {
		updateLogf("download-complete destination=%q size=%d elapsed_ms=%d", destination, info.Size(), time.Since(startedAt).Milliseconds())
	} else {
		updateLogf("download-complete destination=%q elapsed_ms=%d", destination, time.Since(startedAt).Milliseconds())
	}
	return nil
}

func verifyDownloadedAssetSHA256(path string, expected string) error {
	expected = normalizeSHA256(expected)
	if expected == "" {
		return nil
	}
	actual := computeExecutableHash(path)
	if actual == "" {
		return fmt.Errorf("无法计算下载文件的 SHA-256")
	}
	if !strings.EqualFold(actual, expected) {
		return fmt.Errorf("下载文件 SHA-256 校验失败: expected=%s actual=%s", expected, actual)
	}
	return nil
}

func prepareDownloadedExecutable(downloadPath string, tempDir string) (string, error) {
	lower := strings.ToLower(downloadPath)
	if strings.HasSuffix(lower, ".exe") {
		return downloadPath, nil
	}
	if !strings.HasSuffix(lower, ".zip") {
		return "", fmt.Errorf("暂不支持安装该更新格式: %s", filepath.Base(downloadPath))
	}

	reader, err := zip.OpenReader(downloadPath)
	if err != nil {
		return "", fmt.Errorf("解压更新包失败: %w", err)
	}
	defer reader.Close()

	bestIndex := -1
	bestScore := -1
	for i := range reader.File {
		name := strings.ToLower(reader.File[i].Name)
		score := 0
		if strings.HasSuffix(name, ".exe") {
			score += 100
		}
		for _, token := range archTokens(runtime.GOARCH) {
			if strings.Contains(name, token) {
				score += 12
				break
			}
		}
		if score > bestScore {
			bestScore = score
			bestIndex = i
		}
	}
	if bestIndex < 0 {
		return "", fmt.Errorf("压缩包中未找到可执行更新文件")
	}

	file := reader.File[bestIndex]
	source, err := file.Open()
	if err != nil {
		return "", fmt.Errorf("读取压缩包更新文件失败: %w", err)
	}
	defer source.Close()

	targetPath := filepath.Join(tempDir, sanitizeFilename(filepath.Base(file.Name)))
	target, err := os.Create(targetPath)
	if err != nil {
		return "", fmt.Errorf("创建解压后的更新文件失败: %w", err)
	}
	defer target.Close()

	if _, err := io.Copy(target, source); err != nil {
		return "", fmt.Errorf("写入解压后的更新文件失败: %w", err)
	}
	return targetPath, nil
}

func spawnWindowsUpdater(sourcePath string, targetPath string, waitPID int) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("当前系统暂不支持自动替换安装")
	}

	scriptDir := filepath.Join(os.TempDir(), "gshark-sentinel", "updater")
	if err := os.MkdirAll(scriptDir, 0o755); err != nil {
		return fmt.Errorf("创建更新脚本目录失败: %w", err)
	}

	scriptPath := filepath.Join(scriptDir, fmt.Sprintf("apply-update-%d.ps1", time.Now().UnixNano()))
	script := buildUpdaterScript()
	if err := os.WriteFile(scriptPath, []byte(script), 0o600); err != nil {
		return fmt.Errorf("写入更新脚本失败: %w", err)
	}

	cmd := exec.Command(
		"powershell",
		"-ExecutionPolicy", "Bypass",
		"-File", scriptPath,
		"-Source", sourcePath,
		"-Target", targetPath,
		"-WaitPid", strconv.Itoa(waitPID),
	)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动更新脚本失败: %w", err)
	}
	return nil
}

func buildUpdaterScript() string {
	var script bytes.Buffer
	script.WriteString("param(\n")
	script.WriteString("  [string]$Source,\n")
	script.WriteString("  [string]$Target,\n")
	script.WriteString("  [int]$WaitPid\n")
	script.WriteString(")\n")
	script.WriteString("$ErrorActionPreference = 'Stop'\n")
	script.WriteString("for ($i = 0; $i -lt 240; $i++) {\n")
	script.WriteString("  try {\n")
	script.WriteString("    Get-Process -Id $WaitPid -ErrorAction Stop | Out-Null\n")
	script.WriteString("    Start-Sleep -Milliseconds 500\n")
	script.WriteString("  } catch {\n")
	script.WriteString("    break\n")
	script.WriteString("  }\n")
	script.WriteString("}\n")
	script.WriteString("$backup = \"$Target.bak\"\n")
	script.WriteString("$staged = \"$Target.new\"\n")
	script.WriteString("Copy-Item -LiteralPath $Source -Destination $staged -Force\n")
	script.WriteString("if (Test-Path -LiteralPath $backup) { Remove-Item -LiteralPath $backup -Force }\n")
	script.WriteString("if (Test-Path -LiteralPath $Target) { Move-Item -LiteralPath $Target -Destination $backup -Force }\n")
	script.WriteString("Move-Item -LiteralPath $staged -Destination $Target -Force\n")
	script.WriteString("Remove-Item -LiteralPath $Source -Force -ErrorAction SilentlyContinue\n")
	script.WriteString("Start-Process -FilePath $Target\n")
	script.WriteString("Remove-Item -LiteralPath $PSCommandPath -Force -ErrorAction SilentlyContinue\n")
	return script.String()
}

func sanitizeFilename(name string) string {
	base := strings.TrimSpace(filepath.Base(name))
	if base == "" || base == "." || base == string(filepath.Separator) {
		return "gshark-update.exe"
	}
	return base
}

func describeUpdateRequestError(stage string, err error) error {
	if err == nil {
		return nil
	}

	var urlErr *neturl.Error
	if errors.As(err, &urlErr) {
		if urlErr.Timeout() {
			return fmt.Errorf("%s失败：连接 GitHub 超时，可能是网络或代理问题: %w", stage, err)
		}
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return fmt.Errorf("%s失败：DNS 解析 GitHub 域名失败，请检查网络或 DNS 配置: %w", stage, err)
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return fmt.Errorf("%s失败：无法建立网络连接，请检查防火墙、代理或系统网络设置: %w", stage, err)
	}

	return fmt.Errorf("%s失败: %w", stage, err)
}

func updateLogf(format string, args ...any) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	fmt.Fprintf(os.Stdout, "[gshark][update][%s] %s\n", timestamp, fmt.Sprintf(format, args...))
}

func applyUpdateRequestHeaders(req *http.Request) {
	if req == nil {
		return
	}
	req.Header.Set("User-Agent", updaterUserAgent)
	req.Header.Set("Accept", "application/json, text/plain, */*")
}

func normalizeSHA256(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimPrefix(value, "sha256:")
	if len(value) != 64 {
		return ""
	}
	for _, ch := range value {
		if !strings.ContainsRune("0123456789abcdef", ch) {
			return ""
		}
	}
	return value
}

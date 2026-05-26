//go:build dev || production

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const backendBaseURL = "http://127.0.0.1:17891"
const desktopBackendBlobMaxBytes int64 = 50 * 1024 * 1024

type backendProxyClient struct {
	baseURL   string
	token     string
	client    *http.Client
	userAgent string
}

type runtimeIdentity struct {
	Service        string `json:"service"`
	Version        string `json:"version"`
	BuildCommit    string `json:"build_commit,omitempty"`
	AuthEnabled    bool   `json:"auth_enabled"`
	BuildID        string `json:"build_id,omitempty"`
	ExecutablePath string `json:"executable_path,omitempty"`
	WorkingDir     string `json:"working_dir,omitempty"`
	StartedAt      string `json:"started_at,omitempty"`
}

type captureStartRequest struct {
	FilePath         string `json:"file_path"`
	DisplayFilter    string `json:"display_filter"`
	MaxPackets       int    `json:"max_packets"`
	EmitPackets      bool   `json:"emit_packets,omitempty"`
	FastList         bool   `json:"fast_list,omitempty"`
	ListProfile      string `json:"list_profile,omitempty"`
	EnableEnrichment bool   `json:"enable_enrichment,omitempty"`
}

type desktopToolRuntimeConfig struct {
	TSharkPath    string `json:"tshark_path"`
	FFmpegPath    string `json:"ffmpeg_path"`
	PythonPath    string `json:"python_path"`
	VoskModelPath string `json:"vosk_model_path"`
	YaraEnabled   bool   `json:"yara_enabled"`
	YaraBin       string `json:"yara_bin"`
	YaraRules     string `json:"yara_rules"`
	YaraTimeoutMS int    `json:"yara_timeout_ms"`
}

type desktopMCPConfig struct {
	Enabled bool `json:"enabled"`
}

type desktopTLSConfig struct {
	SSLKeyLogFile string `json:"ssl_key_log_file"`
	RSAPrivateKey string `json:"rsa_private_key"`
	TargetIPPort  string `json:"target_ip_port"`
}

type desktopStreamPayloadPatch struct {
	Index int    `json:"index"`
	Body  string `json:"body"`
}

type desktopMiscModuleRunRequest struct {
	Values map[string]string `json:"values"`
}

type desktopStreamDecodeRequest struct {
	Decoder string         `json:"decoder"`
	Payload string         `json:"payload"`
	Options map[string]any `json:"options,omitempty"`
}

type desktopStreamPayloadUpdateRequest struct {
	Protocol string                      `json:"protocol"`
	StreamID int                         `json:"stream_id"`
	Patches  []desktopStreamPayloadPatch `json:"patches"`
}

type desktopWinRMDecryptRequest struct {
	Port                 int    `json:"port"`
	AuthMode             string `json:"auth_mode"`
	Password             string `json:"password"`
	NTHash               string `json:"nt_hash"`
	PreviewLines         int    `json:"preview_lines"`
	IncludeErrorFrames   bool   `json:"include_error_frames"`
	ExtractCommandOutput bool   `json:"extract_command_output"`
}

type desktopSMB3RandomSessionKeyRequest struct {
	Username            string `json:"username"`
	Domain              string `json:"domain"`
	NTLMHash            string `json:"ntlm_hash"`
	NTProofStr          string `json:"nt_proof_str"`
	EncryptedSessionKey string `json:"encrypted_session_key"`
}

type desktopC2DecryptRequest struct {
	Family string         `json:"family"`
	Scope  map[string]any `json:"scope,omitempty"`
	VShell map[string]any `json:"vshell,omitempty"`
	CS     map[string]any `json:"cs,omitempty"`
}

type desktopMediaTranscriptionRequest struct {
	Token string `json:"token"`
	Force bool   `json:"force"`
}

type desktopMediaBatchTranscriptionRequest struct {
	Force bool `json:"force"`
}

type desktopHuntingRuntimeConfig struct {
	Prefixes      []string `json:"prefixes"`
	YaraEnabled   bool     `json:"yara_enabled"`
	YaraBin       string   `json:"yara_bin"`
	YaraRules     string   `json:"yara_rules"`
	YaraTimeoutMS int      `json:"yara_timeout_ms"`
}

type desktopVehicleDBCRequest struct {
	Path string `json:"path"`
}

type desktopPluginRequest struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Tag          string   `json:"tag"`
	Author       string   `json:"author"`
	Enabled      bool     `json:"enabled"`
	Entry        string   `json:"entry,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
}

type desktopPluginSourceRequest struct {
	ID            string `json:"id"`
	ConfigPath    string `json:"config_path"`
	ConfigContent string `json:"config_content"`
	LogicPath     string `json:"logic_path,omitempty"`
	LogicContent  string `json:"logic_content,omitempty"`
	Entry         string `json:"entry,omitempty"`
}

type desktopPluginBulkRequest struct {
	IDs     []string `json:"ids"`
	Enabled bool     `json:"enabled"`
}

type desktopBackendRequest struct {
	Method    string                 `json:"method"`
	Path      string                 `json:"path"`
	BodyKind  string                 `json:"body_kind"`
	JSONBody  any                    `json:"json_body,omitempty"`
	Multipart []desktopMultipartPart `json:"multipart,omitempty"`
	TimeoutMS int                    `json:"timeout_ms,omitempty"`
}

type desktopMultipartPart struct {
	Name        string `json:"name"`
	Filename    string `json:"filename,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	Value       string `json:"value,omitempty"`
	DataBase64  string `json:"data_base64,omitempty"`
}

type desktopBackendBlob struct {
	DataBase64  string `json:"data_base64"`
	ContentType string `json:"content_type"`
	Filename    string `json:"filename,omitempty"`
	Size        int64  `json:"size"`
}

type desktopBackendProbe struct {
	Ready           bool   `json:"ready"`
	HealthOK        bool   `json:"health_ok"`
	IdentityOK      bool   `json:"identity_ok"`
	CaptureStatusOK bool   `json:"capture_status_ok"`
	MiscPackageDir  string `json:"misc_package_dir,omitempty"`
	Message         string `json:"message,omitempty"`
}

type backendProxyRawResponse struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

func newBackendProxyClient(token string) *backendProxyClient {
	return newBackendProxyClientWithBaseURL(backendBaseURL, token)
}

func newBackendProxyClientWithBaseURL(baseURL, token string) *backendProxyClient {
	return &backendProxyClient{
		baseURL:   strings.TrimRight(baseURL, "/"),
		token:     strings.TrimSpace(token),
		client:    &http.Client{},
		userAgent: "meow-traffic-DesktopProxy",
	}
}

func (c *backendProxyClient) getJSON(ctx context.Context, path string, dest any) error {
	return c.doJSON(ctx, http.MethodGet, path, nil, dest)
}

func (c *backendProxyClient) postJSON(ctx context.Context, path string, payload any, dest any) error {
	return c.doJSON(ctx, http.MethodPost, path, payload, dest)
}

func (c *backendProxyClient) postMultipartFile(ctx context.Context, path, fieldName, filePath string, dest any) error {
	cleanPath := strings.TrimSpace(filePath)
	if cleanPath == "" {
		return errors.New("file path is required")
	}
	file, err := os.Open(cleanPath)
	if err != nil {
		return fmt.Errorf("open file: %w", err)
	}
	defer file.Close()

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, err := writer.CreateFormFile(strings.TrimSpace(fieldName), filepath.Base(cleanPath))
	if err != nil {
		_ = writer.Close()
		return fmt.Errorf("create multipart file part: %w", err)
	}
	if _, err := io.Copy(part, file); err != nil {
		_ = writer.Close()
		return fmt.Errorf("copy multipart file content: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("close multipart body: %w", err)
	}

	raw, err := c.doRaw(ctx, http.MethodPost, path, bytes.NewReader(buf.Bytes()), writer.FormDataContentType())
	if err != nil {
		return err
	}
	if dest == nil || len(bytes.TrimSpace(raw.Body)) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw.Body, dest); err != nil {
		return fmt.Errorf("decode backend response: %w", err)
	}
	return nil
}

func (c *backendProxyClient) doJSON(ctx context.Context, method, path string, payload any, dest any) error {
	var body io.Reader
	contentType := ""
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("encode request body: %w", err)
		}
		body = bytes.NewReader(encoded)
		contentType = "application/json"
	}

	raw, err := c.doRaw(ctx, method, path, body, contentType)
	if err != nil {
		return err
	}
	if dest == nil || len(bytes.TrimSpace(raw.Body)) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw.Body, dest); err != nil {
		return fmt.Errorf("decode backend response: %w", err)
	}
	return nil
}

func (c *backendProxyClient) doRaw(ctx context.Context, method, path string, body io.Reader, contentType string) (backendProxyRawResponse, error) {
	return c.doRawLimited(ctx, method, path, body, contentType, 0)
}

func (c *backendProxyClient) doRawLimited(ctx context.Context, method, path string, body io.Reader, contentType string, maxBytes int64) (backendProxyRawResponse, error) {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = http.MethodGet
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return backendProxyRawResponse{}, fmt.Errorf("build backend request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if strings.TrimSpace(contentType) != "" {
		req.Header.Set("Content-Type", strings.TrimSpace(contentType))
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	res, err := c.client.Do(req)
	if err != nil {
		return backendProxyRawResponse{}, fmt.Errorf("connect backend %s %s: %w", method, path, err)
	}
	defer res.Body.Close()

	reader := res.Body
	if maxBytes > 0 {
		reader = io.NopCloser(io.LimitReader(res.Body, maxBytes+1))
	}
	raw, err := io.ReadAll(reader)
	if err != nil {
		return backendProxyRawResponse{}, fmt.Errorf("read backend response: %w", err)
	}
	if maxBytes > 0 && int64(len(raw)) > maxBytes {
		return backendProxyRawResponse{}, fmt.Errorf("桌面 IPC blob 响应过大：%s 超过 50MB，请使用原生导出或缩小选择范围。", path)
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return backendProxyRawResponse{}, normalizeBackendProxyError(res.StatusCode, raw)
	}
	return backendProxyRawResponse{StatusCode: res.StatusCode, Header: res.Header.Clone(), Body: raw}, nil
}

func normalizeBackendProxyError(statusCode int, raw []byte) error {
	var payload struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw, &payload); err == nil {
		if msg := strings.TrimSpace(payload.Error); msg != "" {
			return errors.New(msg)
		}
	}
	message := strings.TrimSpace(string(raw))
	if message == "" {
		message = http.StatusText(statusCode)
	}
	return fmt.Errorf("backend request failed: %d %s", statusCode, message)
}

func (a *DesktopApp) backendProxy() *backendProxyClient {
	a.mu.Lock()
	token := a.backendAuthToken
	baseURL := strings.TrimSpace(a.backendBaseURL)
	a.mu.Unlock()
	if baseURL == "" {
		baseURL = backendBaseURL
	}
	return newBackendProxyClientWithBaseURL(baseURL, token)
}

func (a *DesktopApp) backendProxyBaseURL() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	baseURL := strings.TrimSpace(a.backendBaseURL)
	if baseURL == "" {
		return backendBaseURL
	}
	return strings.TrimRight(baseURL, "/")
}

func (a *DesktopApp) backendProxyContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return context.WithTimeout(context.Background(), timeout)
}

func (a *DesktopApp) IsBackendReady() bool {
	ctx, cancel := a.backendProxyContext(3 * time.Second)
	defer cancel()
	var payload map[string]string
	return a.backendProxy().getJSON(ctx, "/health", &payload) == nil
}

func (a *DesktopApp) PingBackendDataPlane() desktopBackendProbe {
	ctx, cancel := a.backendProxyContext(8 * time.Second)
	defer cancel()
	proxy := a.backendProxy()
	probe := desktopBackendProbe{}

	var health map[string]any
	if err := proxy.getJSON(ctx, "/health", &health); err != nil {
		probe.Message = "health probe failed: " + err.Error()
		return probe
	}
	probe.HealthOK = true

	var identity map[string]any
	if err := proxy.getJSON(ctx, "/api/runtime/identity", &identity); err != nil {
		probe.Message = "runtime identity probe failed: " + err.Error()
		return probe
	}
	probe.IdentityOK = true
	probe.MiscPackageDir = strings.TrimSpace(fmt.Sprint(identity["misc_package_dir"]))

	var status map[string]any
	if err := proxy.getJSON(ctx, "/api/capture/status", &status); err != nil {
		probe.Message = "capture status probe failed: " + err.Error()
		return probe
	}
	probe.CaptureStatusOK = true
	probe.Ready = true
	return probe
}

func (a *DesktopApp) InvokeBackendJSON(req desktopBackendRequest) (any, error) {
	raw, err := a.invokeBackendRaw(req, "json")
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(raw.Body)) == 0 {
		return map[string]any{}, nil
	}
	var payload any
	if err := json.Unmarshal(raw.Body, &payload); err != nil {
		return nil, fmt.Errorf("decode backend JSON response for %s %s: %w", req.normalizedMethod(), req.Path, err)
	}
	return payload, nil
}

func (a *DesktopApp) InvokeBackendBlob(req desktopBackendRequest) (desktopBackendBlob, error) {
	raw, err := a.invokeBackendRaw(req, "blob")
	if err != nil {
		return desktopBackendBlob{}, err
	}
	contentType := strings.TrimSpace(raw.Header.Get("Content-Type"))
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	return desktopBackendBlob{
		DataBase64:  base64.StdEncoding.EncodeToString(raw.Body),
		ContentType: contentType,
		Filename:    filenameFromContentDisposition(raw.Header.Get("Content-Disposition")),
		Size:        int64(len(raw.Body)),
	}, nil
}

func (a *DesktopApp) InvokeBackendText(req desktopBackendRequest) (string, error) {
	raw, err := a.invokeBackendRaw(req, "text")
	if err != nil {
		return "", err
	}
	return string(raw.Body), nil
}

func (a *DesktopApp) invokeBackendRaw(req desktopBackendRequest, responseKind string) (backendProxyRawResponse, error) {
	method, path, err := validateDesktopBackendRequest(req)
	if err != nil {
		return backendProxyRawResponse{}, err
	}
	body, contentType, err := desktopBackendRequestBody(req)
	if err != nil {
		return backendProxyRawResponse{}, fmt.Errorf("prepare IPC backend request body for %s %s: %w", method, path, err)
	}
	timeout := desktopBackendRequestTimeout(req, method, path)
	ctx, cancel := a.backendProxyContext(timeout)
	defer cancel()
	var maxBytes int64
	if responseKind == "blob" {
		maxBytes = desktopBackendBlobMaxBytes
	}
	raw, err := a.backendProxy().doRawLimited(ctx, method, path, body, contentType, maxBytes)
	if err != nil {
		return backendProxyRawResponse{}, fmt.Errorf("desktop IPC backend %s request failed for %s %s: %w", responseKind, method, path, err)
	}
	return raw, nil
}

func (r desktopBackendRequest) normalizedMethod() string {
	method := strings.ToUpper(strings.TrimSpace(r.Method))
	if method == "" {
		return http.MethodGet
	}
	return method
}

func validateDesktopBackendRequest(req desktopBackendRequest) (string, string, error) {
	method := req.normalizedMethod()
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodDelete:
	default:
		return "", "", fmt.Errorf("desktop IPC backend request rejected: unsupported method %q", method)
	}

	rawPath := strings.TrimSpace(req.Path)
	if rawPath == "" {
		return "", "", errors.New("desktop IPC backend request rejected: empty path")
	}
	if strings.Contains(rawPath, "\\") {
		return "", "", fmt.Errorf("desktop IPC backend request rejected: path contains backslash: %q", rawPath)
	}
	if strings.HasPrefix(strings.ToLower(rawPath), "http://") || strings.HasPrefix(strings.ToLower(rawPath), "https://") {
		return "", "", fmt.Errorf("desktop IPC backend request rejected: absolute URL is not allowed: %q", rawPath)
	}

	parsed, err := url.ParseRequestURI(rawPath)
	if err != nil {
		return "", "", fmt.Errorf("desktop IPC backend request rejected: invalid path %q: %w", rawPath, err)
	}
	if parsed.Scheme != "" || parsed.Host != "" {
		return "", "", fmt.Errorf("desktop IPC backend request rejected: absolute URL is not allowed: %q", rawPath)
	}
	if !strings.HasPrefix(parsed.Path, "/") {
		return "", "", fmt.Errorf("desktop IPC backend request rejected: path must start with /: %q", rawPath)
	}
	unescapedPath, unescapeErr := url.PathUnescape(parsed.Path)
	if unescapeErr != nil {
		return "", "", fmt.Errorf("desktop IPC backend request rejected: invalid escaped path %q: %w", rawPath, unescapeErr)
	}
	if strings.Contains(unescapedPath, "\\") || strings.Contains(unescapedPath, "..") {
		return "", "", fmt.Errorf("desktop IPC backend request rejected: unsafe path %q", rawPath)
	}
	if parsed.Path != "/health" && !strings.HasPrefix(parsed.Path, "/api/") {
		return "", "", fmt.Errorf("desktop IPC backend request rejected: path outside backend allowlist: %q", rawPath)
	}
	return method, rawPath, nil
}

func desktopBackendRequestBody(req desktopBackendRequest) (io.Reader, string, error) {
	bodyKind := strings.ToLower(strings.TrimSpace(req.BodyKind))
	if bodyKind == "" {
		if req.JSONBody != nil {
			bodyKind = "json"
		} else {
			bodyKind = "none"
		}
	}

	switch bodyKind {
	case "none":
		return nil, "", nil
	case "json":
		encoded, err := json.Marshal(req.JSONBody)
		if err != nil {
			return nil, "", fmt.Errorf("encode JSON body: %w", err)
		}
		return bytes.NewReader(encoded), "application/json", nil
	case "multipart":
		var buf bytes.Buffer
		writer := multipart.NewWriter(&buf)
		for _, part := range req.Multipart {
			name := strings.TrimSpace(part.Name)
			if name == "" {
				_ = writer.Close()
				return nil, "", errors.New("multipart part name is required")
			}
			if strings.TrimSpace(part.DataBase64) == "" {
				if err := writer.WriteField(name, part.Value); err != nil {
					_ = writer.Close()
					return nil, "", fmt.Errorf("write multipart field %q: %w", name, err)
				}
				continue
			}

			data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(part.DataBase64))
			if err != nil {
				_ = writer.Close()
				return nil, "", fmt.Errorf("decode multipart part %q: %w", name, err)
			}
			header := make(textproto.MIMEHeader)
			dispositionParams := map[string]string{"name": name}
			if filename := strings.TrimSpace(part.Filename); filename != "" {
				dispositionParams["filename"] = filename
			}
			header.Set("Content-Disposition", mime.FormatMediaType("form-data", dispositionParams))
			if contentType := strings.TrimSpace(part.ContentType); contentType != "" {
				header.Set("Content-Type", contentType)
			}
			writerPart, err := writer.CreatePart(header)
			if err != nil {
				_ = writer.Close()
				return nil, "", fmt.Errorf("create multipart part %q: %w", name, err)
			}
			if _, err := writerPart.Write(data); err != nil {
				_ = writer.Close()
				return nil, "", fmt.Errorf("write multipart part %q: %w", name, err)
			}
		}
		if err := writer.Close(); err != nil {
			return nil, "", fmt.Errorf("close multipart body: %w", err)
		}
		return bytes.NewReader(buf.Bytes()), writer.FormDataContentType(), nil
	default:
		return nil, "", fmt.Errorf("unsupported body kind %q", bodyKind)
	}
}

func desktopBackendRequestTimeout(req desktopBackendRequest, method, path string) time.Duration {
	if req.TimeoutMS > 0 {
		return time.Duration(req.TimeoutMS) * time.Millisecond
	}
	normalizedPath := strings.ToLower(path)
	if strings.Contains(normalizedPath, "/download") ||
		strings.Contains(normalizedPath, "/export") ||
		strings.Contains(normalizedPath, "/play") ||
		strings.Contains(normalizedPath, "/transcribe") {
		return 60 * time.Second
	}
	if method == http.MethodPost ||
		strings.HasPrefix(normalizedPath, "/api/analysis/") ||
		strings.HasPrefix(normalizedPath, "/api/c2-analysis") ||
		strings.HasPrefix(normalizedPath, "/api/apt-analysis") ||
		strings.HasPrefix(normalizedPath, "/api/evidence") ||
		strings.HasPrefix(normalizedPath, "/api/stats/") ||
		strings.HasPrefix(normalizedPath, "/api/objects") ||
		strings.HasPrefix(normalizedPath, "/api/streams") {
		return 30 * time.Second
	}
	return 15 * time.Second
}

func filenameFromContentDisposition(header string) string {
	_, params, err := mime.ParseMediaType(strings.TrimSpace(header))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(params["filename"])
}

func (a *DesktopApp) GetToolRuntimeSnapshot() (map[string]any, error) {
	return a.getToolRuntimeSnapshot("full")
}

func (a *DesktopApp) GetToolRuntimeSnapshotFast() (map[string]any, error) {
	return a.getToolRuntimeSnapshot("fast")
}

func (a *DesktopApp) GetToolRuntimeSnapshotFull() (map[string]any, error) {
	return a.getToolRuntimeSnapshot("full")
}

func (a *DesktopApp) getToolRuntimeSnapshot(probeMode string) (map[string]any, error) {
	ctx, cancel := a.backendProxyContext(10 * time.Second)
	defer cancel()
	var snapshot map[string]any
	path := "/api/tools/runtime-config"
	if strings.TrimSpace(probeMode) != "" {
		path += "?probe=" + url.QueryEscape(strings.TrimSpace(probeMode))
	}
	if err := a.backendProxy().getJSON(ctx, path, &snapshot); err != nil {
		return nil, err
	}
	return snapshot, nil
}

func (a *DesktopApp) UpdateToolRuntimeConfig(cfg desktopToolRuntimeConfig) (map[string]any, error) {
	return a.updateToolRuntimeConfig(cfg, "full")
}

func (a *DesktopApp) UpdateToolRuntimeConfigFast(cfg desktopToolRuntimeConfig) (map[string]any, error) {
	return a.updateToolRuntimeConfig(cfg, "fast")
}

func (a *DesktopApp) UpdateToolRuntimeConfigFull(cfg desktopToolRuntimeConfig) (map[string]any, error) {
	return a.updateToolRuntimeConfig(cfg, "full")
}

func (a *DesktopApp) updateToolRuntimeConfig(cfg desktopToolRuntimeConfig, probeMode string) (map[string]any, error) {
	ctx, cancel := a.backendProxyContext(10 * time.Second)
	defer cancel()
	var snapshot map[string]any
	path := "/api/tools/runtime-config"
	if strings.TrimSpace(probeMode) != "" {
		path += "?probe=" + url.QueryEscape(strings.TrimSpace(probeMode))
	}
	if err := a.backendProxy().postJSON(ctx, path, cfg, &snapshot); err != nil {
		return nil, err
	}
	return snapshot, nil
}

func (a *DesktopApp) SetTSharkPath(path string) (map[string]any, error) {
	ctx, cancel := a.backendProxyContext(10 * time.Second)
	defer cancel()
	var payload map[string]any
	if err := a.backendProxy().postJSON(ctx, "/api/tools/tshark", map[string]string{"path": strings.TrimSpace(path)}, &payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func (a *DesktopApp) GetMCPStatus() (map[string]any, error) {
	ctx, cancel := a.backendProxyContext(10 * time.Second)
	defer cancel()
	var payload map[string]any
	if err := a.backendProxy().getJSON(ctx, "/api/mcp/config", &payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func (a *DesktopApp) UpdateMCPConfig(cfg desktopMCPConfig) (map[string]any, error) {
	ctx, cancel := a.backendProxyContext(10 * time.Second)
	defer cancel()
	var payload map[string]any
	if err := a.backendProxy().postJSON(ctx, "/api/mcp/config", cfg, &payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func (a *DesktopApp) StartCapture(filePath, filter string) error {
	ctx, cancel := a.backendProxyContext(15 * time.Second)
	defer cancel()
	return a.backendProxy().postJSON(ctx, "/api/capture/start", captureStartRequest{
		FilePath:         strings.TrimSpace(filePath),
		DisplayFilter:    filter,
		MaxPackets:       0,
		EmitPackets:      false,
		FastList:         true,
		ListProfile:      "first_screen",
		EnableEnrichment: true,
	}, nil)
}

func (a *DesktopApp) StopCapture() error {
	ctx, cancel := a.backendProxyContext(10 * time.Second)
	defer cancel()
	return a.backendProxy().postJSON(ctx, "/api/capture/stop", map[string]any{}, nil)
}

func (a *DesktopApp) PrepareCaptureReplacement() error {
	ctx, cancel := a.backendProxyContext(10 * time.Second)
	defer cancel()
	return a.backendProxy().postJSON(ctx, "/api/capture/prepare-replacement", map[string]any{}, nil)
}

func (a *DesktopApp) CloseCapture() error {
	ctx, cancel := a.backendProxyContext(10 * time.Second)
	defer cancel()
	return a.backendProxy().postJSON(ctx, "/api/capture/close", map[string]any{}, nil)
}

func (a *DesktopApp) GetCaptureStatus() (map[string]any, error) {
	ctx, cancel := a.backendProxyContext(10 * time.Second)
	defer cancel()
	var payload map[string]any
	if err := a.backendProxy().getJSON(ctx, "/api/capture/status", &payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func (a *DesktopApp) ListPacketsPage(cursor, limit int, filter string) (map[string]any, error) {
	ctx, cancel := a.backendProxyContext(10 * time.Second)
	defer cancel()
	query := fmt.Sprintf(
		"/api/packets/page?cursor=%d&limit=%d",
		cursor,
		limit,
	)
	if strings.TrimSpace(filter) != "" {
		query += "&filter=" + url.QueryEscape(filter)
	}
	var payload map[string]any
	if err := a.backendProxy().getJSON(ctx, query, &payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func (a *DesktopApp) LocatePacketPage(packetID, limit int, filter string) (map[string]any, error) {
	ctx, cancel := a.backendProxyContext(10 * time.Second)
	defer cancel()
	query := fmt.Sprintf(
		"/api/packets/locate?id=%d&limit=%d",
		packetID,
		limit,
	)
	if strings.TrimSpace(filter) != "" {
		query += "&filter=" + url.QueryEscape(filter)
	}
	var payload map[string]any
	if err := a.backendProxy().getJSON(ctx, query, &payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func (a *DesktopApp) GetPacket(packetID int) (map[string]any, error) {
	ctx, cancel := a.backendProxyContext(10 * time.Second)
	defer cancel()
	var payload map[string]any
	if err := a.backendProxy().getJSON(ctx, fmt.Sprintf("/api/packet?id=%d", packetID), &payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func (a *DesktopApp) ListThreatHits(prefixes []string) (any, error) {
	query := url.Values{}
	for _, prefix := range prefixes {
		if strings.TrimSpace(prefix) != "" {
			query.Add("prefix", prefix)
		}
	}
	path := "/api/hunting"
	if encoded := query.Encode(); encoded != "" {
		path += "?" + encoded
	}
	return a.desktopGetJSON(path, 120*time.Second)
}

func (a *DesktopApp) GetHuntingRuntimeConfig() (any, error) {
	return a.desktopGetJSON("/api/hunting/config", 10*time.Second)
}

func (a *DesktopApp) UpdateHuntingRuntimeConfig(config desktopHuntingRuntimeConfig) (any, error) {
	return a.desktopPostJSON("/api/hunting/config", config, 15*time.Second)
}

func (a *DesktopApp) ListVehicleDBCProfiles() (any, error) {
	return a.desktopGetJSON("/api/analysis/vehicle/dbc", 10*time.Second)
}

func (a *DesktopApp) AddVehicleDBC(path string) (any, error) {
	return a.desktopPostJSON("/api/analysis/vehicle/dbc", desktopVehicleDBCRequest{Path: path}, 15*time.Second)
}

func (a *DesktopApp) RemoveVehicleDBC(path string) (any, error) {
	query := "/api/analysis/vehicle/dbc?path=" + url.QueryEscape(path)
	return a.desktopDeleteJSON(query, 10*time.Second)
}

func (a *DesktopApp) ListPlugins() (any, error) {
	return a.desktopGetJSON("/api/plugins", 10*time.Second)
}

func (a *DesktopApp) GetPluginSource(id string) (any, error) {
	return a.desktopGetJSON("/api/plugins/source?id="+url.QueryEscape(strings.TrimSpace(id)), 10*time.Second)
}

func (a *DesktopApp) SavePluginSource(source desktopPluginSourceRequest) (any, error) {
	return a.desktopPostJSON("/api/plugins/source", source, 15*time.Second)
}

func (a *DesktopApp) AddPlugin(plugin desktopPluginRequest) (any, error) {
	return a.desktopPostJSON("/api/plugins/add", plugin, 15*time.Second)
}

func (a *DesktopApp) DeletePlugin(id string) (any, error) {
	return a.desktopPostJSON("/api/plugins/delete?id="+url.QueryEscape(strings.TrimSpace(id)), map[string]any{}, 10*time.Second)
}

func (a *DesktopApp) TogglePlugin(id string) (any, error) {
	return a.desktopPostJSON("/api/plugins/toggle?id="+url.QueryEscape(strings.TrimSpace(id)), map[string]any{}, 10*time.Second)
}

func (a *DesktopApp) SetPluginsEnabled(ids []string, enabled bool) (any, error) {
	return a.desktopPostJSON("/api/plugins/bulk", desktopPluginBulkRequest{IDs: ids, Enabled: enabled}, 15*time.Second)
}

func (a *DesktopApp) ListMiscModules() (any, error) {
	return a.desktopGetJSON("/api/tools/misc/modules", 15*time.Second)
}

func (a *DesktopApp) ImportMiscModulePackageFromPath(path string) (any, error) {
	return a.desktopPostMultipartFile("/api/tools/misc/import", "file", path, 60*time.Second)
}

func (a *DesktopApp) DeleteMiscModulePackage(id string) (any, error) {
	return a.desktopDeleteJSON("/api/tools/misc/packages/"+url.PathEscape(strings.TrimSpace(id)), 15*time.Second)
}

func (a *DesktopApp) RunMiscModulePackage(id string, values map[string]string) (any, error) {
	payload := desktopMiscModuleRunRequest{Values: values}
	return a.desktopPostJSON("/api/tools/misc/packages/"+url.PathEscape(strings.TrimSpace(id))+"/invoke", payload, 120*time.Second)
}

func (a *DesktopApp) GetTLSConfig() (desktopTLSConfig, error) {
	ctx, cancel := a.backendProxyContext(10 * time.Second)
	defer cancel()
	var cfg desktopTLSConfig
	if err := a.backendProxy().getJSON(ctx, "/api/tls", &cfg); err != nil {
		return desktopTLSConfig{}, err
	}
	return cfg, nil
}

func (a *DesktopApp) UpdateTLSConfig(cfg desktopTLSConfig) error {
	ctx, cancel := a.backendProxyContext(10 * time.Second)
	defer cancel()
	return a.backendProxy().postJSON(ctx, "/api/tls", cfg, nil)
}

func (a *DesktopApp) desktopGetJSON(path string, timeout time.Duration) (any, error) {
	ctx, cancel := a.backendProxyContext(timeout)
	defer cancel()
	var payload any
	if err := a.backendProxy().getJSON(ctx, path, &payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func (a *DesktopApp) desktopPostJSON(path string, payload any, timeout time.Duration) (any, error) {
	ctx, cancel := a.backendProxyContext(timeout)
	defer cancel()
	var response any
	if err := a.backendProxy().postJSON(ctx, path, payload, &response); err != nil {
		return nil, err
	}
	return response, nil
}

func (a *DesktopApp) desktopPostMultipartFile(path, fieldName, filePath string, timeout time.Duration) (any, error) {
	ctx, cancel := a.backendProxyContext(timeout)
	defer cancel()
	var response any
	if err := a.backendProxy().postMultipartFile(ctx, path, fieldName, filePath, &response); err != nil {
		return nil, err
	}
	return response, nil
}

func (a *DesktopApp) desktopDeleteJSON(path string, timeout time.Duration) (any, error) {
	ctx, cancel := a.backendProxyContext(timeout)
	defer cancel()
	var response any
	if err := a.backendProxy().doJSON(ctx, http.MethodDelete, path, nil, &response); err != nil {
		return nil, err
	}
	return response, nil
}

func (a *DesktopApp) GetHttpStream(streamID int) (any, error) {
	return a.desktopGetJSON(fmt.Sprintf("/api/streams/http?streamId=%d", streamID), 30*time.Second)
}

func (a *DesktopApp) GetRawStream(protocol string, streamID int) (any, error) {
	query := fmt.Sprintf(
		"/api/streams/raw?protocol=%s&streamId=%d",
		url.QueryEscape(strings.ToUpper(strings.TrimSpace(protocol))),
		streamID,
	)
	return a.desktopGetJSON(query, 30*time.Second)
}

func (a *DesktopApp) GetRawStreamPage(protocol string, streamID, cursor, limit int) (any, error) {
	query := fmt.Sprintf(
		"/api/streams/raw/page?protocol=%s&streamId=%d&cursor=%d&limit=%d",
		url.QueryEscape(strings.ToUpper(strings.TrimSpace(protocol))),
		streamID,
		cursor,
		limit,
	)
	return a.desktopGetJSON(query, 30*time.Second)
}

func (a *DesktopApp) DecodeStreamPayload(req desktopStreamDecodeRequest) (any, error) {
	if req.Options == nil {
		req.Options = map[string]any{}
	}
	return a.desktopPostJSON("/api/streams/decode", req, 30*time.Second)
}

func (a *DesktopApp) InspectStreamPayload(payload string) (any, error) {
	return a.desktopPostJSON("/api/streams/inspect", map[string]string{"payload": payload}, 30*time.Second)
}

func (a *DesktopApp) ListStreamPayloadSources(limit int) (any, error) {
	if limit <= 0 {
		limit = 500
	}
	return a.desktopGetJSON(fmt.Sprintf("/api/streams/payload-sources?limit=%d", limit), 30*time.Second)
}

func (a *DesktopApp) ListStreamIDs(protocol string) (any, error) {
	query := "/api/streams/index?protocol=" + url.QueryEscape(strings.ToUpper(strings.TrimSpace(protocol)))
	return a.desktopGetJSON(query, 15*time.Second)
}

func (a *DesktopApp) UpdateStreamPayloads(protocol string, streamID int, patches []desktopStreamPayloadPatch) (any, error) {
	return a.desktopPostJSON("/api/streams/payloads", desktopStreamPayloadUpdateRequest{
		Protocol: strings.ToUpper(strings.TrimSpace(protocol)),
		StreamID: streamID,
		Patches:  patches,
	}, 30*time.Second)
}

func (a *DesktopApp) GetPacketRawHex(packetID int) (any, error) {
	return a.desktopGetJSON(fmt.Sprintf("/api/packet/raw?id=%d", packetID), 15*time.Second)
}

func (a *DesktopApp) GetPacketLayers(packetID int) (any, error) {
	return a.desktopGetJSON(fmt.Sprintf("/api/packet/layers?id=%d", packetID), 15*time.Second)
}

func (a *DesktopApp) ListObjects() (any, error) {
	return a.desktopGetJSON("/api/objects", 30*time.Second)
}

func (a *DesktopApp) DownloadObjectsZip(ids []int) (desktopBackendBlob, error) {
	return a.InvokeBackendBlob(desktopBackendRequest{
		Method:   http.MethodPost,
		Path:     "/api/objects/download",
		BodyKind: "json",
		JSONBody: map[string]any{"ids": ids},
	})
}

func (a *DesktopApp) RunWinRMDecrypt(req desktopWinRMDecryptRequest) (any, error) {
	return a.desktopPostJSON("/api/tools/winrm-decrypt", req, 60*time.Second)
}

func (a *DesktopApp) GetWinRMDecryptResultText(resultID string) (string, error) {
	return a.InvokeBackendText(desktopBackendRequest{
		Path: "/api/tools/winrm-decrypt/export?result_id=" + url.QueryEscape(strings.TrimSpace(resultID)),
	})
}

func (a *DesktopApp) ExportWinRMDecryptResult(resultID string) (desktopBackendBlob, error) {
	return a.InvokeBackendBlob(desktopBackendRequest{
		Path: "/api/tools/winrm-decrypt/export?result_id=" + url.QueryEscape(strings.TrimSpace(resultID)),
	})
}

func (a *DesktopApp) ListSMB3SessionCandidates() (any, error) {
	return a.desktopGetJSON("/api/tools/smb3-session-candidates", 30*time.Second)
}

func (a *DesktopApp) GenerateSMB3RandomSessionKey(req desktopSMB3RandomSessionKeyRequest) (any, error) {
	return a.desktopPostJSON("/api/tools/smb3-random-session-key", req, 30*time.Second)
}

func (a *DesktopApp) ListNTLMSessionMaterials() (any, error) {
	return a.desktopGetJSON("/api/tools/ntlm-sessions", 30*time.Second)
}

func (a *DesktopApp) GetHTTPLoginAnalysis() (any, error) {
	return a.desktopGetJSON("/api/tools/http-login-analysis", 30*time.Second)
}

func (a *DesktopApp) GetSMTPAnalysis() (any, error) {
	return a.desktopGetJSON("/api/tools/smtp-analysis", 30*time.Second)
}

func (a *DesktopApp) GetMySQLAnalysis() (any, error) {
	return a.desktopGetJSON("/api/tools/mysql-analysis", 30*time.Second)
}

func (a *DesktopApp) GetShiroRememberMeAnalysis(candidateKeys []string) (any, error) {
	return a.desktopPostJSON("/api/tools/shiro-rememberme", map[string]any{
		"candidate_keys": candidateKeys,
	}, 30*time.Second)
}

func (a *DesktopApp) GetGlobalTrafficStats() (any, error) {
	return a.desktopGetJSON("/api/stats/traffic/global", 30*time.Second)
}

func (a *DesktopApp) GetIndustrialAnalysis() (any, error) {
	return a.desktopGetJSON("/api/analysis/industrial", 30*time.Second)
}

func (a *DesktopApp) GetVehicleAnalysis() (any, error) {
	return a.desktopGetJSON("/api/analysis/vehicle", 30*time.Second)
}

func (a *DesktopApp) GetMediaAnalysis(forceRefresh bool) (any, error) {
	path := "/api/analysis/media"
	if forceRefresh {
		path += "?refresh=1"
	}
	return a.desktopGetJSON(path, 60*time.Second)
}

func (a *DesktopApp) TranscribeMediaArtifact(token string, force bool) (any, error) {
	return a.desktopPostJSON("/api/analysis/media/transcribe", desktopMediaTranscriptionRequest{
		Token: strings.TrimSpace(token),
		Force: force,
	}, 60*time.Second)
}

func (a *DesktopApp) StartMediaBatchTranscription(force bool) (any, error) {
	return a.desktopPostJSON("/api/analysis/media/transcribe/batch", desktopMediaBatchTranscriptionRequest{
		Force: force,
	}, 60*time.Second)
}

func (a *DesktopApp) GetMediaBatchTranscriptionStatus() (any, error) {
	return a.desktopGetJSON("/api/analysis/media/transcribe/batch", 15*time.Second)
}

func (a *DesktopApp) CancelMediaBatchTranscription() (any, error) {
	return a.desktopPostJSON("/api/analysis/media/transcribe/batch/cancel", map[string]any{}, 15*time.Second)
}

func (a *DesktopApp) ExportMediaBatchTranscription(format string) (desktopBackendBlob, error) {
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" {
		format = "txt"
	}
	return a.InvokeBackendBlob(desktopBackendRequest{
		Path: "/api/analysis/media/transcribe/batch/export?format=" + url.QueryEscape(format),
	})
}

func (a *DesktopApp) DownloadMediaArtifact(token string) (desktopBackendBlob, error) {
	return a.InvokeBackendBlob(desktopBackendRequest{
		Path: "/api/analysis/media/export?token=" + url.QueryEscape(strings.TrimSpace(token)),
	})
}

func (a *DesktopApp) GetMediaPlaybackBlob(token string) (desktopBackendBlob, error) {
	return a.InvokeBackendBlob(desktopBackendRequest{
		Path: "/api/analysis/media/play?token=" + url.QueryEscape(strings.TrimSpace(token)),
	})
}

func (a *DesktopApp) GetUSBAnalysis(hidSource string, hidEventLimit int) (any, error) {
	if strings.TrimSpace(hidSource) == "" {
		hidSource = "auto"
	}
	if hidEventLimit <= 0 {
		hidEventLimit = 20000
	}
	values := url.Values{}
	values.Set("hid_source", strings.TrimSpace(hidSource))
	values.Set("hid_event_limit", fmt.Sprint(hidEventLimit))
	return a.desktopGetJSON("/api/analysis/usb?"+values.Encode(), 30*time.Second)
}

func (a *DesktopApp) GetC2SampleAnalysis() (any, error) {
	return a.desktopGetJSON("/api/c2-analysis", 30*time.Second)
}

func (a *DesktopApp) DecryptC2Traffic(req desktopC2DecryptRequest) (any, error) {
	return a.desktopPostJSON("/api/c2-analysis/decrypt", req, 60*time.Second)
}

func (a *DesktopApp) GetAPTAnalysis() (any, error) {
	return a.desktopGetJSON("/api/apt-analysis", 30*time.Second)
}

func (a *DesktopApp) GetEvidence() (any, error) {
	return a.desktopGetJSON("/api/evidence", 30*time.Second)
}

func (a *DesktopApp) GetEvidenceWithFilter(modules []string) (any, error) {
	values := url.Values{}
	if len(modules) > 0 {
		cleaned := make([]string, 0, len(modules))
		for _, module := range modules {
			if trimmed := strings.TrimSpace(module); trimmed != "" {
				cleaned = append(cleaned, trimmed)
			}
		}
		if len(cleaned) > 0 {
			values.Set("modules", strings.Join(cleaned, ","))
		}
	}
	path := "/api/evidence"
	if encoded := values.Encode(); encoded != "" {
		path += "?" + encoded
	}
	return a.desktopGetJSON(path, 30*time.Second)
}

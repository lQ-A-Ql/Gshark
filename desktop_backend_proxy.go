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

type desktopTLSConfig struct {
	SSLKeyLogFile string `json:"ssl_key_log_file"`
	RSAPrivateKey string `json:"rsa_private_key"`
	TargetIPPort  string `json:"target_ip_port"`
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
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   strings.TrimSpace(token),
		client: &http.Client{
			Timeout: 15 * time.Second,
		},
		userAgent: "GShark-Sentinel-DesktopProxy",
	}
}

func (c *backendProxyClient) getJSON(ctx context.Context, path string, dest any) error {
	return c.doJSON(ctx, http.MethodGet, path, nil, dest)
}

func (c *backendProxyClient) postJSON(ctx context.Context, path string, payload any, dest any) error {
	return c.doJSON(ctx, http.MethodPost, path, payload, dest)
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

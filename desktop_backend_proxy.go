//go:build dev || production

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const backendBaseURL = "http://127.0.0.1:17891"

type backendProxyClient struct {
	baseURL   string
	token     string
	client    *http.Client
	userAgent string
}

type runtimeIdentity struct {
	Service     string `json:"service"`
	Version     string `json:"version"`
	BuildCommit string `json:"build_commit,omitempty"`
	AuthEnabled bool   `json:"auth_enabled"`
}

type captureStartRequest struct {
	FilePath      string `json:"file_path"`
	DisplayFilter string `json:"display_filter"`
	MaxPackets    int    `json:"max_packets"`
	EmitPackets   bool   `json:"emit_packets,omitempty"`
	FastList      bool   `json:"fast_list,omitempty"`
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
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("encode request body: %w", err)
		}
		body = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return fmt.Errorf("build backend request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	res, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("connect backend %s %s: %w", method, path, err)
	}
	defer res.Body.Close()

	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("read backend response: %w", err)
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return normalizeBackendProxyError(res.StatusCode, raw)
	}
	if dest == nil || len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, dest); err != nil {
		return fmt.Errorf("decode backend response: %w", err)
	}
	return nil
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
	a.mu.Unlock()
	return newBackendProxyClient(token)
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

func (a *DesktopApp) GetToolRuntimeSnapshot() (map[string]any, error) {
	ctx, cancel := a.backendProxyContext(10 * time.Second)
	defer cancel()
	var snapshot map[string]any
	if err := a.backendProxy().getJSON(ctx, "/api/tools/runtime-config", &snapshot); err != nil {
		return nil, err
	}
	return snapshot, nil
}

func (a *DesktopApp) UpdateToolRuntimeConfig(cfg desktopToolRuntimeConfig) (map[string]any, error) {
	ctx, cancel := a.backendProxyContext(10 * time.Second)
	defer cancel()
	var snapshot map[string]any
	if err := a.backendProxy().postJSON(ctx, "/api/tools/runtime-config", cfg, &snapshot); err != nil {
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
		FilePath:      strings.TrimSpace(filePath),
		DisplayFilter: filter,
		MaxPackets:    0,
		EmitPackets:   false,
		FastList:      true,
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

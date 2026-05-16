//go:build dev || production

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

func (a *DesktopApp) startBackendEventBridge() {
	if a.ctx == nil {
		return
	}
	a.eventMu.Lock()
	if a.eventCancel != nil {
		a.eventCancel()
	}
	ctx, cancel := context.WithCancel(a.ctx)
	a.eventCancel = cancel
	a.eventMu.Unlock()

	go a.runBackendEventBridge(ctx)
}

func (a *DesktopApp) stopBackendEventBridge() {
	a.eventMu.Lock()
	cancel := a.eventCancel
	a.eventCancel = nil
	a.eventMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (a *DesktopApp) runBackendEventBridge(ctx context.Context) {
	backoff := time.Second
	for {
		sawEvent, err := a.readBackendEvents(ctx)
		if sawEvent {
			backoff = time.Second
		}
		if err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "desktop events: backend SSE bridge disconnected: %v\n", err)
			wruntime.EventsEmit(a.ctx, "gshark:backend:error", map[string]any{
				"message": fmt.Sprintf("桌面事件桥断开，%.0fs 后重连：%v", backoff.Seconds(), err),
			})
		}
		if ctx.Err() != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
			backoff *= 2
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
		}
	}
}

func (a *DesktopApp) readBackendEvents(ctx context.Context) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.backendProxyBaseURL()+"/api/events", nil)
	if err != nil {
		return false, fmt.Errorf("build event request: %w", err)
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("User-Agent", "GShark-Sentinel-DesktopEventBridge")
	if token := strings.TrimSpace(a.GetBackendAuthToken()); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	res, err := newDesktopEventHTTPClient().Do(req)
	if err != nil {
		return false, fmt.Errorf("connect event stream: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return false, fmt.Errorf("event stream returned %d %s", res.StatusCode, res.Status)
	}

	scanner := bufio.NewScanner(res.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	eventName := "message"
	var dataLines []string
	sawEvent := false
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if emitDesktopBackendEvent(a.ctx, eventName, strings.Join(dataLines, "\n")) {
				sawEvent = true
			}
			eventName = "message"
			dataLines = dataLines[:0]
			continue
		}
		if strings.HasPrefix(line, "event:") {
			eventName = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			continue
		}
		if strings.HasPrefix(line, "data:") {
			dataLines = append(dataLines, strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		}
	}
	if err := scanner.Err(); err != nil {
		return sawEvent, fmt.Errorf("read event stream: %w", err)
	}
	return sawEvent, nil
}

func newDesktopEventHTTPClient() *http.Client {
	dialer := &net.Dialer{
		Timeout:   3 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	return &http.Client{
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           dialer.DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   3 * time.Second,
			ResponseHeaderTimeout: 5 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}

func emitDesktopBackendEvent(ctx context.Context, eventName string, rawData string) bool {
	runtimeEvent, payload, ok := parseDesktopBackendEvent(eventName, rawData)
	if !ok {
		return false
	}
	wruntime.EventsEmit(ctx, runtimeEvent, payload)
	return true
}

func parseDesktopBackendEvent(eventName string, rawData string) (string, any, bool) {
	eventName = strings.TrimSpace(eventName)
	if eventName == "" || eventName == "message" {
		return "", nil, false
	}
	var payload any = map[string]any{}
	if strings.TrimSpace(rawData) != "" {
		if err := json.Unmarshal([]byte(rawData), &payload); err != nil {
			payload = map[string]any{"message": rawData}
		}
	}
	return "gshark:backend:" + eventName, payload, true
}

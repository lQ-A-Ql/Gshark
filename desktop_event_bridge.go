//go:build dev || production || bindings

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

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
	rt := a.getBackendRuntime()
	if rt == nil {
		fmt.Fprintln(os.Stderr, "desktop events: backend runtime bridge skipped: runtime is not ready")
		return
	}
	for ev := range rt.Subscribe(ctx) {
		if ctx.Err() != nil {
			return
		}
		emitDesktopBackendRuntimeEvent(a.ctx, ev.Type, ev.Data)
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

func emitDesktopBackendRuntimeEvent(ctx context.Context, eventName string, payload any) bool {
	eventName = strings.TrimSpace(eventName)
	if eventName == "" || eventName == "message" {
		return false
	}
	wruntime.EventsEmit(ctx, "meow:backend:"+eventName, payload)
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
	return "meow:backend:" + eventName, payload, true
}

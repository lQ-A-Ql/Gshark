//go:build dev || production || bindings

package main

import (
	"context"
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

func emitDesktopBackendRuntimeEvent(ctx context.Context, eventName string, payload any) bool {
	runtimeEvent, ok := desktopBackendRuntimeEventName(eventName)
	if !ok {
		return false
	}
	wruntime.EventsEmit(ctx, runtimeEvent, payload)
	return true
}

func desktopBackendRuntimeEventName(eventName string) (string, bool) {
	eventName = strings.TrimSpace(eventName)
	if eventName == "" || eventName == "message" {
		return "", false
	}
	return "meow:backend:" + eventName, true
}

package miscpkg

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestInvokeJavaScriptDisablesDangerousGlobals(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "backend.js")
	if err := os.WriteFile(path, []byte(`export function onRequest() {
  return {
    evalType: typeof eval,
    functionType: typeof Function,
    requireType: typeof require,
    processType: typeof process,
    globalProcessType: typeof globalThis.process
  };
}`), 0o644); err != nil {
		t.Fatalf("write backend.js: %v", err)
	}

	result, err := invokeJavaScript(context.Background(), path, nil, InvokeContext{})
	if err != nil {
		t.Fatalf("invokeJavaScript() error = %v", err)
	}
	payload, ok := result.(map[string]any)
	if !ok {
		t.Fatalf("unexpected result type: %#v", result)
	}
	for key, value := range payload {
		if value != "undefined" {
			t.Fatalf("%s = %v, want undefined", key, value)
		}
	}
}

func TestInvokeJavaScriptReadTextStaysInsideModuleDir(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("secret"), 0o644); err != nil {
		t.Fatalf("write outside secret: %v", err)
	}
	path := filepath.Join(dir, "backend.js")
	if err := os.WriteFile(path, []byte(`export function onRequest(input, ctx) {
  return { text: ctx.readText("../secret.txt") };
}`), 0o644); err != nil {
		t.Fatalf("write backend.js: %v", err)
	}

	result, err := invokeJavaScript(context.Background(), path, nil, InvokeContext{})
	if err != nil {
		t.Fatalf("invokeJavaScript() error = %v", err)
	}
	payload, ok := result.(map[string]any)
	if !ok {
		t.Fatalf("unexpected result type: %#v", result)
	}
	if strings.Contains(strings.TrimSpace(asString(payload["text"])), "secret") {
		t.Fatalf("readText leaked outside module dir: %#v", result)
	}
}

func TestInvokeJavaScriptRunsInWorkerProcessWithMinimalEnv(t *testing.T) {
	t.Setenv("MEOW_TRAFFIC_BACKEND_TOKEN", "secret-token")
	dir := t.TempDir()
	path := filepath.Join(dir, "backend.js")
	workerProbePath := filepath.Join(dir, "probe.txt")
	if err := os.WriteFile(path, []byte(`export function onRequest() {
  return {
    pid: String(globalThis.workerPid || ""),
    tokenValue: String(globalThis.backendToken || "")
  };
}`), 0o644); err != nil {
		t.Fatalf("rewrite backend.js: %v", err)
	}
	oldExtraEnv := javascriptWorkerExtraEnv
	javascriptWorkerExtraEnv = []string{javascriptWorkerProbePathEnvVar + "=" + workerProbePath}
	t.Cleanup(func() { javascriptWorkerExtraEnv = oldExtraEnv })

	result, err := invokeJavaScript(context.Background(), path, nil, InvokeContext{})
	if err != nil {
		t.Fatalf("invokeJavaScript() error = %v", err)
	}
	payload, ok := result.(map[string]any)
	if !ok {
		t.Fatalf("unexpected result type: %#v", result)
	}
	workerPID, err := strconv.Atoi(strings.TrimSpace(asString(payload["pid"])))
	if err != nil {
		t.Fatalf("worker pid was not returned: %#v", payload)
	}
	if workerPID == os.Getpid() {
		t.Fatalf("javascript executed in backend process pid=%d", workerPID)
	}
	if payload["tokenValue"] != "" {
		t.Fatalf("backend token leaked to javascript worker: %#v", payload["tokenValue"])
	}
	if raw, err := os.ReadFile(workerProbePath); err != nil || strings.TrimSpace(string(raw)) != strconv.Itoa(workerPID) {
		t.Fatalf("worker probe file mismatch raw=%q err=%v", string(raw), err)
	}
}

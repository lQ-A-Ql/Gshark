package miscpkg

import (
	"context"
	"os"
	"path/filepath"
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

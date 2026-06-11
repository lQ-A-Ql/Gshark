package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

func TestPrintJSONAndUsageWriteExpectedText(t *testing.T) {
	out := captureStdout(t, func() {
		printJSON("demo", map[string]any{"ok": true})
	})
	if !strings.Contains(out, "demo:") || !strings.Contains(out, `"ok": true`) {
		t.Fatalf("printJSON output = %q", out)
	}

	out = captureStdout(t, usage)
	if !strings.Contains(out, "sentinel serve") || !strings.Contains(out, "sentinel parse") {
		t.Fatalf("usage output = %q", out)
	}
}

func TestResolveBackendAuthTokenUsesEnvOrGeneratesHex(t *testing.T) {
	t.Setenv("MEOW_TRAFFIC_BACKEND_TOKEN", "from-env")
	token, err := resolveBackendAuthToken()
	if err != nil || token != "from-env" {
		t.Fatalf("resolveBackendAuthToken env token=%q err=%v", token, err)
	}

	t.Setenv("MEOW_TRAFFIC_BACKEND_TOKEN", "")
	token, err = resolveBackendAuthToken()
	if err != nil {
		t.Fatalf("resolveBackendAuthToken generated error = %v", err)
	}
	if len(token) != 64 {
		t.Fatalf("generated token length = %d, want 64", len(token))
	}
	for _, r := range token {
		if !strings.ContainsRune("0123456789abcdef", r) {
			t.Fatalf("generated token contains non-hex rune %q in %q", r, token)
		}
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stdout: %v", err)
	}
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	return buf.String()
}

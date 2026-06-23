package miscpkg

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestMinimalPythonEnvDoesNotExposeBackendToken(t *testing.T) {
	t.Setenv("MEOW_TRAFFIC_BACKEND_TOKEN", "secret-token")
	t.Setenv("PATH", "C:/Tools")
	env := minimalPythonEnv("C:/helper", `{"ok":true}`)
	for _, item := range env {
		if strings.HasPrefix(item, "MEOW_TRAFFIC_BACKEND_TOKEN=") {
			t.Fatalf("backend token leaked into misc python env: %v", env)
		}
	}
	joined := strings.Join(env, "\n")
	for _, want := range []string{"PATH=", "PYTHONIOENCODING=utf-8", "PYTHONPATH=C:/helper", `MEOW_TRAFFIC_MISC_INPUT_JSON={"ok":true}`} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected env to contain %q, got %v", want, env)
		}
	}
}

func TestInvokePythonConsumesStderrConcurrently(t *testing.T) {
	pythonBin, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available in PATH")
	}
	if err := exec.Command(pythonBin, "--version").Run(); err != nil {
		t.Skipf("python is not executable in this environment: %v", err)
	}

	script := filepath.Join(t.TempDir(), "stderr_first.py")
	if err := os.WriteFile(script, []byte(`import sys
sys.stderr.write("x" * 262144)
sys.stderr.flush()
sys.stdin.read()
sys.stdout.write('{"message":"ok"}')
sys.stdout.flush()
`), 0o644); err != nil {
		t.Fatalf("write script: %v", err)
	}

	result, err := invokePython(context.Background(), script, map[string]any{"value": "demo"}, pythonBin)
	if err != nil {
		t.Fatalf("invokePython() error = %v", err)
	}
	payload, ok := result.(map[string]any)
	if !ok || payload["message"] != "ok" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

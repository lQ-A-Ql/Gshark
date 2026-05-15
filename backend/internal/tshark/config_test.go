package tshark

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestResolveBinary_UsesCustomDirectory(t *testing.T) {
	t.Cleanup(func() {
		SetBinaryPath("")
	})

	tempDir := t.TempDir()
	name := "tshark"
	if runtime.GOOS == "windows" {
		name = "tshark.exe"
	}
	target := filepath.Join(tempDir, name)
	if err := os.WriteFile(target, []byte(""), 0o755); err != nil {
		t.Fatalf("write fake tshark binary: %v", err)
	}

	SetBinaryPath(tempDir)
	resolved, err := ResolveBinary()
	if err != nil {
		t.Fatalf("ResolveBinary() error = %v", err)
	}
	if resolved != target {
		t.Fatalf("ResolveBinary() = %q, want %q", resolved, target)
	}
}

func TestCurrentStatus_InvalidCustomPath(t *testing.T) {
	t.Cleanup(func() {
		SetBinaryPath("")
	})

	originalDefaultCandidates := defaultWindowsTSharkCandidates
	defaultWindowsTSharkCandidates = nil
	t.Cleanup(func() {
		defaultWindowsTSharkCandidates = originalDefaultCandidates
	})

	t.Setenv("PATH", t.TempDir())
	SetBinaryPath(filepath.Join(t.TempDir(), "missing-tshark.exe"))
	status := CurrentStatus()
	if status.Available {
		t.Fatalf("expected unavailable status, got %+v", status)
	}
	if !status.UsingCustomPath {
		t.Fatalf("expected custom path flag, got %+v", status)
	}
	if status.CustomPath == "" {
		t.Fatalf("expected custom path to be echoed back, got %+v", status)
	}
}

func TestCurrentStatusWithContextHonorsCancellation(t *testing.T) {
	t.Cleanup(func() {
		SetBinaryPath("")
	})

	tempDir := t.TempDir()
	name := "tshark"
	if runtime.GOOS == "windows" {
		name = "tshark.exe"
	}
	target := filepath.Join(tempDir, name)
	if err := os.WriteFile(target, []byte(""), 0o755); err != nil {
		t.Fatalf("write fake tshark binary: %v", err)
	}
	SetBinaryPath(tempDir)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	status := CurrentStatusWithContext(ctx)
	if time.Since(start) > time.Second {
		t.Fatalf("CurrentStatusWithContext ignored cancellation, status=%+v", status)
	}
	if !status.CapabilityCheckDegraded {
		t.Fatalf("expected cancelled capability probe to be degraded, got %+v", status)
	}
}

func TestCurrentStatus_FallsBackToPathWhenCustomPathIsStale(t *testing.T) {
	t.Cleanup(func() {
		SetBinaryPath("")
	})

	tempDir := t.TempDir()
	name := "tshark"
	if runtime.GOOS == "windows" {
		name = "tshark.exe"
	}
	target := filepath.Join(tempDir, name)
	if err := os.WriteFile(target, []byte(""), 0o755); err != nil {
		t.Fatalf("write fake tshark binary: %v", err)
	}
	t.Setenv("PATH", tempDir)

	SetBinaryPath(filepath.Join(tempDir, "missing-tshark.exe"))
	status := CurrentStatus()
	if !status.Available {
		t.Fatalf("expected fallback status, got %+v", status)
	}
	if status.Path != target {
		t.Fatalf("expected fallback path %q, got %+v", target, status)
	}
	if status.UsingCustomPath {
		t.Fatalf("expected PATH fallback instead of custom path, got %+v", status)
	}
}

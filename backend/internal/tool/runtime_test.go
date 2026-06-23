package tool

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestRuntime_SetPathAndRevalidate(t *testing.T) {
	rt := NewRuntime("tshark", []string{"tshark"}, nil)

	warning, err := rt.SetPath("")
	if err != nil || warning != "" || rt.ConfiguredPath() != "" {
		t.Fatalf("empty path should clear configured path")
	}

	name := "tshark"
	if runtime.GOOS == "windows" {
		name = "tshark.exe"
	}

	dir := t.TempDir()
	bin := filepath.Join(dir, name)
	if err := writeFakeFile(bin); err != nil {
		t.Fatalf("write fake binary: %v", err)
	}

	warning, err = rt.SetPath(bin)
	if err != nil || warning == "" {
		t.Fatalf("expected warning for outside-dir binary, got err=%v warning=%q", err, warning)
	}

	// Allowing the directory removes the warning on revalidation.
	rt.AllowDir(dir)
	warning, err = rt.Revalidate()
	if err != nil || warning != "" {
		t.Fatalf("expected no warning after allow, got err=%v warning=%q", err, warning)
	}
}

func TestRuntime_AllowDirRemoveDir(t *testing.T) {
	rt := NewRuntime("tshark", []string{"tshark"}, nil)
	if !rt.AllowDir(`/usr/local/bin`) {
		t.Fatal("expected AllowDir to add new dir")
	}
	if rt.AllowDir(`/usr/local/bin`) {
		t.Fatal("expected AllowDir to skip duplicate")
	}
	if !rt.RemoveDir(`/usr/local/bin`) {
		t.Fatal("expected RemoveDir to remove existing dir")
	}
	if rt.RemoveDir(`/usr/local/bin`) {
		t.Fatal("expected RemoveDir to skip absent dir")
	}
}

func TestRuntime_ExtraAllowedDir(t *testing.T) {
	dir := t.TempDir()
	rt := NewRuntime("tshark", []string{"tshark"}, []string{dir})
	name := "tshark"
	if runtime.GOOS == "windows" {
		name = "tshark.exe"
	}
	bin := filepath.Join(dir, name)
	if err := writeFakeFile(bin); err != nil {
		t.Fatalf("write fake binary: %v", err)
	}
	if got := rt.ExtraAllowedDir(bin); got != filepath.Clean(dir) {
		t.Fatalf("ExtraAllowedDir(%q) = %q, want %q", bin, got, filepath.Clean(dir))
	}
}

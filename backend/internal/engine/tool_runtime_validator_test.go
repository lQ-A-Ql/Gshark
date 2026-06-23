package engine

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestValidateExecutablePath_AllowsEmptyAndValidPaths(t *testing.T) {
	t.Run("empty path", func(t *testing.T) {
		if err := ValidateExecutablePath("", []string{"tshark"}); err != nil {
			t.Fatalf("empty path should be valid, got %v", err)
		}
	})

	t.Run("absolute binary in extra allowed dir", func(t *testing.T) {
		dir := t.TempDir()
		name := "tshark"
		if runtime.GOOS == "windows" {
			name = "tshark.exe"
		}
		bin := filepath.Join(dir, name)
		mode := os.FileMode(0o755)
		if runtime.GOOS == "windows" {
			mode = 0o644
		}
		if err := os.WriteFile(bin, []byte("fake"), mode); err != nil {
			t.Fatalf("write fake binary: %v", err)
		}
		if err := ValidateExecutablePath(bin, []string{"tshark"}, dir); err != nil {
			t.Fatalf("valid binary should pass: %v", err)
		}
	})
}

func TestValidateExecutablePath_RejectsDangerousPaths(t *testing.T) {
	t.Run("relative path with directory component", func(t *testing.T) {
		if err := ValidateExecutablePath("../bin/tshark", []string{"tshark"}); err == nil {
			t.Fatal("expected relative path to be rejected")
		}
	})

	t.Run("absolute path outside allowed dirs", func(t *testing.T) {
		dir := t.TempDir()
		bin := filepath.Join(dir, "tshark")
		if err := os.WriteFile(bin, []byte("fake"), 0o755); err != nil {
			t.Fatalf("write fake binary: %v", err)
		}
		if err := ValidateExecutablePath(bin, []string{"tshark"}); err == nil {
			t.Fatal("expected absolute path outside allowed dirs to be rejected")
		}
	})

	t.Run("wrong basename", func(t *testing.T) {
		dir := t.TempDir()
		bin := filepath.Join(dir, "evil")
		if err := os.WriteFile(bin, []byte("fake"), 0o755); err != nil {
			t.Fatalf("write fake binary: %v", err)
		}
		if err := ValidateExecutablePath(bin, []string{"tshark"}, dir); err == nil {
			t.Fatal("expected wrong basename to be rejected")
		}
	})

	t.Run("script extension", func(t *testing.T) {
		dir := t.TempDir()
		bin := filepath.Join(dir, "tshark.sh")
		if err := os.WriteFile(bin, []byte("fake"), 0o755); err != nil {
			t.Fatalf("write fake script: %v", err)
		}
		if err := ValidateExecutablePath(bin, []string{"tshark"}, dir); err == nil {
			t.Fatal("expected script extension to be rejected")
		}
	})

	t.Run("directory", func(t *testing.T) {
		dir := t.TempDir()
		if err := ValidateExecutablePath(dir, []string{"tshark"}, dir); err == nil {
			t.Fatal("expected directory to be rejected")
		}
	})

	t.Run("symlink to outside allowed dir", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("skipping symlink test on windows")
		}
		allowed := t.TempDir()
		outside := t.TempDir()
		target := filepath.Join(outside, "tshark")
		link := filepath.Join(allowed, "tshark")
		if err := os.WriteFile(target, []byte("fake"), 0o755); err != nil {
			t.Fatalf("write target: %v", err)
		}
		if err := os.Symlink(target, link); err != nil {
			t.Fatalf("create symlink: %v", err)
		}
		if err := ValidateExecutablePath(link, []string{"tshark"}, allowed); err == nil {
			t.Fatal("expected symlink to outside dir to be rejected")
		}
	})
}

func TestValidateExecutablePath_NameOnlyRequiresPATH(t *testing.T) {
	t.Run("name not in PATH", func(t *testing.T) {
		if err := ValidateExecutablePath("tshark-not-in-path-xyz", []string{"tshark-not-in-path-xyz"}); err == nil {
			t.Fatal("expected missing PATH binary to be rejected")
		}
	})
}

func TestValidateExecutablePathWithWarning(t *testing.T) {
	name := "tshark"
	if runtime.GOOS == "windows" {
		name = "tshark.exe"
	}

	t.Run("empty path", func(t *testing.T) {
		warning, err := ValidateExecutablePathWithWarning("", []string{"tshark"})
		if err != nil || warning != "" {
			t.Fatalf("empty path should be valid without warning, got warning=%q err=%v", warning, err)
		}
	})

	t.Run("outside allowed dir returns warning", func(t *testing.T) {
		dir := t.TempDir()
		bin := filepath.Join(dir, name)
		if err := os.WriteFile(bin, []byte("fake"), 0o755); err != nil {
			t.Fatalf("write fake binary: %v", err)
		}
		warning, err := ValidateExecutablePathWithWarning(bin, []string{"tshark"})
		if err != nil {
			t.Fatalf("expected warning, got error: %v", err)
		}
		if warning == "" {
			t.Fatal("expected non-empty warning for binary outside allowed dirs")
		}
	})

	t.Run("inside extra allowed dir has no warning", func(t *testing.T) {
		dir := t.TempDir()
		bin := filepath.Join(dir, name)
		if err := os.WriteFile(bin, []byte("fake"), 0o755); err != nil {
			t.Fatalf("write fake binary: %v", err)
		}
		warning, err := ValidateExecutablePathWithWarning(bin, []string{"tshark"}, dir)
		if err != nil || warning != "" {
			t.Fatalf("expected no warning in extra allowed dir, got warning=%q err=%v", warning, err)
		}
	})

	t.Run("hard security errors still fail", func(t *testing.T) {
		warning, err := ValidateExecutablePathWithWarning("../evil/tshark", []string{"tshark"})
		if err == nil {
			t.Fatal("expected relative path to be rejected")
		}
		if warning != "" {
			t.Fatalf("expected no warning alongside hard error, got %q", warning)
		}
	})

	t.Run("script extension is an error not a warning", func(t *testing.T) {
		dir := t.TempDir()
		bin := filepath.Join(dir, "tshark.sh")
		if err := os.WriteFile(bin, []byte("fake"), 0o755); err != nil {
			t.Fatalf("write fake script: %v", err)
		}
		warning, err := ValidateExecutablePathWithWarning(bin, []string{"tshark"})
		if err == nil {
			t.Fatal("expected script extension to be rejected")
		}
		if warning != "" {
			t.Fatalf("expected no warning alongside hard error, got %q", warning)
		}
	})

	t.Run("name-only PATH reference has no warning", func(t *testing.T) {
		warning, err := ValidateExecutablePathWithWarning(name, []string{"tshark"})
		if err != nil {
			// PATH may not contain tshark on all test machines; that is still an error, not a warning.
			if warning != "" {
				t.Fatalf("expected no warning when PATH lookup fails, got %q", warning)
			}
			return
		}
		if warning != "" {
			t.Fatalf("expected no warning for PATH-resolved binary, got %q", warning)
		}
	})
}

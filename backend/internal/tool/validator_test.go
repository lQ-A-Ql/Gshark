package tool

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestExecutableValidator_AllowsEmptyAndValidPaths(t *testing.T) {
	v := NewExecutableValidator([]string{"tshark"}, nil, ModeStrict)

	t.Run("empty path", func(t *testing.T) {
		warning, err := v.Validate("")
		if err != nil || warning != "" {
			t.Fatalf("empty path should be valid, got warning=%q err=%v", warning, err)
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
		v := NewExecutableValidator([]string{"tshark"}, []string{dir}, ModeStrict)
		warning, err := v.Validate(bin)
		if err != nil || warning != "" {
			t.Fatalf("valid binary should pass: warning=%q err=%v", warning, err)
		}
	})
}

func TestExecutableValidator_RejectsDangerousPaths(t *testing.T) {
	v := NewExecutableValidator([]string{"tshark"}, nil, ModeStrict)

	t.Run("relative path with directory component", func(t *testing.T) {
		if _, err := v.Validate("../bin/tshark"); err == nil {
			t.Fatal("expected relative path to be rejected")
		}
	})

	t.Run("absolute path outside allowed dirs", func(t *testing.T) {
		dir := t.TempDir()
		bin := filepath.Join(dir, "tshark")
		if err := os.WriteFile(bin, []byte("fake"), 0o755); err != nil {
			t.Fatalf("write fake binary: %v", err)
		}
		if _, err := v.Validate(bin); err == nil {
			t.Fatal("expected absolute path outside allowed dirs to be rejected")
		}
	})

	t.Run("wrong basename", func(t *testing.T) {
		dir := t.TempDir()
		bin := filepath.Join(dir, "evil")
		if err := os.WriteFile(bin, []byte("fake"), 0o755); err != nil {
			t.Fatalf("write fake binary: %v", err)
		}
		v := NewExecutableValidator([]string{"tshark"}, []string{dir}, ModeStrict)
		if _, err := v.Validate(bin); err == nil {
			t.Fatal("expected wrong basename to be rejected")
		}
	})

	t.Run("script extension", func(t *testing.T) {
		dir := t.TempDir()
		bin := filepath.Join(dir, "tshark.sh")
		if err := os.WriteFile(bin, []byte("fake"), 0o755); err != nil {
			t.Fatalf("write fake script: %v", err)
		}
		v := NewExecutableValidator([]string{"tshark"}, []string{dir}, ModeStrict)
		if _, err := v.Validate(bin); err == nil {
			t.Fatal("expected script extension to be rejected")
		}
	})

	t.Run("directory", func(t *testing.T) {
		dir := t.TempDir()
		v := NewExecutableValidator([]string{"tshark"}, []string{dir}, ModeStrict)
		if _, err := v.Validate(dir); err == nil {
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
		v := NewExecutableValidator([]string{"tshark"}, []string{allowed}, ModeStrict)
		if _, err := v.Validate(link); err == nil {
			t.Fatal("expected symlink to outside dir to be rejected")
		}
	})
}

func TestExecutableValidator_NameOnlyRequiresPATH(t *testing.T) {
	v := NewExecutableValidator([]string{"tshark-not-in-path-xyz"}, nil, ModeStrict)
	if _, err := v.Validate("tshark-not-in-path-xyz"); err == nil {
		t.Fatal("expected missing PATH binary to be rejected")
	}
}

func TestExecutableValidatorWithWarning(t *testing.T) {
	name := "tshark"
	if runtime.GOOS == "windows" {
		name = "tshark.exe"
	}

	t.Run("empty path", func(t *testing.T) {
		v := NewExecutableValidator([]string{"tshark"}, nil, ModeWarn)
		warning, err := v.Validate("")
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
		v := NewExecutableValidator([]string{"tshark"}, nil, ModeWarn)
		warning, err := v.Validate(bin)
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
		v := NewExecutableValidator([]string{"tshark"}, []string{dir}, ModeWarn)
		warning, err := v.Validate(bin)
		if err != nil || warning != "" {
			t.Fatalf("expected no warning in extra allowed dir, got warning=%q err=%v", warning, err)
		}
	})

	t.Run("hard security errors still fail", func(t *testing.T) {
		v := NewExecutableValidator([]string{"tshark"}, nil, ModeWarn)
		warning, err := v.Validate("../evil/tshark")
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
		v := NewExecutableValidator([]string{"tshark"}, nil, ModeWarn)
		warning, err := v.Validate(bin)
		if err == nil {
			t.Fatal("expected script extension to be rejected")
		}
		if warning != "" {
			t.Fatalf("expected no warning alongside hard error, got %q", warning)
		}
	})
}

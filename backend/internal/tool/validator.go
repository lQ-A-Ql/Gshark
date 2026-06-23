package tool

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// ValidationMode controls how a validator reacts when a binary is outside the
// default trusted directories.
type ValidationMode int

const (
	// ModeStrict treats an outside-directory binary as a hard error.
	ModeStrict ValidationMode = iota
	// ModeWarn treats an outside-directory binary as a warning.
	ModeWarn
)

// ExecutableValidator validates external binary paths.
type ExecutableValidator struct {
	mode             ValidationMode
	expectedNames    map[string]struct{}
	extraAllowedDirs []string
}

// NewExecutableValidator creates a validator for the given acceptable basenames
// (without extension, case-insensitive) and extra allowed directories. An empty
// path is considered valid.
func NewExecutableValidator(expectedNames []string, extraAllowedDirs []string, mode ValidationMode) *ExecutableValidator {
	expected := make(map[string]struct{}, len(expectedNames))
	for _, n := range expectedNames {
		expected[strings.ToLower(strings.TrimSpace(n))] = struct{}{}
	}
	return &ExecutableValidator{
		mode:             mode,
		expectedNames:    expected,
		extraAllowedDirs: NormalizeAllowedDirs(extraAllowedDirs),
	}
}

// Validate checks path and returns a warning string and an error. When mode is
// ModeStrict, an outside-directory binary returns an error and an empty warning.
// When mode is ModeWarn, it returns a non-empty warning and a nil error. Hard
// security problems (wrong basename, forbidden script extension, relative path,
// symlink to invalid target) always return an error.
func (v *ExecutableValidator) Validate(path string) (warning string, err error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", nil
	}
	if len(v.expectedNames) == 0 {
		return "", errors.New("no expected binary names provided")
	}

	// Path contains a directory component but is not absolute => reject.
	if strings.ContainsAny(path, `/\`) && !filepath.IsAbs(path) {
		return "", errors.New("relative paths with directory components are not allowed")
	}

	// Name-only references (e.g. "tshark") are resolved through PATH.
	if !filepath.IsAbs(path) {
		resolved, lookErr := exec.LookPath(path)
		if lookErr != nil {
			return "", fmt.Errorf("binary %q not found in PATH", path)
		}
		return v.validateBinary(resolved, false, nil)
	}

	return v.validateBinary(path, true, v.extraAllowedDirs)
}

func (v *ExecutableValidator) validateBinary(path string, checkDir bool, extraAllowedDirs []string) (warning string, err error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("cannot access binary: %w", err)
	}
	if info.IsDir() {
		return "", errors.New("path points to a directory, not a binary")
	}

	base := strings.TrimSpace(filepath.Base(path))
	ext := strings.ToLower(filepath.Ext(base))
	name := strings.ToLower(strings.TrimSuffix(base, ext))
	if _, ok := v.expectedNames[name]; !ok {
		return "", fmt.Errorf("binary basename %q is not allowed (want one of %s)", base, joinExpectedNames(v.expectedNames))
	}
	if isForbiddenScriptExtension(ext) {
		return "", fmt.Errorf("script/interpreted file extension %q is not allowed", ext)
	}

	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("cannot resolve symlink: %w", err)
	}
	if resolved != filepath.Clean(path) {
		warning, err := v.validateBinary(resolved, checkDir, extraAllowedDirs)
		if err != nil {
			return "", fmt.Errorf("symlink target invalid: %w", err)
		}
		return warning, nil
	}

	if checkDir {
		if err := validateAllowedDirectory(resolved, extraAllowedDirs); err != nil {
			if v.mode == ModeWarn {
				return fmt.Sprintf("binary %q is outside the default trusted directories; add its directory to the allow-list to suppress this warning", resolved), nil
			}
			return "", err
		}
	}

	if runtime.GOOS != "windows" && info.Mode()&0111 == 0 {
		return "", errors.New("file is not executable")
	}

	return "", nil
}

func validateAllowedDirectory(path string, extraAllowedDirs []string) error {
	clean := filepath.Clean(path)
	dirs := append(defaultAllowedExecutableDirs(), extraAllowedDirs...)
	sep := string(filepath.Separator)
	for _, dir := range dirs {
		d := filepath.Clean(dir)
		if strings.HasPrefix(strings.ToLower(clean), strings.ToLower(d+sep)) || strings.EqualFold(clean, d) {
			return nil
		}
	}
	return fmt.Errorf("binary %q is outside allowed directories", path)
}

func defaultAllowedExecutableDirs() []string {
	if runtime.GOOS == "windows" {
		return []string{
			`C:\Program Files`,
			`C:\Program Files (x86)`,
			`C:\Windows\System32`,
			`C:\Windows\SysWOW64`,
			`C:\ffmpeg`,
			`C:\Python`,
		}
	}
	return []string{
		"/usr/bin",
		"/usr/local/bin",
		"/bin",
		"/sbin",
		"/usr/sbin",
		"/opt/homebrew/bin",
		"/opt/local/bin",
		"/snap/bin",
	}
}

func isForbiddenScriptExtension(ext string) bool {
	switch ext {
	case ".sh", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".py", ".pl", ".rb", ".php":
		return true
	}
	return false
}

func joinExpectedNames(expected map[string]struct{}) string {
	names := make([]string, 0, len(expected))
	for n := range expected {
		names = append(names, n)
	}
	return strings.Join(names, ", ")
}

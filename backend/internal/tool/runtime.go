package tool

import (
	"strings"
	"sync"
)

// Runtime holds the configured path and allowed-directory list for a single
// external tool. It provides a reusable pipeline for setting, allowing,
// removing, and re-validating a binary path.
type Runtime struct {
	mu             sync.RWMutex
	name           string
	expectedNames  []string
	configuredPath string
	pathWarning    string
	allowedDirs    *AllowedDirList
	validator      *ExecutableValidator
}

// NewRuntime creates a tool runtime for the named tool with acceptable
// basenames (without extension, case-insensitive).
func NewRuntime(name string, expectedNames []string, initialAllowedDirs []string) *Runtime {
	rt := &Runtime{
		name:          name,
		expectedNames: append([]string(nil), expectedNames...),
		allowedDirs:   NewAllowedDirList(initialAllowedDirs),
	}
	rt.updateValidator()
	return rt
}

// Name returns the tool name.
func (rt *Runtime) Name() string {
	return rt.name
}

// ConfiguredPath returns the currently configured binary path.
func (rt *Runtime) ConfiguredPath() string {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return rt.configuredPath
}

// PathWarning returns the current warning for the configured path.
func (rt *Runtime) PathWarning() string {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return rt.pathWarning
}

// AllowedDirs returns a snapshot of the allowed directories.
func (rt *Runtime) AllowedDirs() []string {
	return rt.allowedDirs.All()
}

// SetAllowedDirs replaces the allowed-directory list and re-creates the
// validator.
func (rt *Runtime) SetAllowedDirs(dirs []string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.allowedDirs = NewAllowedDirList(dirs)
	rt.updateValidatorLocked()
}

// SetPath validates and stores a configured binary path. An empty path clears
// the stored path. A path that produces a hard validation error is not stored
// and the previous configured path is preserved.
func (rt *Runtime) SetPath(path string) (warning string, err error) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	trimmed := normalizeConfiguredPath(path)
	if trimmed == "" {
		rt.configuredPath = ""
		rt.pathWarning = ""
		return "", nil
	}

	warning, err = rt.validator.Validate(trimmed)
	if err != nil {
		rt.pathWarning = ""
		return "", err
	}
	rt.configuredPath = trimmed
	rt.pathWarning = warning
	return warning, nil
}

// ClearPath removes the configured path and its warning.
func (rt *Runtime) ClearPath() {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.configuredPath = ""
	rt.pathWarning = ""
}

// AllowDir adds a directory to the allow-list.
func (rt *Runtime) AllowDir(dir string) bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	changed := rt.allowedDirs.Add(dir)
	if changed {
		rt.updateValidatorLocked()
	}
	return changed
}

// RemoveDir deletes a directory from the allow-list.
func (rt *Runtime) RemoveDir(dir string) bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	changed := rt.allowedDirs.Remove(dir)
	if changed {
		rt.updateValidatorLocked()
	}
	return changed
}

// Revalidate re-checks the currently configured path against the current
// allowed directories and returns any warning or hard error. It updates the
// stored PathWarning.
func (rt *Runtime) Revalidate() (warning string, err error) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	if rt.configuredPath == "" {
		rt.pathWarning = ""
		return "", nil
	}
	warning, err = rt.validator.Validate(rt.configuredPath)
	if err != nil {
		rt.pathWarning = ""
		return "", err
	}
	rt.pathWarning = warning
	return warning, nil
}

// ExtraAllowedDir returns the allowed directory that matches the configured
// binary's location, if any.
func (rt *Runtime) ExtraAllowedDir(path string) string {
	return rt.allowedDirs.MatchingDir(path)
}

func (rt *Runtime) updateValidator() {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.validator = NewExecutableValidator(rt.expectedNames, rt.allowedDirs.All(), ModeWarn)
}

func (rt *Runtime) updateValidatorLocked() {
	rt.validator = NewExecutableValidator(rt.expectedNames, rt.allowedDirs.All(), ModeWarn)
}

func normalizeConfiguredPath(path string) string {
	return strings.TrimSpace(path)
}

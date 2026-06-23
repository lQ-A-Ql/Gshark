package tool

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// AllowedDirList is a thread-safe list of directories that may host external
// tool binaries. It stores normalized, de-duplicated paths.
type AllowedDirList struct {
	mu   sync.RWMutex
	dirs []string
}

// NewAllowedDirList creates an allowed-directory list from initial values.
func NewAllowedDirList(initial []string) *AllowedDirList {
	return &AllowedDirList{dirs: NormalizeAllowedDirs(initial)}
}

// All returns a snapshot of the allowed directories.
func (a *AllowedDirList) All() []string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return append([]string(nil), a.dirs...)
}

// Add inserts a directory if it is non-empty and not already present. It
// returns true when the list changed.
func (a *AllowedDirList) Add(dir string) bool {
	clean := NormalizeAllowedDir(dir)
	if clean == "" {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, existing := range a.dirs {
		if strings.EqualFold(filepath.Clean(existing), clean) {
			return false
		}
	}
	a.dirs = append(a.dirs, clean)
	return true
}

// Remove deletes a directory from the list (case-insensitive). It returns true
// when the list changed.
func (a *AllowedDirList) Remove(dir string) bool {
	clean := NormalizeAllowedDir(dir)
	if clean == "" {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	changed := false
	filtered := a.dirs[:0]
	for _, existing := range a.dirs {
		if strings.EqualFold(filepath.Clean(existing), clean) {
			changed = true
			continue
		}
		filtered = append(filtered, existing)
	}
	a.dirs = filtered
	return changed
}

// Contains reports whether path is located inside (or equal to) any allowed
// directory.
func (a *AllowedDirList) Contains(path string) bool {
	clean := filepath.Clean(path)
	a.mu.RLock()
	defer a.mu.RUnlock()
	sep := string(filepath.Separator)
	for _, dir := range a.dirs {
		d := filepath.Clean(dir)
		if strings.HasPrefix(strings.ToLower(clean), strings.ToLower(d+sep)) || strings.EqualFold(clean, d) {
			return true
		}
	}
	return false
}

// MatchingDir returns the allowed directory that contains path, or an empty
// string if none matches. If path points to a file, its parent directory is
// checked. A parent allow-list entry is considered a match so status payloads
// can explain which configured directory suppressed a path warning.
func (a *AllowedDirList) MatchingDir(path string) string {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return ""
	}
	if !filepath.IsAbs(trimmed) {
		return ""
	}
	info, err := osStat(trimmed)
	if err != nil {
		return ""
	}
	checkPath := trimmed
	if !info.IsDir() {
		checkPath = filepath.Dir(trimmed)
	}

	a.mu.RLock()
	defer a.mu.RUnlock()
	checkPath = filepath.Clean(checkPath)
	sep := string(filepath.Separator)
	for _, d := range a.dirs {
		clean := filepath.Clean(d)
		if strings.EqualFold(clean, checkPath) ||
			strings.HasPrefix(strings.ToLower(checkPath), strings.ToLower(clean+sep)) {
			return clean
		}
	}
	return ""
}

// osStat is a test seam for file-system metadata.
var osStat = func(path string) (fileInfo, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	return info, nil
}

type fileInfo interface {
	IsDir() bool
}

// NormalizeAllowedDir cleans a single allowed directory. It returns an empty
// string for invalid or root-only values.
func NormalizeAllowedDir(dir string) string {
	trimmed := strings.TrimSpace(dir)
	if trimmed == "" {
		return ""
	}
	if isRootOnlyPath(trimmed) {
		return ""
	}
	clean := filepath.Clean(trimmed)
	if isRootOnlyPath(clean) {
		return ""
	}
	return clean
}

func isRootOnlyPath(clean string) bool {
	if clean == "." || clean == "/" || clean == `\` {
		return true
	}
	volume := filepath.VolumeName(clean)
	if volume == "" {
		return false
	}
	rest := strings.TrimPrefix(clean, volume)
	return rest == "" || rest == string(filepath.Separator) || rest == "/" || rest == `\`
}

// NormalizeAllowedDirs de-duplicates and cleans a slice of allowed directories.
func NormalizeAllowedDirs(dirs []string) []string {
	seen := make(map[string]struct{}, len(dirs))
	out := make([]string, 0, len(dirs))
	for _, d := range dirs {
		clean := NormalizeAllowedDir(d)
		if clean == "" {
			continue
		}
		key := strings.ToLower(clean)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, clean)
	}
	return out
}

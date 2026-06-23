package transport

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// SafePathUnder returns the cleaned, absolute path for candidate if it is
// contained within base. Both base and candidate are cleaned with
// filepath.Clean. If base is empty, candidate is simply cleaned and returned.
// The function rejects paths that escape the base directory, contain NUL
// bytes, or are empty.
func SafePathUnder(base, candidate string) (string, error) {
	if strings.ContainsAny(candidate, "\x00") {
		return "", errors.New("path contains invalid character")
	}
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return "", errors.New("path is empty")
	}

	cleanCandidate := filepath.Clean(candidate)
	if !filepath.IsAbs(cleanCandidate) {
		return "", fmt.Errorf("path %q is not absolute", candidate)
	}

	if base == "" {
		return cleanCandidate, nil
	}

	cleanBase := filepath.Clean(base)
	sep := string(filepath.Separator)
	prefix := cleanBase + sep
	if !strings.HasPrefix(strings.ToLower(cleanCandidate), strings.ToLower(prefix)) &&
		!strings.EqualFold(cleanCandidate, cleanBase) {
		return "", fmt.Errorf("path %q escapes base directory %q", candidate, cleanBase)
	}
	return cleanCandidate, nil
}

// IsSafeFilePath returns true if path is either an absolute path without
// traversal components or a simple relative path. It rejects empty input,
// NUL bytes, and parent-directory references.
func IsSafeFilePath(path string) bool {
	path = strings.TrimSpace(path)
	if path == "" {
		return false
	}
	if strings.ContainsAny(path, "\x00") {
		return false
	}
	if filepath.IsAbs(path) || filepath.VolumeName(path) != "" {
		_, err := SafePathUnder("", path)
		return err == nil
	}
	return IsSafeRelativePath(path)
}

// IsSafeRelativePath returns true if path is a simple relative path that does
// not contain path traversal components. It is intended for filenames or
// one-level relative identifiers, not arbitrary filesystem paths.
func IsSafeRelativePath(path string) bool {
	path = strings.TrimSpace(path)
	if path == "" {
		return false
	}
	if strings.ContainsAny(path, "\x00") {
		return false
	}
	// Reject any input that looks absolute or contains a parent reference.
	if filepath.VolumeName(path) != "" || strings.HasPrefix(path, "/") || strings.HasPrefix(path, string(filepath.Separator)) {
		return false
	}
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		if part == ".." {
			return false
		}
	}
	clean := filepath.Clean(path)
	return !filepath.IsAbs(clean)
}

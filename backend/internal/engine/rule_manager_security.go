package engine

import (
	"fmt"
	"io"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
)

var rulePackIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

func validateRulePackID(packID string) error {
	packID = strings.TrimSpace(packID)
	if packID == "" {
		return fmt.Errorf("pack_id is required")
	}
	if len(packID) > 128 {
		return fmt.Errorf("pack_id exceeds maximum length")
	}
	if !rulePackIDPattern.MatchString(packID) {
		return fmt.Errorf("invalid pack_id: %q", packID)
	}
	return nil
}

func safeCachePath(cacheDir, packID string) (string, error) {
	cacheDir = filepath.Clean(cacheDir)
	cachePath := filepath.Join(cacheDir, packID+".yar")
	cleanPath := filepath.Clean(cachePath)
	sep := string(filepath.Separator)
	if !(strings.HasPrefix(cleanPath, cacheDir+sep) || cleanPath == cacheDir) {
		return "", fmt.Errorf("pack cache path escapes cache directory: %s", cachePath)
	}
	return cachePath, nil
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if strings.Contains(host, "://") {
		parsed, err := url.Parse(host)
		if err != nil {
			return ""
		}
		if hostname := strings.TrimSpace(parsed.Hostname()); hostname != "" {
			return strings.ToLower(hostname)
		}
	}
	if strings.HasPrefix(host, "[") {
		if idx := strings.Index(host, "]"); idx > 0 {
			return strings.ToLower(strings.TrimSpace(host[1:idx]))
		}
	}
	if unbracketed, _, err := net.SplitHostPort(host); err == nil {
		return strings.ToLower(strings.Trim(unbracketed, "[]"))
	}
	if strings.Count(host, ":") == 1 {
		if h, p, ok := strings.Cut(host, ":"); ok && isDecimalPort(p) {
			return strings.ToLower(strings.TrimSpace(h))
		}
	}
	return strings.ToLower(strings.TrimSpace(host))
}

func isDecimalPort(port string) bool {
	port = strings.TrimSpace(port)
	if port == "" {
		return false
	}
	for _, c := range port {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func isAllowedRuleHost(host string, allowed []string) bool {
	host = normalizeHost(host)
	if host == "" {
		return false
	}
	for _, a := range allowed {
		if host == normalizeHost(a) {
			return true
		}
	}
	return false
}

func validateRuleDownloadURL(rawURL string, allowedHosts []string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return nil, fmt.Errorf("invalid download URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("invalid download URL scheme: %q", rawURL)
	}
	if !isAllowedRuleHost(parsed.Hostname(), allowedHosts) {
		return nil, fmt.Errorf("download host %q is not in allowlist", parsed.Host)
	}
	return parsed, nil
}

func validateRuleChecksum(checksum string) error {
	checksum = strings.TrimSpace(checksum)
	if checksum == "" {
		return fmt.Errorf("checksum is required")
	}
	if len(checksum) != 64 {
		return fmt.Errorf("invalid checksum length")
	}
	for _, c := range checksum {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return fmt.Errorf("invalid checksum characters")
		}
	}
	return nil
}

func readLimitedRulePack(r io.Reader, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, fmt.Errorf("rule pack size limit must be positive")
	}
	body, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("rule pack exceeds %d bytes", maxBytes)
	}
	return body, nil
}

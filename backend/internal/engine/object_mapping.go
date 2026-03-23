package engine

import (
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

var (
	contentDispositionNameRE = regexp.MustCompile(`(?i)filename\*?=(?:UTF-8''|utf-8''|\"?)([^\";\r\n]+)`)
	fileNameTokenRE          = regexp.MustCompile(`(?i)\b([A-Za-z0-9._-]+\.[A-Za-z0-9]{1,10})\b`)
	dupSuffixRE              = regexp.MustCompile(`(?i)^(.*)\s*\(\d+\)(\.[a-z0-9]{1,10})$`)
)

func buildPacketIDByObjectName(packets []model.Packet) map[string]int64 {
	result := make(map[string]int64, len(packets))
	for _, packet := range packets {
		addPacketObjectCandidates(result, packet)
	}
	return result
}

func buildPacketIDByObjectNameFromIterate(iterate func(func(model.Packet) error) error) map[string]int64 {
	result := map[string]int64{}
	if iterate == nil {
		return result
	}
	_ = iterate(func(packet model.Packet) error {
		addPacketObjectCandidates(result, packet)
		return nil
	})
	return result
}

func addPacketObjectCandidates(result map[string]int64, packet model.Packet) {
	for _, candidate := range extractPacketObjectCandidates(packet.Info, packet.Payload) {
		key := normalizeObjectLookupKey(candidate)
		if key == "" {
			continue
		}
		if _, exists := result[key]; exists {
			continue
		}
		result[key] = packet.ID
	}
}

func extractPacketObjectCandidates(info, payload string) []string {
	text := info + "\n" + payload
	seen := map[string]struct{}{}
	out := make([]string, 0, 8)
	add := func(v string) {
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		if v == "" {
			return
		}
		if decoded, err := url.PathUnescape(v); err == nil && decoded != "" {
			v = decoded
		}
		v = path.Base(strings.ReplaceAll(v, "\\", "/"))
		if v == "" || v == "." || v == "/" {
			return
		}
		if _, ok := seen[v]; ok {
			return
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}

	for _, m := range contentDispositionNameRE.FindAllStringSubmatch(text, -1) {
		if len(m) > 1 {
			add(m[1])
		}
	}

	for _, m := range fileNameTokenRE.FindAllStringSubmatch(text, -1) {
		if len(m) > 1 {
			add(m[1])
		}
	}

	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		method := strings.ToUpper(fields[0])
		switch method {
		case "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH":
			uri := fields[1]
			if i := strings.IndexAny(uri, "?#"); i >= 0 {
				uri = uri[:i]
			}
			if uri != "" {
				add(uri)
			}
		}
	}

	return out
}

func normalizeObjectLookupKey(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	if decoded, err := url.PathUnescape(name); err == nil && decoded != "" {
		name = decoded
	}
	name = strings.ReplaceAll(name, "\\", "/")
	name = path.Base(name)
	if i := strings.IndexAny(name, "?#"); i >= 0 {
		name = name[:i]
	}
	name = strings.TrimSpace(name)
	if m := dupSuffixRE.FindStringSubmatch(name); len(m) == 3 {
		name = strings.TrimSpace(m[1]) + m[2]
	}
	return strings.ToLower(name)
}

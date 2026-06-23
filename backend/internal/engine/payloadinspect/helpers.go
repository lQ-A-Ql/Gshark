package payloadinspect

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"unicode/utf8"
)

var (
	base64CandidatePattern = regexp.MustCompile(`[A-Za-z0-9+/_-]{16,}={0,2}`)
	multipartNamePattern   = regexp.MustCompile(`name="([^"]+)"`)
	httpMethodPrefixes     = []string{"GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS ", "CONNECT ", "TRACE "}
)

func normalizeTransportPayload(raw string) string {
	candidate := strings.TrimSpace(raw)
	if candidate == "" {
		return ""
	}
	if looksLikeHTTPMessage(candidate) {
		candidate = strings.TrimSpace(extractHTTPMessageBody(candidate))
	}
	if text, ok := unwrapHexEncodedText(candidate); ok {
		candidate = text
	}
	return strings.TrimSpace(candidate)
}

func extractHTTPMessageBody(raw string) string {
	if idx := strings.Index(raw, "\r\n\r\n"); idx >= 0 {
		return raw[idx+4:]
	}
	if idx := strings.Index(raw, "\n\n"); idx >= 0 {
		return raw[idx+2:]
	}
	return raw
}

func looksLikeHTTPMessage(raw string) bool {
	text := strings.TrimSpace(raw)
	if text == "" {
		return false
	}
	if strings.HasPrefix(text, "HTTP/") {
		return true
	}
	for _, method := range httpMethodPrefixes {
		if strings.HasPrefix(text, method) {
			return true
		}
	}
	return strings.Contains(text, "\r\nHost:") || strings.Contains(text, "\nHost:")
}

func extractHTTPHeaderIgnoreCase(headers, name string) string {
	nameLower := strings.ToLower(name)
	lines := strings.Split(strings.ReplaceAll(headers, "\r\n", "\n"), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if idx := strings.Index(line, ":"); idx > 0 {
			key := strings.TrimSpace(line[:idx])
			if strings.ToLower(key) == nameLower {
				return strings.TrimSpace(line[idx+1:])
			}
		}
	}
	return ""
}

func extractBestBase64Candidate(raw string) string {
	candidate := strings.TrimSpace(raw)
	if candidate == "" {
		return ""
	}
	if scoreBase64Candidate(candidate) >= 70 {
		return candidate
	}
	matches := base64CandidatePattern.FindAllString(candidate, -1)
	best := ""
	bestScore := -1
	for _, item := range matches {
		if item != candidate && isAlphaNumericOnly(item) {
			continue
		}
		score := scoreBase64Candidate(item)
		if score > bestScore {
			best = item
			bestScore = score
		}
	}
	if bestScore >= 70 {
		return best
	}
	return candidate
}

func isAlphaNumericOnly(raw string) bool {
	if raw == "" {
		return false
	}
	for _, c := range raw {
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') {
			return false
		}
	}
	return true
}

func scoreBase64Candidate(raw string) int {
	candidate := strings.TrimSpace(raw)
	if candidate == "" {
		return -1
	}
	if strings.ContainsAny(candidate, "{}[]()\\|;,'\"` ") {
		return -1
	}
	if len(candidate) < 16 {
		return -1
	}
	score := 0
	if len(candidate)%4 == 0 {
		score += 30
	}
	if strings.HasSuffix(candidate, "=") {
		score += 10
	}
	if decoded, err := decodeBase64Loose(candidate); err == nil {
		if len(decoded) == 0 {
			return -1
		}
		score += 40
		ratio := float64(len(decoded)) / float64(len(candidate))
		if ratio >= 0.45 && ratio <= 0.8 {
			score += 10
		}
	} else {
		return -1
	}
	if strings.ContainsAny(candidate, "+/") {
		score += 10
	}
	if strings.ContainsAny(candidate, "-_") {
		score += 5
	}
	return score
}

func isPureHexToken(raw string) bool {
	candidate := strings.TrimSpace(raw)
	if candidate == "" {
		return false
	}
	cleaned := strings.NewReplacer(":", "", " ", "", "\t", "", "\r", "", "\n", "").Replace(candidate)
	if len(cleaned) < 16 || len(cleaned)%2 != 0 {
		return false
	}
	for _, c := range cleaned {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func unwrapHexEncodedText(raw string) (string, bool) {
	candidate := strings.TrimSpace(raw)
	if !isLikelyWrappedHexText(candidate) {
		return "", false
	}
	decoded := decodeLooseHex(candidate)
	if len(decoded) == 0 {
		return "", false
	}
	trimmed := strings.Trim(decodedString(decoded), "\x00")
	if len(trimmed) == 0 {
		return "", false
	}
	trimmedBytes := []byte(trimmed)
	if utf8.Valid(trimmedBytes) || looksMostlyPrintable(trimmedBytes) {
		return trimmed, true
	}
	return "", false
}

func isLikelyWrappedHexText(raw string) bool {
	candidate := strings.TrimSpace(raw)
	if candidate == "" {
		return false
	}
	if looksLikeHTTPMessage(candidate) {
		return false
	}
	if strings.ContainsAny(candidate, "=&?") {
		return false
	}
	cleaned := strings.NewReplacer(":", "", " ", "", "\t", "", "\r", "", "\n", "").Replace(candidate)
	if len(cleaned) < 16 || len(cleaned)%2 != 0 {
		return false
	}
	if !isPureHexToken(cleaned) {
		return false
	}
	return true
}

func looksMostlyPrintable(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	printable := 0
	for _, b := range data {
		if b == '\r' || b == '\n' || b == '\t' || (b >= 32 && b <= 126) {
			printable++
		}
	}
	return printable*100/len(data) >= 85
}

func decodeBase64Loose(raw string) ([]byte, error) {
	candidate := strings.TrimSpace(raw)
	candidate = strings.NewReplacer("\r", "", "\n", "", "\t", "", " ", "").Replace(candidate)
	candidate = strings.ReplaceAll(candidate, "-", "+")
	candidate = strings.ReplaceAll(candidate, "_", "/")
	if mod := len(candidate) % 4; mod != 0 {
		candidate += strings.Repeat("=", 4-mod)
	}

	for _, encoding := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		if decoded, err := encoding.DecodeString(candidate); err == nil && len(decoded) > 0 {
			return decoded, nil
		}
	}
	return nil, errors.New("base64 decode failed")
}

func decodeLooseHex(raw string) []byte {
	cleaned := strings.NewReplacer(":", "", " ", "", "\t", "", "\r", "", "\n", "").Replace(strings.TrimSpace(raw))
	if len(cleaned) == 0 || len(cleaned)%2 != 0 {
		return nil
	}
	decoded, err := hex.DecodeString(cleaned)
	if err != nil {
		return nil
	}
	return decoded
}

func decodedString(decoded []byte) string {
	return string(decoded)
}

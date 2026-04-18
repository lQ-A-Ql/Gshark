package engine

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

type StreamDecodeRequest struct {
	Decoder string         `json:"decoder"`
	Payload string         `json:"payload"`
	Options map[string]any `json:"options"`
}

type StreamDecodeResult struct {
	Decoder  string `json:"decoder"`
	Summary  string `json:"summary"`
	Text     string `json:"text"`
	BytesHex string `json:"bytes_hex"`
	Encoding string `json:"encoding"`
}

var (
	base64CandidatePattern = regexp.MustCompile(`[A-Za-z0-9+/=_-]{12,}`)
	multipartNamePattern   = regexp.MustCompile(`name="([^"]+)"`)
)

func DecodeStreamPayload(req StreamDecodeRequest) (StreamDecodeResult, error) {
	decoder := strings.ToLower(strings.TrimSpace(req.Decoder))
	switch decoder {
	case "base64":
		return decodeBase64Payload(req.Payload)
	case "behinder":
		return decodeBehinderPayload(req.Payload, req.Options)
	case "antsword":
		return decodeAntSwordPayload(req.Payload, req.Options)
	case "godzilla":
		return decodeGodzillaPayload(req.Payload, req.Options)
	case "auto":
		return autoDetectDecode(req.Payload, req.Options)
	default:
		return StreamDecodeResult{}, fmt.Errorf("unsupported decoder: %s", req.Decoder)
	}
}

func decodeBase64Payload(raw string) (StreamDecodeResult, error) {
	candidate := extractBasePayload(raw)
	decoded, err := decodeBase64Loose(extractBestBase64Candidate(candidate))
	if err != nil {
		return StreamDecodeResult{}, err
	}
	return buildDecodeResult("base64", "Base64 自动解码", decoded, "base64"), nil
}

func decodeBehinderPayload(raw string, options map[string]any) (StreamDecodeResult, error) {
	// Check if CBC mode is requested — delegate to CBC handler
	cipherMode := strings.ToLower(strings.TrimSpace(optionsStringDefault(options, "cipherMode", "ecb")))
	if cipherMode == "cbc" {
		return decodeBehinderPayloadCBC(raw, options)
	}

	candidate := extractPayloadCandidate(raw, optionsString(options, "pass"), optionsBool(options, "extractParam"))
	if candidate == "" {
		return StreamDecodeResult{}, errors.New("未提取到冰蝎密文")
	}
	candidate = applyURLDecodeRounds(candidate, optionsIntDefault(options, "urlDecodeRounds", 0))

	key := strings.TrimSpace(optionsString(options, "key"))
	if key == "" && optionsBoolDefault(options, "deriveKeyFromPass", true) {
		sum := md5.Sum([]byte(optionsString(options, "pass")))
		key = string(sum[:16])
	}
	if key == "" {
		return StreamDecodeResult{}, errors.New("冰蝎解密需要 key 或 pass")
	}

	cipherBytes, encoding, err := decodeCipherInput(candidate, optionsStringDefault(options, "inputEncoding", "auto"))
	if err != nil {
		return StreamDecodeResult{}, err
	}

	// Use lenient unpadding for better CTF compatibility
	plain, err := decryptAESECBLenient(cipherBytes, []byte(key))
	if err != nil {
		return StreamDecodeResult{}, err
	}

	summary := "冰蝎 AES-ECB 解密"
	if optionsBoolDefault(options, "deriveKeyFromPass", true) && optionsString(options, "pass") != "" && optionsString(options, "key") == "" {
		summary += " (key <- md5(pass)[:16])"
	}
	return buildDecodeResult("behinder", summary, plain, encoding), nil
}

func decodeAntSwordPayload(raw string, options map[string]any) (StreamDecodeResult, error) {
	candidate := extractPayloadCandidate(raw, optionsString(options, "pass"), optionsBool(options, "extractParam"))
	if candidate == "" {
		return StreamDecodeResult{}, errors.New("未提取到蚁剑载荷")
	}

	rounds := optionsIntDefault(options, "urlDecodeRounds", 1)
	for i := 0; i < rounds; i++ {
		decoded, err := url.QueryUnescape(candidate)
		if err != nil {
			break
		}
		candidate = decoded
	}

	// Try chr() decoding first
	if chrDecoded, ok := decodeAntSwordChr(candidate); ok {
		return buildDecodeResult("antsword", "蚁剑 chr() 解码", []byte(chrDecoded), "chr"), nil
	}

	// Try rot13
	encoder := strings.ToLower(strings.TrimSpace(optionsStringDefault(options, "encoder", "")))
	if encoder == "rot13" {
		rot13Result := decodeRot13(candidate)
		return buildDecodeResult("antsword", "蚁剑 ROT13 解码", []byte(rot13Result), "rot13"), nil
	}

	best := extractBestBase64Candidate(candidate)
	decoded, err := decodeBase64Loose(best)
	if err != nil {
		return buildDecodeResult("antsword", "蚁剑 URL 解码结果", []byte(candidate), "plain"), nil
	}
	return buildDecodeResult("antsword", "蚁剑 Base64 解码", decoded, "base64"), nil
}

func decodeGodzillaPayload(raw string, options map[string]any) (StreamDecodeResult, error) {
	candidate := extractPayloadCandidate(raw, optionsString(options, "pass"), optionsBool(options, "extractParam"))
	if candidate == "" {
		return StreamDecodeResult{}, errors.New("未提取到哥斯拉载荷")
	}
	candidate = applyURLDecodeRounds(candidate, optionsIntDefault(options, "urlDecodeRounds", 0))

	if optionsBoolDefault(options, "stripMarkers", true) {
		candidate = stripGodzillaMarkers(candidate, optionsString(options, "pass"), optionsString(options, "key"))
	}

	cipherBytes, encoding, err := decodeCipherInput(candidate, optionsStringDefault(options, "inputEncoding", "auto"))
	if err != nil {
		return StreamDecodeResult{}, err
	}

	key := strings.TrimSpace(optionsString(options, "key"))
	if key == "" {
		return StreamDecodeResult{}, errors.New("哥斯拉解密需要 key")
	}

	cipherMode := strings.ToLower(strings.TrimSpace(optionsStringDefault(options, "cipher", "aes_ecb")))
	pass := optionsString(options, "pass")
	var plain []byte
	switch cipherMode {
	case "xor":
		// Godzilla PHP XOR: key = md5(pass+key)[:16]
		xorKey := deriveGodzillaXORKey(pass, key)
		plain = xorBytes(cipherBytes, xorKey)
	case "aes", "aes_ecb":
		plain, err = decryptAESECBLenient(cipherBytes, normalizeAESKey([]byte(key)))
		if err != nil {
			return StreamDecodeResult{}, err
		}
	case "aes_cbc":
		var iv []byte
		if ivStr := strings.TrimSpace(optionsString(options, "iv")); ivStr != "" {
			iv = []byte(ivStr)
		}
		plain, err = decryptAESCBC(cipherBytes, []byte(key), iv)
		if err != nil {
			return StreamDecodeResult{}, err
		}
	default:
		return StreamDecodeResult{}, fmt.Errorf("unsupported godzilla cipher: %s", cipherMode)
	}

	return buildDecodeResult("godzilla", fmt.Sprintf("哥斯拉流量解密 (%s)", cipherMode), plain, encoding), nil
}

func buildDecodeResult(decoder, summary string, data []byte, encoding string) StreamDecodeResult {
	return StreamDecodeResult{
		Decoder:  decoder,
		Summary:  summary,
		Text:     bytesToDisplayText(data),
		BytesHex: bytesToColonHex(data),
		Encoding: encoding,
	}
}

func extractPayloadCandidate(raw, pass string, extractParam bool) string {
	candidate := normalizeTransportPayload(raw)
	if !extractParam || strings.TrimSpace(pass) == "" {
		if !extractParam {
			return candidate
		}
		if extracted, ok := extractPayloadParam(candidate, ""); ok {
			return extracted
		}
		return candidate
	}
	if extracted, ok := extractPayloadParam(candidate, pass); ok {
		return extracted
	}
	return candidate
}

func extractPayloadParam(candidate, pass string) (string, bool) {
	if values, err := url.ParseQuery(strings.TrimSpace(candidate)); err == nil && len(values) > 0 {
		if value := strings.TrimSpace(values.Get(pass)); value != "" {
			return value, true
		}
		if value := longestQueryValue(values); value != "" {
			return value, true
		}
	}
	if value := extractMultipartValue(candidate, pass); value != "" {
		return value, true
	}
	return "", false
}

func longestQueryValue(values url.Values) string {
	best := ""
	for _, items := range values {
		for _, item := range items {
			trimmed := strings.TrimSpace(item)
			if len(trimmed) > len(best) {
				best = trimmed
			}
		}
	}
	return best
}

func extractMultipartValue(candidate, pass string) string {
	body := strings.ReplaceAll(candidate, "\r\n", "\n")
	lines := strings.Split(body, "\n")
	boundary := ""
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "--") && len(trimmed) > 4 {
			boundary = trimmed
			break
		}
	}
	if boundary == "" {
		return ""
	}

	best := ""
	sections := strings.Split(body, boundary)
	for _, section := range sections {
		section = strings.TrimSpace(section)
		if section == "" || section == "--" {
			continue
		}
		headerBody := strings.SplitN(section, "\n\n", 2)
		if len(headerBody) != 2 {
			continue
		}
		headers := headerBody[0]
		value := strings.TrimSpace(strings.TrimSuffix(headerBody[1], "--"))
		if value == "" {
			continue
		}
		matches := multipartNamePattern.FindStringSubmatch(headers)
		name := ""
		if len(matches) > 1 {
			name = strings.TrimSpace(matches[1])
		}
		if pass != "" && name == pass {
			return value
		}
		if len(value) > len(best) {
			best = value
		}
	}
	return best
}

func applyURLDecodeRounds(candidate string, rounds int) string {
	current := candidate
	for i := 0; i < rounds; i++ {
		decoded, err := url.QueryUnescape(current)
		if err != nil {
			break
		}
		current = decoded
	}
	return current
}

func extractBasePayload(raw string) string {
	return normalizeTransportPayload(raw)
}

func normalizeTransportPayload(raw string) string {
	candidate := strings.TrimSpace(raw)
	for i := 0; i < 3; i++ {
		updated := candidate
		if looksLikeHTTPMessage(updated) {
			updated = strings.TrimSpace(extractHTTPMessageBody(updated))
		}
		if text, ok := unwrapHexEncodedText(updated); ok {
			updated = text
		}
		updated = strings.TrimSpace(updated)
		if updated == candidate {
			break
		}
		candidate = updated
	}
	return candidate
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
	return strings.Contains(text, "\r\nHost:") || strings.Contains(text, "\nHost:") || strings.HasPrefix(text, "HTTP/") || strings.HasPrefix(text, "GET ") || strings.HasPrefix(text, "POST ")
}

func extractBestBase64Candidate(raw string) string {
	candidate := strings.TrimSpace(raw)
	matches := base64CandidatePattern.FindAllString(candidate, -1)
	best := ""
	for _, item := range matches {
		if len(item) > len(best) {
			best = item
		}
	}
	if best == "" {
		best = candidate
	}
	return best
}

func unwrapHexEncodedText(raw string) (string, bool) {
	decoded := decodeLooseHex(raw)
	if len(decoded) == 0 {
		return "", false
	}
	trimmed := bytes.Trim(decoded, "\x00")
	if len(trimmed) == 0 {
		return "", false
	}
	if utf8.Valid(trimmed) || looksMostlyPrintable(trimmed) {
		return string(trimmed), true
	}
	return "", false
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

func decodeCipherInput(raw, mode string) ([]byte, string, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "auto":
		if decoded, err := decodeBase64Loose(extractBestBase64Candidate(raw)); err == nil {
			return decoded, "base64", nil
		}
		if decoded, err := decodeCipherHex(raw); err == nil && len(decoded) > 0 {
			return decoded, "hex", nil
		}
		return nil, "", errors.New("无法识别密文编码，支持 base64 / hex")
	case "base64":
		decoded, err := decodeBase64Loose(extractBestBase64Candidate(raw))
		return decoded, "base64", err
	case "hex":
		decoded, err := decodeCipherHex(raw)
		return decoded, "hex", err
	default:
		return nil, "", fmt.Errorf("unsupported input encoding: %s", mode)
	}
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
	return nil, errors.New("base64 解码失败")
}

func decodeCipherHex(raw string) ([]byte, error) {
	decoded := decodeLooseHex(raw)
	if len(decoded) == 0 {
		return nil, errors.New("hex 解码失败")
	}
	return decoded, nil
}

func normalizeAESKey(raw []byte) []byte {
	switch {
	case len(raw) >= 32:
		return raw[:32]
	case len(raw) >= 24:
		return raw[:24]
	case len(raw) >= 16:
		return raw[:16]
	default:
		out := make([]byte, 16)
		copy(out, raw)
		return out
	}
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errors.New("PKCS7 unpad failed")
	}
	padding := int(data[len(data)-1])
	if padding <= 0 || padding > blockSize || padding > len(data) {
		return nil, errors.New("PKCS7 padding invalid")
	}
	for _, b := range data[len(data)-padding:] {
		if int(b) != padding {
			return nil, errors.New("PKCS7 padding invalid")
		}
	}
	return data[:len(data)-padding], nil
}

func xorBytes(data, key []byte) []byte {
	if len(key) == 0 {
		return append([]byte(nil), data...)
	}
	out := make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ key[i%len(key)]
	}
	return out
}

func stripGodzillaMarkers(raw, pass, key string) string {
	text := strings.TrimSpace(raw)
	if pass == "" || key == "" {
		return text
	}
	sign := fmt.Sprintf("%x", md5.Sum([]byte(pass+key)))
	if len(sign) < 32 {
		return text
	}
	lower := strings.ToLower(text)
	prefix := sign[:16]
	suffix := sign[16:]
	start := strings.Index(lower, prefix)
	end := strings.LastIndex(lower, suffix)
	if start >= 0 && end > start+16 {
		return text[start+16 : end]
	}
	return text
}

func bytesToDisplayText(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	trimmed := bytes.Trim(data, "\x00")
	if len(trimmed) > 0 && utf8.Valid(trimmed) {
		return string(trimmed)
	}
	if utf8.Valid(data) {
		return string(data)
	}
	return base64.StdEncoding.EncodeToString(data)
}

func optionsString(options map[string]any, key string) string {
	if options == nil {
		return ""
	}
	value, ok := options[key]
	if !ok || value == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprintf("%v", value))
}

func optionsStringDefault(options map[string]any, key, fallback string) string {
	if value := optionsString(options, key); value != "" {
		return value
	}
	return fallback
}

func optionsBool(options map[string]any, key string) bool {
	return optionsBoolDefault(options, key, false)
}

func optionsBoolDefault(options map[string]any, key string, fallback bool) bool {
	if options == nil {
		return fallback
	}
	value, ok := options[key]
	if !ok || value == nil {
		return fallback
	}
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		return strings.EqualFold(strings.TrimSpace(typed), "true")
	default:
		return fallback
	}
}

func optionsIntDefault(options map[string]any, key string, fallback int) int {
	if options == nil {
		return fallback
	}
	value, ok := options[key]
	if !ok || value == nil {
		return fallback
	}
	switch typed := value.(type) {
	case float64:
		return int(typed)
	case int:
		return typed
	case string:
		if parsed := strings.TrimSpace(typed); parsed != "" {
			var out int
			_, err := fmt.Sscanf(parsed, "%d", &out)
			if err == nil {
				return out
			}
		}
	}
	return fallback
}

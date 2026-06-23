package engine

import (
	"bytes"
	"crypto/aes"
	"crypto/md5"
	"crypto/subtle"
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
	Decoder       string   `json:"decoder"`
	Summary       string   `json:"summary"`
	Text          string   `json:"text"`
	BytesHex      string   `json:"bytes_hex"`
	Encoding      string   `json:"encoding"`
	Confidence    int      `json:"confidence,omitempty"`
	Warnings      []string `json:"warnings,omitempty"`
	Signals       []string `json:"signals,omitempty"`
	AttemptErrors []string `json:"attempt_errors,omitempty"`
}

var (
	base64CandidatePattern = regexp.MustCompile(`[A-Za-z0-9+/_-]{16,}={0,2}`)
	multipartNamePattern   = regexp.MustCompile(`name="([^"]+)"`)
	httpMethodPrefixes     = []string{"GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS ", "CONNECT ", "TRACE "}
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
	case "regeorg":
		return decodeReGeorgPayload(req.Payload)
	case "china_chopper":
		return decodeChinaChopperPayload(req.Payload, req.Options)
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

	encoder := strings.ToLower(strings.TrimSpace(optionsStringDefault(options, "encoder", "")))
	if encoder == "rot13" {
		rot13Result := decodeRot13(candidate)
		return buildDecodeResult("antsword", "蚁剑 ROT13 解码", []byte(rot13Result), "rot13"), nil
	}

	if chrDecoded, ok := decodeAntSwordChr(candidate); ok {
		return buildDecodeResult("antsword", "蚁剑 chr() 解码", []byte(chrDecoded), "chr"), nil
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
		iv, ivErr := decodeCBCIVOption(options)
		if ivErr != nil {
			return StreamDecodeResult{}, ivErr
		}
		if len(iv) != aes.BlockSize {
			return StreamDecodeResult{}, errors.New("AES-CBC 需要提供 iv 选项")
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

func decodeChinaChopperPayload(raw string, options map[string]any) (StreamDecodeResult, error) {
	candidate := extractPayloadCandidate(raw, optionsString(options, "pass"), optionsBool(options, "extractParam"))
	if candidate == "" {
		return StreamDecodeResult{}, errors.New("未提取到菜刀载荷")
	}
	candidate = applyURLDecodeRounds(candidate, optionsIntDefault(options, "urlDecodeRounds", 1))

	// Try to extract the command from the POST parameter value
	// China Chopper sends: caidao=<base64_encoded_command>
	// or the raw payload itself may be the command
	command := extractChinaChopperCommand(candidate, optionsString(options, "pass"))
	if command != "" {
		// Try Base64 decode the command
		decoded, err := decodeBase64Loose(command)
		if err == nil && len(decoded) > 0 && looksMostlyPrintable(decoded) {
			return buildDecodeResult("china_chopper", "菜刀 Base64 命令解码", decoded, "base64"), nil
		}
		// If Base64 fails, return as plain text
		return buildDecodeResult("china_chopper", "菜刀命令提取", []byte(command), "plain"), nil
	}

	// If no command extracted, try Base64 decode the whole candidate
	decoded, err := decodeBase64Loose(extractBestBase64Candidate(candidate))
	if err == nil && len(decoded) > 0 && looksMostlyPrintable(decoded) {
		return buildDecodeResult("china_chopper", "菜刀 Base64 解码", decoded, "base64"), nil
	}

	// Return the raw candidate as plain text
	return buildDecodeResult("china_chopper", "菜刀载荷提取", []byte(candidate), "plain"), nil
}

func extractChinaChopperCommand(candidate, pass string) string {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return ""
	}

	// Only try URL parsing if it looks like a query string
	if strings.Contains(candidate, "=") && strings.Contains(candidate, "&") || looksLikeHTTPMessage(candidate) {
		// Try URL-encoded form parameters first
		if values, err := url.ParseQuery(candidate); err == nil && len(values) > 0 {
			// Try specified pass first
			if pass != "" {
				if value := strings.TrimSpace(values.Get(pass)); value != "" {
					return value
				}
			}
			// Try common China Chopper parameter names
			for _, name := range []string{"caidao", "pass", "password", "cmd", "data"} {
				if value := strings.TrimSpace(values.Get(name)); value != "" {
					return value
				}
			}
			// Fall back to longest value
			if value := longestQueryValue(values); value != "" {
				return value
			}
		}
	}

	// Try multipart
	if value := extractMultipartValue(candidate, pass); value != "" {
		return value
	}
	if pass == "" {
		if value := extractMultipartValue(candidate, "caidao"); value != "" {
			return value
		}
	}

	return ""
}

// reGeorg / neo-reGeorg HTTP tunnel decoder.
// Parses X-CMD, X-TARGET, X-STATUS-CODE, X-ERROR headers and extracts tunnel data.
func decodeReGeorgPayload(raw string) (StreamDecodeResult, error) {
	text := strings.TrimSpace(raw)
	if text == "" {
		return StreamDecodeResult{}, errors.New("未提取到 reGeorg 隧道载荷")
	}

	headers, body := splitHTTPHeadersAndBody(text)
	cmd := extractHTTPHeaderIgnoreCase(headers, "X-CMD")
	target := extractHTTPHeaderIgnoreCase(headers, "X-TARGET")
	statusCode := extractHTTPHeaderIgnoreCase(headers, "X-STATUS-CODE")
	errMsg := extractHTTPHeaderIgnoreCase(headers, "X-ERROR")

	if cmd == "" && target == "" && statusCode == "" {
		return StreamDecodeResult{}, errors.New("未检测到 reGeorg 隧道特征头 (X-CMD / X-TARGET / X-STATUS-CODE)")
	}

	var summaryParts []string
	if cmd != "" {
		summaryParts = append(summaryParts, "CMD="+cmd)
	}
	if target != "" {
		summaryParts = append(summaryParts, "TARGET="+target)
	}
	if statusCode != "" {
		summaryParts = append(summaryParts, "STATUS="+statusCode)
	}
	if errMsg != "" {
		summaryParts = append(summaryParts, "ERROR="+errMsg)
	}

	summary := "reGeorg 隧道解码"
	if len(summaryParts) > 0 {
		summary += " (" + strings.Join(summaryParts, ", ") + ")"
	}

	data := []byte(body)
	signals := []string{"decoder:regeorg", "encoding:tunnel"}
	if cmd != "" {
		signals = append(signals, "cmd:"+strings.ToLower(cmd))
	}
	if target != "" {
		signals = append(signals, "target:"+target)
	}

	return StreamDecodeResult{
		Decoder:    "regeorg",
		Summary:    summary,
		Text:       body,
		BytesHex:   bytesToColonHex(data),
		Encoding:   "tunnel",
		Confidence: confidenceForReGeorg(cmd, target, statusCode),
		Warnings:   warningsForReGeorg(cmd, target, statusCode, errMsg),
		Signals:    dedupeDecodeStrings(signals),
	}, nil
}

func confidenceForReGeorg(cmd, target, statusCode string) int {
	score := 30
	if cmd != "" {
		score += 25
		upper := strings.ToUpper(cmd)
		if upper == "CONNECT" || upper == "READ" || upper == "WRITE" || upper == "DISCONNECT" || upper == "HEADER" || upper == "FORWARD" {
			score += 10
		}
	}
	if target != "" {
		score += 20
	}
	if statusCode != "" {
		score += 15
	}
	return clampInt(score, 1, 99)
}

func warningsForReGeorg(cmd, target, statusCode, errMsg string) []string {
	var warnings []string
	if cmd == "" {
		warnings = append(warnings, "缺少 X-CMD 头，隧道命令类型未知。")
	}
	if target == "" {
		warnings = append(warnings, "缺少 X-TARGET 头，隧道目标未知。")
	}
	if errMsg != "" {
		warnings = append(warnings, "隧道返回错误: "+errMsg)
	}
	return warnings
}

func splitHTTPHeadersAndBody(raw string) (headers, body string) {
	if idx := strings.Index(raw, "\r\n\r\n"); idx >= 0 {
		return raw[:idx], raw[idx+4:]
	}
	if idx := strings.Index(raw, "\n\n"); idx >= 0 {
		return raw[:idx], raw[idx+2:]
	}
	return raw, ""
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

func buildDecodeResult(decoder, summary string, data []byte, encoding string) StreamDecodeResult {
	text := bytesToDisplayText(data)
	return StreamDecodeResult{
		Decoder:    decoder,
		Summary:    summary,
		Text:       text,
		BytesHex:   bytesToColonHex(data),
		Encoding:   encoding,
		Confidence: confidenceForDecodedText(text, data, encoding),
		Warnings:   warningsForDecodedText(text, data),
		Signals:    signalsForDecodedText(decoder, text, encoding),
	}
}

func confidenceForDecodedText(text string, data []byte, encoding string) int {
	score := scoreDecodedText(text)
	if score < 0 {
		if len(data) > 0 {
			return 20
		}
		return 0
	}
	confidence := score + 35
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "base64", "hex", "chr", "rot13":
		confidence += 8
	case "plain":
		confidence -= 12
	}
	return clampInt(confidence, 1, 99)
}

func warningsForDecodedText(text string, data []byte) []string {
	warnings := make([]string, 0, 3)
	if len(data) == 0 {
		return []string{"解码结果为空，建议检查候选值或密钥参数。"}
	}
	if strings.TrimSpace(text) == "" {
		warnings = append(warnings, "解码后无可展示文本，可能仍是二进制或密钥/算法不匹配。")
	}
	if strings.Contains(text, "\x00") || !looksMostlyPrintable([]byte(text)) {
		warnings = append(warnings, "结果可打印率偏低，非 Base64 解码需人工复核。")
	}
	if len(text) > 0 && scoreDecodedText(text) < 35 {
		warnings = append(warnings, "结果文本特征较弱，不应直接视为成功解密。")
	}
	return warnings
}

func signalsForDecodedText(decoder, text, encoding string) []string {
	signals := []string{
		"decoder:" + strings.ToLower(strings.TrimSpace(decoder)),
		"encoding:" + strings.ToLower(strings.TrimSpace(encoding)),
	}
	lower := strings.ToLower(text)
	for _, keyword := range []string{"<?php", "eval(", "assert", "system(", "exec(", "base64_decode", "cmd", "whoami"} {
		if strings.Contains(lower, keyword) {
			signals = append(signals, "keyword:"+keyword)
		}
	}
	return dedupeDecodeStrings(signals)
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

func isLikelyHexCipher(raw string) bool {
	candidate := strings.TrimSpace(raw)
	if candidate == "" {
		return false
	}
	cleaned := strings.NewReplacer(":", "", " ", "", "\t", "", "\r", "", "\n", "").Replace(candidate)
	if len(cleaned) < 16 || len(cleaned)%2 != 0 {
		return false
	}
	if strings.ContainsAny(cleaned, "ghijklmnopqrstuvwxyzGHIJKLMNOPQRSTUVWXYZ") {
		return false
	}
	if strings.ContainsAny(cleaned, "/+=_-") {
		return false
	}
	decoded := decodeLooseHex(candidate)
	return len(decoded) != 0
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

func decodeCipherAuto(raw string) ([]byte, string, error) {
	candidate := strings.TrimSpace(raw)
	if candidate == "" {
		return nil, "", errors.New("无法识别密文编码，支持 base64 / hex")
	}

	if isPureHexToken(candidate) {
		if decoded, err := decodeCipherHex(candidate); err == nil {
			return decoded, "hex", nil
		}
	}

	bestBase64 := extractBestBase64Candidate(candidate)
	base64Score := scoreBase64Candidate(bestBase64)
	hexLikely := isLikelyHexCipher(candidate)

	if base64Score >= 70 {
		if decoded, err := decodeBase64Loose(bestBase64); err == nil {
			return decoded, "base64", nil
		}
	}
	if hexLikely {
		if decoded, err := decodeCipherHex(candidate); err == nil {
			return decoded, "hex", nil
		}
	}
	if base64Score >= 40 {
		if decoded, err := decodeBase64Loose(bestBase64); err == nil {
			return decoded, "base64", nil
		}
	}
	if decoded, err := decodeCipherHex(candidate); err == nil && len(decoded) > 0 {
		return decoded, "hex", nil
	}
	if decoded, err := decodeBase64Loose(bestBase64); err == nil && len(decoded) > 0 {
		return decoded, "base64", nil
	}
	return nil, "", errors.New("无法识别密文编码，支持 base64 / hex")
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
	trimmed := bytes.Trim(decoded, "\x00")
	if len(trimmed) == 0 {
		return "", false
	}
	if utf8.Valid(trimmed) || looksMostlyPrintable(trimmed) {
		return string(trimmed), true
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

func decodeCipherInput(raw, mode string) ([]byte, string, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "auto":
		return decodeCipherAuto(raw)
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
	if blockSize <= 0 || len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errors.New("PKCS7 unpad failed")
	}
	padding := int(data[len(data)-1])
	invalid := 1 ^ subtle.ConstantTimeLessOrEq(1, padding)
	invalid |= 1 ^ subtle.ConstantTimeLessOrEq(padding, blockSize)
	invalid |= 1 ^ subtle.ConstantTimeLessOrEq(padding, len(data))

	mismatch := 0
	for i := 0; i < blockSize; i++ {
		mask := subtle.ConstantTimeLessOrEq(i+1, padding)
		equal := subtle.ConstantTimeByteEq(data[len(data)-1-i], byte(padding))
		mismatch |= mask & (1 ^ equal)
	}
	if invalid|mismatch != 0 {
		return nil, errors.New("PKCS7 padding invalid")
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

func clampInt(value, minValue, maxValue int) int {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

func dedupeDecodeStrings(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

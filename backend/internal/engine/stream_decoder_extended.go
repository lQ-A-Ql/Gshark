package engine

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"errors"
	"fmt"
	"strings"
)

const aesBlockSize = aes.BlockSize

// decryptAESCBC decrypts AES-CBC ciphertext. If iv is nil or empty, uses zero IV.
// Supports lenient PKCS7 unpadding — returns raw data on padding failure instead of error.
func decryptAESCBC(ciphertext, key, iv []byte) ([]byte, error) {
	normalizedKey := normalizeAESKey(key)
	block, err := aes.NewCipher(normalizedKey)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("AES-CBC 密文长度非法")
	}
	if len(iv) == 0 {
		iv = make([]byte, aes.BlockSize)
	} else if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("AES-CBC IV 长度非法: %d", len(iv))
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	out := make([]byte, len(ciphertext))
	mode.CryptBlocks(out, ciphertext)
	return pkcs7UnpadLenient(out, aes.BlockSize), nil
}

// pkcs7UnpadLenient tries PKCS7 unpadding but returns raw data on failure instead of error.
func pkcs7UnpadLenient(data []byte, blockSize int) []byte {
	if len(data) == 0 {
		return data
	}
	unpadded, err := pkcs7Unpad(data, blockSize)
	if err != nil {
		// Lenient: return data as-is, trimming trailing nulls
		trimmed := data
		for len(trimmed) > 0 && trimmed[len(trimmed)-1] == 0 {
			trimmed = trimmed[:len(trimmed)-1]
		}
		return trimmed
	}
	return unpadded
}

// decryptAESECBLenient is like decryptAESECB but uses lenient unpadding.
func decryptAESECBLenient(ciphertext, key []byte) ([]byte, error) {
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("AES-ECB 密文长度非法")
	}
	block, err := aes.NewCipher(normalizeAESKey(key))
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(ciphertext))
	for offset := 0; offset < len(ciphertext); offset += aes.BlockSize {
		block.Decrypt(out[offset:offset+aes.BlockSize], ciphertext[offset:offset+aes.BlockSize])
	}
	return pkcs7UnpadLenient(out, aes.BlockSize), nil
}

// decodeBehinderPayloadV2 handles Behinder with AES-CBC mode (version 2.x/3.x).
func decodeBehinderPayloadCBC(raw string, options map[string]any) (StreamDecodeResult, error) {
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

	iv, err := decodeCBCIVOption(options)
	if err != nil {
		return StreamDecodeResult{}, err
	}

	plain, err := decryptAESCBC(cipherBytes, []byte(key), iv)
	if err != nil {
		return StreamDecodeResult{}, err
	}

	summary := "冰蝎 AES-CBC 解密"
	if optionsBoolDefault(options, "deriveKeyFromPass", true) && optionsString(options, "pass") != "" && optionsString(options, "key") == "" {
		summary += " (key <- md5(pass)[:16])"
	}
	return buildDecodeResult("behinder", summary, plain, encoding), nil
}

// deriveGodzillaXORKey derives the XOR key for Godzilla PHP: md5(pass+key)[:16]
func deriveGodzillaXORKey(pass, key string) []byte {
	combined := pass + key
	sum := md5.Sum([]byte(combined))
	hexStr := fmt.Sprintf("%x", sum)
	if len(hexStr) >= 16 {
		return []byte(hexStr[:16])
	}
	return []byte(hexStr)
}

// decodeAntSwordChr handles AntSword chr() encoded payloads.
// chr() encoding looks like: chr(97).chr(98).chr(99) => "abc"
func decodeAntSwordChr(raw string) (string, bool) {
	if !strings.Contains(raw, "chr(") {
		return "", false
	}
	var result strings.Builder
	parts := strings.Split(raw, ".")
	decoded := false
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "chr(") && strings.HasSuffix(part, ")") {
			numStr := part[4 : len(part)-1]
			var num int
			if _, err := fmt.Sscanf(numStr, "%d", &num); err == nil && num >= 0 && num <= 255 {
				result.WriteByte(byte(num))
				decoded = true
				continue
			}
		}
		// If not a chr() call, append as-is
		if result.Len() > 0 {
			result.WriteString(part)
		}
	}
	if !decoded {
		return "", false
	}
	return result.String(), true
}

// decodeRot13 applies ROT13 transformation.
func decodeRot13(raw string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return 'a' + (r-'a'+13)%26
		case r >= 'A' && r <= 'Z':
			return 'A' + (r-'A'+13)%26
		default:
			return r
		}
	}, raw)
}

// autoDetectDecode tries all decoders and returns the best result.
func autoDetectDecode(raw string, options map[string]any) (StreamDecodeResult, error) {
	normalized := strings.TrimSpace(raw)
	if normalized == "" {
		return StreamDecodeResult{}, errors.New("payload 为空")
	}

	type attempt struct {
		name    string
		decoder string
		fn      func() (StreamDecodeResult, error)
	}

	attempts := []attempt{
		{
			name:    "Base64",
			decoder: "base64",
			fn:      func() (StreamDecodeResult, error) { return decodeBase64Payload(raw) },
		},
		{
			name:    "Behinder (ECB)",
			decoder: "behinder",
			fn:      func() (StreamDecodeResult, error) { return decodeBehinderPayload(raw, options) },
		},
		{
			name:    "Behinder (CBC)",
			decoder: "behinder",
			fn:      func() (StreamDecodeResult, error) { return decodeBehinderPayloadCBC(raw, options) },
		},
		{
			name:    "AntSword",
			decoder: "antsword",
			fn:      func() (StreamDecodeResult, error) { return decodeAntSwordPayload(raw, options) },
		},
		{
			name:    "Godzilla",
			decoder: "godzilla",
			fn:      func() (StreamDecodeResult, error) { return decodeGodzillaPayload(raw, options) },
		},
	}

	var bestResult StreamDecodeResult
	bestScore := -1
	attemptErrors := make([]string, 0, len(attempts))

	for _, a := range attempts {
		result, err := a.fn()
		if err != nil {
			attemptErrors = append(attemptErrors, fmt.Sprintf("%s: %v", a.name, err))
			continue
		}
		score := scoreDecodeAttempt(a.name, result)
		if score < 0 {
			attemptErrors = append(attemptErrors, fmt.Sprintf("%s: 结果不可读或为空", a.name))
			continue
		}
		if score > bestScore {
			bestScore = score
			bestResult = result
			bestResult.Summary = fmt.Sprintf("自动检测 → %s: %s", a.name, result.Summary)
		}
	}

	if bestScore < 0 {
		return StreamDecodeResult{}, fmt.Errorf("自动检测未找到有效解码结果，请手动选择解码器；失败阶段：%s", strings.Join(attemptErrors, "；"))
	}
	if bestScore < 35 {
		return StreamDecodeResult{}, fmt.Errorf("自动检测置信度不足，请手动选择解码器；最佳分数 %d；失败阶段：%s", bestScore, strings.Join(attemptErrors, "；"))
	}
	bestResult.Decoder = "auto"
	bestResult.Confidence = clampInt(bestScore+20, 1, 99)
	bestResult.AttemptErrors = attemptErrors
	bestResult.Signals = dedupeDecodeStrings(append(bestResult.Signals, fmt.Sprintf("auto-score:%d", bestScore)))
	return bestResult, nil
}

func scoreDecodeAttempt(attemptName string, result StreamDecodeResult) int {
	text := strings.TrimSpace(result.Text)
	if text == "" {
		return -1
	}
	score := scoreDecodedText(text)
	if score < 0 {
		return -1
	}

	name := strings.ToLower(strings.TrimSpace(attemptName))
	summary := strings.ToLower(strings.TrimSpace(result.Summary))
	encoding := strings.ToLower(strings.TrimSpace(result.Encoding))

	switch {
	case strings.Contains(name, "behinder") || strings.Contains(summary, "冰蝎"):
		score += 20
	case strings.Contains(name, "godzilla") || strings.Contains(summary, "哥斯拉"):
		score += 20
	case strings.Contains(name, "antsword") || strings.Contains(summary, "蚁剑"):
		score += 15
	case strings.Contains(name, "base64"):
		score += 5
	}

	switch encoding {
	case "chr", "rot13":
		score += 20
	case "base64", "hex":
		score += 8
	case "plain":
		score -= 20
	}

	if strings.HasPrefix(result.BytesHex, "00:") || strings.HasSuffix(result.BytesHex, ":00") {
		score -= 8
	}
	if strings.Contains(result.Text, "\x00") {
		score -= 20
	}
	if len([]rune(text)) < 12 {
		score -= 40
	}
	return score
}

// scoreDecodedText scores decoded text by how "readable" it looks.
func scoreDecodedText(text string) int {
	if text == "" {
		return -1
	}
	total := len([]rune(text))
	if total == 0 {
		return -1
	}
	if total < 4 {
		return -1
	}

	score := 0
	printable := 0
	for _, r := range text {
		if r >= 32 && r <= 126 || r == '\n' || r == '\r' || r == '\t' {
			printable++
		}
	}
	ratio := printable * 100 / total
	if ratio >= 90 {
		score += 40
	} else if ratio >= 75 {
		score += 20
	} else {
		score -= 30
	}
	for _, keyword := range []string{"<?php", "eval(", "system(", "exec(", "base64_decode", "function", "class ", "import ", "require", "echo ", "print"} {
		if strings.Contains(strings.ToLower(text), keyword) {
			score += 10
		}
	}
	if strings.Count(text, "\n") > 0 {
		score += 5
	}
	if len(text) >= 16 {
		score += min(len(text)/12, 20)
	}
	return score
}

func decodeCBCIVOption(options map[string]any) ([]byte, error) {
	ivStr := strings.TrimSpace(optionsString(options, "iv"))
	if ivStr == "" {
		return nil, nil
	}

	ivRaw := []byte(ivStr)
	if len(ivRaw) == aesBlockSize && !strings.ContainsAny(ivStr, "=+/_-") {
		return ivRaw, nil
	}

	hexDecoded := decodeLooseHex(ivStr)
	if len(hexDecoded) > 0 {
		if len(hexDecoded) == aesBlockSize {
			return hexDecoded, nil
		}
		return nil, fmt.Errorf("AES-CBC IV 长度非法: %d (hex 解码后)", len(hexDecoded))
	}

	if strings.ContainsAny(ivStr, "=+/_-") {
		base64Decoded, base64Err := decodeBase64Loose(ivStr)
		if base64Err == nil && len(base64Decoded) > 0 {
			if len(base64Decoded) == aesBlockSize {
				return base64Decoded, nil
			}
			return nil, fmt.Errorf("AES-CBC IV 长度非法: %d (base64 解码后)", len(base64Decoded))
		}
	}

	if len(ivRaw) == aesBlockSize {
		return ivRaw, nil
	}
	return nil, fmt.Errorf("AES-CBC IV 长度非法: %d (原始文本字节长度)", len(ivRaw))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

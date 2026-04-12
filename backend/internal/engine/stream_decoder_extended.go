package engine

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"errors"
	"fmt"
	"strings"
)

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
	}
	if len(iv) < aes.BlockSize {
		padded := make([]byte, aes.BlockSize)
		copy(padded, iv)
		iv = padded
	}
	mode := cipher.NewCBCDecrypter(block, iv[:aes.BlockSize])
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

	// For CBC mode, IV is either explicitly provided or defaults to zero IV
	var iv []byte
	if ivStr := strings.TrimSpace(optionsString(options, "iv")); ivStr != "" {
		iv = []byte(ivStr)
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

	for _, a := range attempts {
		result, err := a.fn()
		if err != nil {
			continue
		}
		text := strings.TrimSpace(result.Text)
		if text == "" {
			continue
		}
		score := scoreDecodedText(text)
		if score > bestScore {
			bestScore = score
			bestResult = result
			bestResult.Summary = fmt.Sprintf("自动检测 → %s: %s", a.name, result.Summary)
		}
	}

	if bestScore < 0 {
		return StreamDecodeResult{}, errors.New("自动检测未找到有效解码结果，请手动选择解码器")
	}
	return bestResult, nil
}

// scoreDecodedText scores decoded text by how "readable" it looks.
func scoreDecodedText(text string) int {
	if text == "" {
		return -1
	}
	score := 0
	printable := 0
	for _, r := range text {
		if r >= 32 && r <= 126 || r == '\n' || r == '\r' || r == '\t' {
			printable++
		}
	}
	total := len([]rune(text))
	if total == 0 {
		return -1
	}
	ratio := printable * 100 / total
	if ratio >= 90 {
		score += 50
	} else if ratio >= 70 {
		score += 20
	}
	// Bonus for common code/shell patterns
	for _, keyword := range []string{"<?php", "eval(", "system(", "exec(", "base64_decode", "function", "class ", "import ", "require", "echo ", "print"} {
		if strings.Contains(strings.ToLower(text), keyword) {
			score += 10
		}
	}
	score += min(len(text)/10, 30)
	return score
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

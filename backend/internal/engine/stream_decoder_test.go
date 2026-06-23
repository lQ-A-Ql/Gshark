package engine

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
)

func TestDecodeStreamPayloadBase64(t *testing.T) {
	result, err := DecodeStreamPayload(StreamDecodeRequest{
		Decoder: "base64",
		Payload: "SGVsbG8gR1NoYXJr",
	})
	if err != nil {
		t.Fatalf("DecodeStreamPayload() error = %v", err)
	}
	if result.Text != "Hello GShark" {
		t.Fatalf("unexpected decoded text: %q", result.Text)
	}
}

func TestDecodeStreamPayloadBase64FromColonHexASCII(t *testing.T) {
	result, err := DecodeStreamPayload(StreamDecodeRequest{
		Decoder: "base64",
		Payload: "53:47:56:73:62:47:38:67:52:31:4e:6f:59:58:4a:72",
	})
	if err != nil {
		t.Fatalf("DecodeStreamPayload() error = %v", err)
	}
	if result.Text != "Hello GShark" {
		t.Fatalf("unexpected decoded text from colon hex: %q", result.Text)
	}
}

func TestDecodeStreamPayloadBase64URL(t *testing.T) {
	result, err := DecodeStreamPayload(StreamDecodeRequest{
		Decoder: "base64",
		Payload: base64.RawURLEncoding.EncodeToString([]byte("~~~~~~~~~~~~~~~~")),
	})
	if err != nil {
		t.Fatalf("DecodeStreamPayload(base64url) error = %v", err)
	}
	if result.Text != "~~~~~~~~~~~~~~~~" {
		t.Fatalf("unexpected decoded base64url text: %q", result.Text)
	}
	if result.Confidence <= 0 {
		t.Fatalf("expected confidence to be populated, got %d", result.Confidence)
	}
}

func TestDecodeStreamPayloadAntSword(t *testing.T) {
	payload := "pass=" + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte("echo('ok');")))
	result, err := DecodeStreamPayload(StreamDecodeRequest{
		Decoder: "antsword",
		Payload: payload,
		Options: map[string]any{
			"pass":            "pass",
			"extractParam":    true,
			"urlDecodeRounds": 1,
		},
	})
	if err != nil {
		t.Fatalf("DecodeStreamPayload() error = %v", err)
	}
	if result.Text != "echo('ok');" {
		t.Fatalf("unexpected antsword text: %q", result.Text)
	}
}

func TestDecodeStreamPayloadAntSwordFromColonHexASCII(t *testing.T) {
	payload := "70:61:73:73:3d:5a:57:4e:6f:62:79:67:6e:62:32:73:6e:4b:54:73:3d"
	result, err := DecodeStreamPayload(StreamDecodeRequest{
		Decoder: "antsword",
		Payload: payload,
		Options: map[string]any{
			"pass":            "pass",
			"extractParam":    true,
			"urlDecodeRounds": 1,
		},
	})
	if err != nil {
		t.Fatalf("DecodeStreamPayload() error = %v", err)
	}
	if result.Text != "echo('ok');" {
		t.Fatalf("unexpected antsword text from colon hex: %q", result.Text)
	}
}

func TestDecodeStreamPayloadBehinder(t *testing.T) {
	pass := "rebeyond"
	keyHash := md5.Sum([]byte(pass))
	plain := []byte("assert|behinder")
	ciphertext := encryptAESECBForTest(plain, keyHash[:16])
	result, err := DecodeStreamPayload(StreamDecodeRequest{
		Decoder: "behinder",
		Payload: base64.StdEncoding.EncodeToString(ciphertext),
		Options: map[string]any{
			"pass":              pass,
			"deriveKeyFromPass": true,
			"inputEncoding":     "base64",
		},
	})
	if err != nil {
		t.Fatalf("DecodeStreamPayload() error = %v", err)
	}
	if result.Text != string(plain) {
		t.Fatalf("unexpected behinder text: %q", result.Text)
	}
}

func TestDecodeStreamPayloadBehinderWithURLDecode(t *testing.T) {
	pass := "rebeyond"
	keyHash := md5.Sum([]byte(pass))
	plain := []byte("assert|behinder")
	ciphertext := encryptAESECBForTest(plain, keyHash[:16])
	payload := "pass=" + url.QueryEscape(url.QueryEscape(base64.StdEncoding.EncodeToString(ciphertext)))
	result, err := DecodeStreamPayload(StreamDecodeRequest{
		Decoder: "behinder",
		Payload: payload,
		Options: map[string]any{
			"pass":              pass,
			"extractParam":      true,
			"deriveKeyFromPass": true,
			"urlDecodeRounds":   1,
			"inputEncoding":     "base64",
		},
	})
	if err != nil {
		t.Fatalf("DecodeStreamPayload() error = %v", err)
	}
	if result.Text != string(plain) {
		t.Fatalf("unexpected behinder url-decoded text: %q", result.Text)
	}
}

func TestDecodeStreamPayloadGodzillaXor(t *testing.T) {
	pass := "pass"
	key := "key123"
	plain := []byte("godzilla")
	xorKey := deriveGodzillaXORKey(pass, key)
	cipher := xorBytes(plain, xorKey)
	result, err := DecodeStreamPayload(StreamDecodeRequest{
		Decoder: "godzilla",
		Payload: base64.StdEncoding.EncodeToString(cipher),
		Options: map[string]any{
			"pass":          pass,
			"key":           key,
			"cipher":        "xor",
			"inputEncoding": "base64",
		},
	})
	if err != nil {
		t.Fatalf("DecodeStreamPayload() error = %v", err)
	}
	if result.Text != string(plain) {
		t.Fatalf("unexpected godzilla text: %q", result.Text)
	}
}

func TestDecodeStreamPayloadGodzillaFromMultipart(t *testing.T) {
	pass := "pass"
	key := "key123"
	plain := []byte("godzilla")
	xorKey := deriveGodzillaXORKey(pass, key)
	cipher := xorBytes(plain, xorKey)
	multipartBody := "--demo\r\n" +
		"Content-Disposition: form-data; name=\"pass\"\r\n\r\n" +
		url.QueryEscape(base64.StdEncoding.EncodeToString(cipher)) + "\r\n" +
		"--demo--\r\n"
	result, err := DecodeStreamPayload(StreamDecodeRequest{
		Decoder: "godzilla",
		Payload: multipartBody,
		Options: map[string]any{
			"pass":            pass,
			"key":             key,
			"extractParam":    true,
			"urlDecodeRounds": 1,
			"cipher":          "xor",
			"inputEncoding":   "base64",
		},
	})
	if err != nil {
		t.Fatalf("DecodeStreamPayload() error = %v", err)
	}
	if result.Text != string(plain) {
		t.Fatalf("unexpected godzilla multipart text: %q", result.Text)
	}
}

func TestDecodeStreamPayloadBehinderCBC(t *testing.T) {
	pass := "rebeyond"
	keyHash := md5.Sum([]byte(pass))
	key := keyHash[:16]
	plain := []byte("assert|behinder-cbc")
	iv := []byte("behinderivcbc001")
	cipherBlock := encryptAESCBCForTest(plain, key, iv)
	ciphertext := append(append([]byte{}, iv...), cipherBlock...)
	result, err := DecodeStreamPayload(StreamDecodeRequest{
		Decoder: "behinder",
		Payload: base64.StdEncoding.EncodeToString(ciphertext),
		Options: map[string]any{
			"pass":              pass,
			"deriveKeyFromPass": true,
			"inputEncoding":     "base64",
			"cipherMode":        "cbc",
		},
	})
	if err != nil {
		t.Fatalf("DecodeStreamPayload(behinder CBC) error = %v", err)
	}
	if result.Text != string(plain) {
		t.Fatalf("unexpected behinder CBC text: %q", result.Text)
	}
}

func TestDecodeStreamPayloadBehinderCBCWithIV(t *testing.T) {
	pass := "rebeyond"
	keyHash := md5.Sum([]byte(pass))
	key := keyHash[:16]
	iv := []byte("0123456789abcdef")
	plain := []byte("assert|behinder-cbc-iv")
	ciphertext := encryptAESCBCForTest(plain, key, iv)
	result, err := DecodeStreamPayload(StreamDecodeRequest{
		Decoder: "behinder",
		Payload: base64.StdEncoding.EncodeToString(ciphertext),
		Options: map[string]any{
			"pass":              pass,
			"deriveKeyFromPass": true,
			"inputEncoding":     "base64",
			"cipherMode":        "cbc",
			"iv":                string(iv),
		},
	})
	if err != nil {
		t.Fatalf("DecodeStreamPayload(behinder CBC+IV) error = %v", err)
	}
	if result.Text != string(plain) {
		t.Fatalf("unexpected behinder CBC+IV text: %q", result.Text)
	}
}

func TestDecodeStreamPayloadBehinderCBCWithHexIV(t *testing.T) {
	pass := "rebeyond"
	keyHash := md5.Sum([]byte(pass))
	key := keyHash[:16]
	iv := []byte("0123456789abcdef")
	plain := []byte("assert|behinder-cbc-iv-hex")
	ciphertext := encryptAESCBCForTest(plain, key, iv)
	result, err := DecodeStreamPayload(StreamDecodeRequest{
		Decoder: "behinder",
		Payload: base64.StdEncoding.EncodeToString(ciphertext),
		Options: map[string]any{
			"pass":              pass,
			"deriveKeyFromPass": true,
			"inputEncoding":     "base64",
			"cipherMode":        "cbc",
			"iv":                "30313233343536373839616263646566",
		},
	})
	if err != nil {
		t.Fatalf("DecodeStreamPayload(behinder CBC+hex IV) error = %v", err)
	}
	if result.Text != string(plain) {
		t.Fatalf("unexpected behinder CBC+hex IV text: %q", result.Text)
	}
}

func TestDecodeStreamPayloadBehinderCBCWithBase64IV(t *testing.T) {
	pass := "rebeyond"
	keyHash := md5.Sum([]byte(pass))
	key := keyHash[:16]
	iv := []byte("0123456789abcdef")
	plain := []byte("assert|behinder-cbc-iv-b64")
	ciphertext := encryptAESCBCForTest(plain, key, iv)
	result, err := DecodeStreamPayload(StreamDecodeRequest{
		Decoder: "behinder",
		Payload: base64.StdEncoding.EncodeToString(ciphertext),
		Options: map[string]any{
			"pass":              pass,
			"deriveKeyFromPass": true,
			"inputEncoding":     "base64",
			"cipherMode":        "cbc",
			"iv":                "MDEyMzQ1Njc4OWFiY2RlZg==",
		},
	})
	if err != nil {
		t.Fatalf("DecodeStreamPayload(behinder CBC+base64 IV) error = %v", err)
	}
	if result.Text != string(plain) {
		t.Fatalf("unexpected behinder CBC+base64 IV text: %q", result.Text)
	}
}

func TestDecodeStreamPayloadBehinderCBCWithInvalidIVLength(t *testing.T) {
	pass := "rebeyond"
	_, err := DecodeStreamPayload(StreamDecodeRequest{
		Decoder: "behinder",
		Payload: base64.StdEncoding.EncodeToString([]byte("abcd1234")),
		Options: map[string]any{
			"pass":              pass,
			"deriveKeyFromPass": true,
			"inputEncoding":     "base64",
			"cipherMode":        "cbc",
			"iv":                "short-iv",
		},
	})
	if err == nil {
		t.Fatal("expected invalid IV length error")
	}
}

func TestDecodeStreamPayloadAntSwordChr(t *testing.T) {
	// chr(101).chr(99).chr(104).chr(111) => "echo"
	payload := "pass=" + url.QueryEscape("chr(101).chr(99).chr(104).chr(111)")
	result, err := DecodeStreamPayload(StreamDecodeRequest{
		Decoder: "antsword",
		Payload: payload,
		Options: map[string]any{
			"pass":            "pass",
			"extractParam":    true,
			"urlDecodeRounds": 1,
		},
	})
	if err != nil {
		t.Fatalf("DecodeStreamPayload(antsword chr) error = %v", err)
	}
	if result.Text != "echo" {
		t.Fatalf("unexpected antsword chr text: %q", result.Text)
	}
	if result.Encoding != "chr" {
		t.Fatalf("unexpected antsword chr encoding: %q", result.Encoding)
	}
}

func TestDecodeStreamPayloadAntSwordRot13(t *testing.T) {
	// ROT13 of "echo" is "rpub"
	payload := "pass=" + url.QueryEscape("rpub")
	result, err := DecodeStreamPayload(StreamDecodeRequest{
		Decoder: "antsword",
		Payload: payload,
		Options: map[string]any{
			"pass":            "pass",
			"extractParam":    true,
			"urlDecodeRounds": 1,
			"encoder":         "rot13",
		},
	})
	if err != nil {
		t.Fatalf("DecodeStreamPayload(antsword rot13) error = %v", err)
	}
	if result.Text != "echo" {
		t.Fatalf("unexpected antsword rot13 text: %q", result.Text)
	}
}

func TestDecodeStreamPayloadGodzillaXorDerivedKey(t *testing.T) {
	pass := "pass"
	key := "key"
	plain := []byte("godzilla-php-xor")
	xorKey := deriveGodzillaXORKey(pass, key)
	cipher := xorBytes(plain, xorKey)
	result, err := DecodeStreamPayload(StreamDecodeRequest{
		Decoder: "godzilla",
		Payload: base64.StdEncoding.EncodeToString(cipher),
		Options: map[string]any{
			"pass":          pass,
			"key":           key,
			"cipher":        "xor",
			"inputEncoding": "base64",
		},
	})
	if err != nil {
		t.Fatalf("DecodeStreamPayload(godzilla xor derived) error = %v", err)
	}
	if result.Text != string(plain) {
		t.Fatalf("unexpected godzilla xor derived text: %q", result.Text)
	}
}

func TestDecodeStreamPayloadGodzillaAESCBC(t *testing.T) {
	key := "0123456789abcdef"
	iv := []byte("fedcba9876543210")
	plain := []byte("godzilla-aes-cbc")
	ciphertext := encryptAESCBCForTest(plain, []byte(key), iv)
	result, err := DecodeStreamPayload(StreamDecodeRequest{
		Decoder: "godzilla",
		Payload: base64.StdEncoding.EncodeToString(ciphertext),
		Options: map[string]any{
			"key":           key,
			"cipher":        "aes_cbc",
			"inputEncoding": "base64",
			"iv":            string(iv),
		},
	})
	if err != nil {
		t.Fatalf("DecodeStreamPayload(godzilla aes_cbc) error = %v", err)
	}
	if result.Text != string(plain) {
		t.Fatalf("unexpected godzilla aes_cbc text: %q", result.Text)
	}
}

func TestDecodeStreamPayloadWebShellManualFailuresExplainStage(t *testing.T) {
	cases := []struct {
		name     string
		decoder  string
		payload  string
		options  map[string]any
		expected string
	}{
		{
			name:     "behinder empty payload",
			decoder:  "behinder",
			payload:  "   ",
			options:  map[string]any{"pass": "rebeyond", "deriveKeyFromPass": true},
			expected: "未提取到冰蝎密文",
		},
		{
			name:     "antsword empty payload",
			decoder:  "antsword",
			payload:  "   ",
			options:  map[string]any{"pass": "pass", "extractParam": true},
			expected: "未提取到蚁剑载荷",
		},
		{
			name:     "godzilla empty payload",
			decoder:  "godzilla",
			payload:  "   ",
			options:  map[string]any{"pass": "pass", "key": "key123", "extractParam": true},
			expected: "未提取到哥斯拉载荷",
		},
		{
			name:     "godzilla missing key",
			decoder:  "godzilla",
			payload:  base64.StdEncoding.EncodeToString([]byte("cipher-block-demo")),
			options:  map[string]any{"pass": "pass", "cipher": "xor", "inputEncoding": "base64"},
			expected: "哥斯拉解密需要 key",
		},
		{
			name:     "godzilla unsupported cipher",
			decoder:  "godzilla",
			payload:  base64.StdEncoding.EncodeToString([]byte("cipher-block-demo")),
			options:  map[string]any{"pass": "pass", "key": "key123", "cipher": "rc4", "inputEncoding": "base64"},
			expected: "unsupported godzilla cipher",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeStreamPayload(StreamDecodeRequest{
				Decoder: tc.decoder,
				Payload: tc.payload,
				Options: tc.options,
			})
			if err == nil {
				t.Fatal("expected readable failure-stage error")
			}
			if !strings.Contains(err.Error(), tc.expected) {
				t.Fatalf("expected error to contain %q, got: %v", tc.expected, err)
			}
		})
	}
}

func TestDecodeStreamPayloadAutoBase64(t *testing.T) {
	result, err := DecodeStreamPayload(StreamDecodeRequest{
		Decoder: "auto",
		Payload: base64.StdEncoding.EncodeToString([]byte("Hello Auto Detect")),
	})
	if err != nil {
		t.Fatalf("DecodeStreamPayload(auto) error = %v", err)
	}
	if result.Text != "Hello Auto Detect" {
		t.Fatalf("unexpected auto text: %q", result.Text)
	}
}

func TestDecodeStreamPayloadAutoHintedGodzillaRequiresKey(t *testing.T) {
	raw := "7f0e6f=" + url.QueryEscape(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x13}, 16)))

	_, err := DecodeStreamPayload(StreamDecodeRequest{
		Decoder: "auto",
		Payload: raw,
	})
	if err == nil {
		t.Fatal("expected Godzilla key error")
	}
	if !strings.Contains(err.Error(), "哥斯拉解密需要 key") {
		t.Fatalf("expected Godzilla key error, got: %v", err)
	}
}

func TestDecodeStreamPayloadAutoHintedAntSwordNumericParam(t *testing.T) {
	raw := "1=" + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte("assert($_POST['cmd']);")))

	result, err := DecodeStreamPayload(StreamDecodeRequest{
		Decoder: "auto",
		Payload: raw,
	})
	if err != nil {
		t.Fatalf("DecodeStreamPayload(auto hinted AntSword) error = %v", err)
	}
	if !strings.Contains(result.Text, "assert($_POST['cmd']);") {
		t.Fatalf("unexpected auto hinted AntSword text: %q", result.Text)
	}
}

func TestDecodeCipherAutoPrefersHexForPureHexToken(t *testing.T) {
	result, encoding, err := decodeCipherInput("48656c6c6f20536861726b", "auto")
	if err != nil {
		t.Fatalf("decodeCipherInput(auto) error = %v", err)
	}
	if result == nil {
		t.Fatal("decodeCipherInput(auto) result is nil")
	}
	if encoding != "hex" {
		t.Fatalf("unexpected decodeCipherInput(auto) encoding: %q", encoding)
	}
	if string(result) != "Hello Shark" {
		t.Fatalf("unexpected decodeCipherInput(auto) text: %q", string(result))
	}
}

func TestExtractBestBase64CandidateRejectsPlainToken(t *testing.T) {
	raw := "Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456"
	candidate := extractBestBase64Candidate(raw)
	if candidate != raw {
		t.Fatalf("extractBestBase64Candidate should keep original text, got %q", candidate)
	}
}

func TestScoreDecodeAttemptPenalizesPlainEncoding(t *testing.T) {
	plainScore := scoreDecodeAttempt("AntSword", StreamDecodeResult{
		Summary:  "蚁剑 URL 解码结果",
		Text:     "echo('ok');",
		BytesHex: "65:63:68:6f:28:27:6f:6b:27:29:3b",
		Encoding: "plain",
	})
	base64Score := scoreDecodeAttempt("AntSword", StreamDecodeResult{
		Summary:  "蚁剑 Base64 解码",
		Text:     "echo('ok');",
		BytesHex: "65:63:68:6f:28:27:6f:6b:27:29:3b",
		Encoding: "base64",
	})
	if plainScore >= base64Score {
		t.Fatalf("plain score should be lower than base64 score, plain=%d base64=%d", plainScore, base64Score)
	}
}

func TestScoreDecodeAttemptRewardsSignatureDecoder(t *testing.T) {
	behinderScore := scoreDecodeAttempt("Behinder (CBC)", StreamDecodeResult{
		Summary:  "冰蝎 AES-CBC 解密",
		Text:     "assert(base64_decode($_POST['x']));",
		BytesHex: "61:73:73:65:72:74",
		Encoding: "base64",
	})
	base64Score := scoreDecodeAttempt("Base64", StreamDecodeResult{
		Summary:  "Base64 自动解码",
		Text:     "assert(base64_decode($_POST['x']));",
		BytesHex: "61:73:73:65:72:74",
		Encoding: "base64",
	})
	if behinderScore <= base64Score {
		t.Fatalf("behinder score should be greater than base64 score, behinder=%d base64=%d", behinderScore, base64Score)
	}
}

func TestDecodeStreamPayloadAntSwordRot13TakesPriorityOverChr(t *testing.T) {
	payload := "pass=" + url.QueryEscape("pu e(101)")
	result, err := DecodeStreamPayload(StreamDecodeRequest{
		Decoder: "antsword",
		Payload: payload,
		Options: map[string]any{
			"pass":            "pass",
			"extractParam":    true,
			"urlDecodeRounds": 1,
			"encoder":         "rot13",
		},
	})
	if err != nil {
		t.Fatalf("DecodeStreamPayload(antsword rot13 priority) error = %v", err)
	}
	if result.Encoding != "rot13" {
		t.Fatalf("unexpected encoding: %q", result.Encoding)
	}
}

func TestDecodeCBCIVOptionInvalidLength(t *testing.T) {
	_, err := decodeCBCIVOption(map[string]any{"iv": "short-iv"})
	if err == nil {
		t.Fatal("expected decodeCBCIVOption invalid length error")
	}
}

func TestDecodeCBCIVOptionAcceptsHexAndBase64(t *testing.T) {
	hexIV, err := decodeCBCIVOption(map[string]any{"iv": "30313233343536373839616263646566"})
	if err != nil {
		t.Fatalf("decodeCBCIVOption(hex) error = %v", err)
	}
	if string(hexIV) != "0123456789abcdef" {
		t.Fatalf("unexpected hex IV decode: %q", string(hexIV))
	}

	base64IV, err := decodeCBCIVOption(map[string]any{"iv": "MDEyMzQ1Njc4OWFiY2RlZg=="})
	if err != nil {
		t.Fatalf("decodeCBCIVOption(base64) error = %v", err)
	}
	if string(base64IV) != "0123456789abcdef" {
		t.Fatalf("unexpected base64 IV decode: %q", string(base64IV))
	}
}

func TestDecodeCBCIVOptionErrorIncludesFormatHint(t *testing.T) {
	_, err := decodeCBCIVOption(map[string]any{"iv": "MDEyMzQ1Njc4OQ=="})
	if err == nil {
		t.Fatal("expected decodeCBCIVOption error")
	}
	if !strings.Contains(err.Error(), "base64 解码后") {
		t.Fatalf("expected base64 format hint in error, got: %v", err)
	}
}

func TestNormalizeTransportPayloadSkipsQueryHexUnwrap(t *testing.T) {
	raw := "pass=48656c6c6f20536861726b"
	got := normalizeTransportPayload(raw)
	if got != raw {
		t.Fatalf("normalizeTransportPayload should keep query-like payload, got %q", got)
	}
}

func TestNormalizeTransportPayloadUnwrapsPureHexText(t *testing.T) {
	raw := "48656c6c6f20536861726b"
	got := normalizeTransportPayload(raw)
	if got != "Hello Shark" {
		t.Fatalf("normalizeTransportPayload should unwrap pure hex text, got %q", got)
	}
}

func TestDecodeStreamPayloadAutoLowConfidenceFails(t *testing.T) {
	_, err := DecodeStreamPayload(StreamDecodeRequest{
		Decoder: "auto",
		Payload: base64.StdEncoding.EncodeToString([]byte("test")),
	})
	if err == nil {
		t.Fatal("expected auto failure")
	}
	if !strings.Contains(err.Error(), "置信度不足") && !strings.Contains(err.Error(), "未找到有效解码结果") {
		t.Fatalf("expected low-confidence or no-valid-result error, got: %v", err)
	}
}

func TestDecodeStreamPayloadAutoStillAcceptsHighConfidence(t *testing.T) {
	result, err := DecodeStreamPayload(StreamDecodeRequest{
		Decoder: "auto",
		Payload: base64.StdEncoding.EncodeToString([]byte("<?php echo 'ok';")),
	})
	if err != nil {
		t.Fatalf("DecodeStreamPayload(auto high confidence) error = %v", err)
	}
	if !strings.Contains(result.Text, "<?php") {
		t.Fatalf("unexpected auto high confidence result: %q", result.Text)
	}
	if result.Decoder != "auto" {
		t.Fatalf("auto result decoder = %q, want auto", result.Decoder)
	}
	if result.Confidence < 70 {
		t.Fatalf("auto confidence = %d, want >= 70", result.Confidence)
	}
	if !hasStringPrefix(result.Signals, "auto-score:") {
		t.Fatalf("expected auto score signal, got signals=%#v", result.Signals)
	}
}

func TestDecodeStreamPayloadAutoLowConfidenceIncludesAttemptStages(t *testing.T) {
	_, err := DecodeStreamPayload(StreamDecodeRequest{
		Decoder: "auto",
		Payload: base64.StdEncoding.EncodeToString([]byte("test")),
	})
	if err == nil {
		t.Fatal("expected auto low-confidence error")
	}
	if !strings.Contains(err.Error(), "失败阶段") {
		t.Fatalf("expected failure-stage details, got: %v", err)
	}
	if !strings.Contains(err.Error(), "Behinder") && !strings.Contains(err.Error(), "Godzilla") {
		t.Fatalf("expected webshell decoder attempt detail, got: %v", err)
	}
}

func TestDecodeStreamPayloadBehinderCBCInvalidBlockLengthIsReadable(t *testing.T) {
	pass := "rebeyond"
	_, err := DecodeStreamPayload(StreamDecodeRequest{
		Decoder: "behinder",
		Payload: base64.StdEncoding.EncodeToString([]byte("not-aes-block")),
		Options: map[string]any{
			"pass":              pass,
			"deriveKeyFromPass": true,
			"inputEncoding":     "base64",
			"cipherMode":        "cbc",
		},
	})
	if err == nil {
		t.Fatal("expected AES block length error")
	}
	if !strings.Contains(err.Error(), "AES-CBC 密文长度非法") {
		t.Fatalf("expected readable AES-CBC length error, got: %v", err)
	}
}

func TestLooksLikeHTTPMessageRecognizesPut(t *testing.T) {
	raw := "PUT /shell.php HTTP/1.1\r\nHost: test\r\n\r\nbody"
	if !looksLikeHTTPMessage(raw) {
		t.Fatal("looksLikeHTTPMessage should recognize PUT request")
	}
}

func TestIsPureHexToken(t *testing.T) {
	if !isPureHexToken("48656c6c6f20536861726b") {
		t.Fatal("isPureHexToken should return true for pure hex")
	}
	if isPureHexToken("HelloShark123456") {
		t.Fatal("isPureHexToken should return false for non-hex token")
	}
}

func TestDecryptAESECBLenient(t *testing.T) {
	key := []byte("0123456789abcdef")
	plain := []byte("test-lenient-pad")
	ciphertext := encryptAESECBForTest(plain, key)
	result, err := decryptAESECBLenient(ciphertext, key)
	if err != nil {
		t.Fatalf("decryptAESECBLenient error = %v", err)
	}
	if string(result) != string(plain) {
		t.Fatalf("unexpected decryptAESECBLenient result: %q", string(result))
	}
}

func TestDecryptAESCBC(t *testing.T) {
	key := []byte("0123456789abcdef")
	iv := []byte("fedcba9876543210")
	plain := []byte("test-cbc-decrypt")
	ciphertext := encryptAESCBCForTest(plain, key, iv)
	result, err := decryptAESCBC(ciphertext, key, iv)
	if err != nil {
		t.Fatalf("decryptAESCBC error = %v", err)
	}
	if string(result) != string(plain) {
		t.Fatalf("unexpected decryptAESCBC result: %q", string(result))
	}
}

func TestPKCS7UnpadRejectsInvalidFullBlockPadding(t *testing.T) {
	data := append([]byte("0123456789abcdef"), bytesRepeatForTest(16, aes.BlockSize)...)
	data[len(data)-aes.BlockSize] = 1
	if _, err := pkcs7Unpad(data, aes.BlockSize); err == nil {
		t.Fatal("expected invalid full-block padding to be rejected")
	}
}

func TestPKCS7UnpadLenientRejectsRandomWrongKeyPlaintext(t *testing.T) {
	data := bytesRepeatForTest(0x01, aes.BlockSize)
	data[len(data)-1] = 8
	if _, err := pkcs7UnpadLenient(data, aes.BlockSize); err == nil {
		t.Fatal("expected random invalid padding output to be rejected")
	}
}

func TestPKCS7UnpadLenientAcceptsReadableUnpaddedPlaintext(t *testing.T) {
	plain := []byte("system(\"whoami\");")
	padded := append([]byte{}, plain...)
	padded = append(padded, bytesRepeatForTest(0, aes.BlockSize-len(plain)%aes.BlockSize)...)
	got, err := pkcs7UnpadLenient(padded, aes.BlockSize)
	if err != nil {
		t.Fatalf("expected readable unpadded plaintext to be accepted: %v", err)
	}
	if string(got) != string(plain) {
		t.Fatalf("unexpected plaintext: %q", got)
	}
}

func TestDecodeRot13(t *testing.T) {
	if got := decodeRot13("Hello"); got != "Uryyb" {
		t.Fatalf("decodeRot13(Hello) = %q, want Uryyb", got)
	}
	if got := decodeRot13("Uryyb"); got != "Hello" {
		t.Fatalf("decodeRot13(Uryyb) = %q, want Hello", got)
	}
}

func TestDecodeAntSwordChr(t *testing.T) {
	input := "chr(72).chr(101).chr(108).chr(108).chr(111)"
	result, ok := decodeAntSwordChr(input)
	if !ok {
		t.Fatal("decodeAntSwordChr returned false")
	}
	if result != "Hello" {
		t.Fatalf("decodeAntSwordChr = %q, want Hello", result)
	}
}

func hasStringPrefix(items []string, prefix string) bool {
	for _, item := range items {
		if strings.HasPrefix(item, prefix) {
			return true
		}
	}
	return false
}

func encryptAESCBCForTest(plain, key, iv []byte) []byte {
	normalizedKey := normalizeAESKey(key)
	block, err := aes.NewCipher(normalizedKey)
	if err != nil {
		panic(err)
	}
	padded := pkcs7PadForTest(plain, aes.BlockSize)
	if len(iv) == 0 {
		iv = make([]byte, aes.BlockSize)
	}
	out := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv[:aes.BlockSize])
	mode.CryptBlocks(out, padded)
	return out
}

func encryptAESECBForTest(plain, key []byte) []byte {
	block, err := aes.NewCipher(normalizeAESKey(key))
	if err != nil {
		panic(err)
	}
	padded := pkcs7PadForTest(plain, aes.BlockSize)
	out := make([]byte, len(padded))
	for offset := 0; offset < len(padded); offset += aes.BlockSize {
		block.Encrypt(out[offset:offset+aes.BlockSize], padded[offset:offset+aes.BlockSize])
	}
	return out
}

func pkcs7PadForTest(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	if padding == 0 {
		padding = blockSize
	}
	return append(bytes.Clone(data), bytes.Repeat([]byte{byte(padding)}, padding)...)
}

func TestDecodeStreamPayloadChinaChopperEval(t *testing.T) {
	// China Chopper sends: caidao=<base64_encoded_command>
	// The command is typically PHP code like: system("whoami");
	command := `system("whoami");`
	encodedCommand := base64.StdEncoding.EncodeToString([]byte(command))
	payload := "caidao=" + url.QueryEscape(encodedCommand)
	result, err := DecodeStreamPayload(StreamDecodeRequest{
		Decoder: "china_chopper",
		Payload: payload,
		Options: map[string]any{
			"pass":            "caidao",
			"extractParam":    true,
			"urlDecodeRounds": 1,
		},
	})
	if err != nil {
		t.Fatalf("DecodeStreamPayload(china_chopper eval) error = %v", err)
	}
	if result.Text != command {
		t.Fatalf("unexpected china_chopper eval text: %q", result.Text)
	}
	if result.Decoder != "china_chopper" {
		t.Fatalf("unexpected decoder: %q", result.Decoder)
	}
}

func TestDecodeStreamPayloadChinaChopperAssert(t *testing.T) {
	// China Chopper with assert pattern: @assert($_POST['pass'])
	// The payload itself is the base64-encoded command (after extraction)
	command := `echo("flag{test}");`
	encodedCommand := base64.StdEncoding.EncodeToString([]byte(command))
	result, err := DecodeStreamPayload(StreamDecodeRequest{
		Decoder: "china_chopper",
		Payload: encodedCommand,
		Options: map[string]any{
			"pass":            "pass",
			"extractParam":    false,
			"urlDecodeRounds": 0,
		},
	})
	if err != nil {
		t.Fatalf("DecodeStreamPayload(china_chopper assert) error = %v", err)
	}
	if result.Text != command {
		t.Fatalf("unexpected china_chopper assert text: %q", result.Text)
	}
}

func TestDecodeStreamPayloadChinaChopperEmptyPayload(t *testing.T) {
	_, err := DecodeStreamPayload(StreamDecodeRequest{
		Decoder: "china_chopper",
		Payload: "   ",
		Options: map[string]any{
			"pass":         "caidao",
			"extractParam": true,
		},
	})
	if err == nil {
		t.Fatal("expected error for empty china_chopper payload")
	}
	if !strings.Contains(err.Error(), "未提取到菜刀载荷") {
		t.Fatalf("expected '未提取到菜刀载荷' error, got: %v", err)
	}
}

func TestDecodeStreamPayloadChinaChopperWithHTTPMessage(t *testing.T) {
	// Simulate a full HTTP POST request with China Chopper payload
	command := `file_get_contents("/etc/passwd");`
	encodedCommand := base64.StdEncoding.EncodeToString([]byte(command))
	payload := "POST /shell.php HTTP/1.1\r\nHost: target.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\ncaidao=" + url.QueryEscape(encodedCommand)
	result, err := DecodeStreamPayload(StreamDecodeRequest{
		Decoder: "china_chopper",
		Payload: payload,
		Options: map[string]any{
			"pass":            "caidao",
			"extractParam":    true,
			"urlDecodeRounds": 1,
		},
	})
	if err != nil {
		t.Fatalf("DecodeStreamPayload(china_chopper HTTP) error = %v", err)
	}
	if result.Text != command {
		t.Fatalf("unexpected china_chopper HTTP text: %q", result.Text)
	}
}

func TestDecodeStreamPayloadReGeorgCONNECT(t *testing.T) {
	payload := "GET /tunnel.php HTTP/1.1\r\n" +
		"Host: target.test\r\n" +
		"X-CMD: CONNECT\r\n" +
		"X-TARGET: 192.168.1.100:3389\r\n" +
		"\r\n"
	result, err := DecodeStreamPayload(StreamDecodeRequest{
		Decoder: "regeorg",
		Payload: payload,
	})
	if err != nil {
		t.Fatalf("DecodeStreamPayload(regeorg CONNECT) error = %v", err)
	}
	if result.Decoder != "regeorg" {
		t.Fatalf("Decoder = %q, want regeorg", result.Decoder)
	}
	if !strings.Contains(result.Summary, "CMD=CONNECT") {
		t.Fatalf("Summary = %q, want CMD=CONNECT", result.Summary)
	}
	if !strings.Contains(result.Summary, "TARGET=192.168.1.100:3389") {
		t.Fatalf("Summary = %q, want TARGET=192.168.1.100:3389", result.Summary)
	}
	if result.Encoding != "tunnel" {
		t.Fatalf("Encoding = %q, want tunnel", result.Encoding)
	}
	if result.Confidence < 60 {
		t.Fatalf("Confidence = %d, want >= 60", result.Confidence)
	}
}

func TestDecodeStreamPayloadReGeorgREADWithStatus(t *testing.T) {
	payload := "POST /tunnel.aspx HTTP/1.1\r\n" +
		"Host: target.test\r\n" +
		"X-CMD: READ\r\n" +
		"X-TARGET: 10.0.0.5:8080\r\n" +
		"X-STATUS-CODE: 200\r\n" +
		"\r\n" +
		"Hello from tunnel"
	result, err := DecodeStreamPayload(StreamDecodeRequest{
		Decoder: "regeorg",
		Payload: payload,
	})
	if err != nil {
		t.Fatalf("DecodeStreamPayload(regeorg READ) error = %v", err)
	}
	if !strings.Contains(result.Summary, "CMD=READ") {
		t.Fatalf("Summary = %q, want CMD=READ", result.Summary)
	}
	if !strings.Contains(result.Summary, "STATUS=200") {
		t.Fatalf("Summary = %q, want STATUS=200", result.Summary)
	}
	if result.Text != "Hello from tunnel" {
		t.Fatalf("Text = %q, want 'Hello from tunnel'", result.Text)
	}
}

func TestDecodeStreamPayloadReGeorgWithXError(t *testing.T) {
	payload := "POST /tunnel.php HTTP/1.1\r\n" +
		"Host: target.test\r\n" +
		"X-CMD: CONNECT\r\n" +
		"X-TARGET: 10.0.0.1:22\r\n" +
		"X-ERROR: Connection refused\r\n" +
		"\r\n"
	result, err := DecodeStreamPayload(StreamDecodeRequest{
		Decoder: "regeorg",
		Payload: payload,
	})
	if err != nil {
		t.Fatalf("DecodeStreamPayload(regeorg error) error = %v", err)
	}
	if len(result.Warnings) == 0 {
		t.Fatal("expected warning for X-ERROR")
	}
	foundErrorWarning := false
	for _, w := range result.Warnings {
		if strings.Contains(w, "Connection refused") {
			foundErrorWarning = true
		}
	}
	if !foundErrorWarning {
		t.Fatalf("expected warning about 'Connection refused', got warnings: %v", result.Warnings)
	}
}

func TestDecodeStreamPayloadReGeorgEmptyPayload(t *testing.T) {
	_, err := DecodeStreamPayload(StreamDecodeRequest{
		Decoder: "regeorg",
		Payload: "   ",
	})
	if err == nil {
		t.Fatal("expected empty payload error")
	}
	if !strings.Contains(err.Error(), "未提取到 reGeorg") {
		t.Fatalf("expected reGeorg empty error, got: %v", err)
	}
}

func TestDecodeStreamPayloadReGeorgMissingHeaders(t *testing.T) {
	_, err := DecodeStreamPayload(StreamDecodeRequest{
		Decoder: "regeorg",
		Payload: "GET /index.html HTTP/1.1\r\nHost: test\r\n\r\n",
	})
	if err == nil {
		t.Fatal("expected missing headers error")
	}
	if !strings.Contains(err.Error(), "未检测到 reGeorg") {
		t.Fatalf("expected reGeorg missing headers error, got: %v", err)
	}
}

func TestDecodeStreamPayloadReGeorgNeoVariant(t *testing.T) {
	payload := "GET /tunnel.jsp HTTP/1.1\r\n" +
		"Host: target.test\r\n" +
		"X-CMD: FORWARD\r\n" +
		"X-TARGET: 172.16.0.1:443\r\n" +
		"\r\n"
	result, err := DecodeStreamPayload(StreamDecodeRequest{
		Decoder: "regeorg",
		Payload: payload,
	})
	if err != nil {
		t.Fatalf("DecodeStreamPayload(neo-reGeorg) error = %v", err)
	}
	if result.Decoder != "regeorg" {
		t.Fatalf("Decoder = %q, want regeorg", result.Decoder)
	}
	if !strings.Contains(result.Summary, "CMD=FORWARD") {
		t.Fatalf("Summary = %q, want CMD=FORWARD", result.Summary)
	}
}

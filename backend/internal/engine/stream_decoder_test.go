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
	ciphertext := encryptAESCBCForTest(plain, key, nil)
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
	plain := []byte("godzilla-aes-cbc")
	ciphertext := encryptAESCBCForTest(plain, []byte(key), nil)
	result, err := DecodeStreamPayload(StreamDecodeRequest{
		Decoder: "godzilla",
		Payload: base64.StdEncoding.EncodeToString(ciphertext),
		Options: map[string]any{
			"key":           key,
			"cipher":        "aes_cbc",
			"inputEncoding": "base64",
		},
	})
	if err != nil {
		t.Fatalf("DecodeStreamPayload(godzilla aes_cbc) error = %v", err)
	}
	if result.Text != string(plain) {
		t.Fatalf("unexpected godzilla aes_cbc text: %q", result.Text)
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

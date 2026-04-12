package engine

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/base64"
	"net/url"
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

package engine

import (
	"bytes"
	"crypto/aes"
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
	key := "key123"
	plain := []byte("godzilla")
	cipher := xorBytes(plain, []byte(key))
	result, err := DecodeStreamPayload(StreamDecodeRequest{
		Decoder: "godzilla",
		Payload: base64.StdEncoding.EncodeToString(cipher),
		Options: map[string]any{
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
	key := "key123"
	plain := []byte("godzilla")
	cipher := xorBytes(plain, []byte(key))
	multipartBody := "--demo\r\n" +
		"Content-Disposition: form-data; name=\"pass\"\r\n\r\n" +
		url.QueryEscape(base64.StdEncoding.EncodeToString(cipher)) + "\r\n" +
		"--demo--\r\n"
	result, err := DecodeStreamPayload(StreamDecodeRequest{
		Decoder: "godzilla",
		Payload: multipartBody,
		Options: map[string]any{
			"pass":            "pass",
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

package engine

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestBuildShiroRememberMeAnalysisFromPacketsDetectsDefaultKeyHit(t *testing.T) {
	plaintext := append([]byte{0xac, 0xed, 0x00, 0x05}, []byte("org.apache.shiro.subject.SimplePrincipalCollection")...)
	cookieValue := mustMakeRememberMeCBC(t, "kPH+bIxk5D2deZiIxcaaaA==", plaintext)
	packets := []model.Packet{
		{
			ID:         12,
			Timestamp:  "2026-04-26T13:14:15Z",
			SourceIP:   "10.0.0.10",
			DestIP:     "10.0.0.20",
			SourcePort: 52341,
			DestPort:   8080,
			Protocol:   "HTTP",
			Info:       "GET /dashboard HTTP/1.1",
			Payload:    "GET /dashboard HTTP/1.1\r\nHost: shiro.demo\r\nCookie: rememberMe=" + cookieValue + "; JSESSIONID=abc\r\n\r\n",
			StreamID:   9,
		},
	}

	analysis, err := buildShiroRememberMeAnalysisFromPackets(context.Background(), packets, model.ShiroRememberMeRequest{})
	if err != nil {
		t.Fatalf("buildShiroRememberMeAnalysisFromPackets returned error: %v", err)
	}
	if analysis.CandidateCount != 1 {
		t.Fatalf("expected 1 candidate, got %d", analysis.CandidateCount)
	}
	if analysis.HitCount != 1 {
		t.Fatalf("expected 1 hit, got %d", analysis.HitCount)
	}
	candidate := analysis.Candidates[0]
	if candidate.SourceHeader != "Cookie" {
		t.Fatalf("expected source header Cookie, got %q", candidate.SourceHeader)
	}
	if !candidate.DecodeOK {
		t.Fatalf("expected candidate to decode successfully")
	}
	if !candidate.PossibleCBC {
		t.Fatalf("expected candidate to look like CBC data")
	}
	if candidate.HitCount != 1 {
		t.Fatalf("expected 1 key hit, got %d", candidate.HitCount)
	}
	if len(candidate.KeyResults) == 0 || !candidate.KeyResults[0].Hit {
		t.Fatalf("expected first key result to hit, got %+v", candidate.KeyResults)
	}
	if candidate.KeyResults[0].Algorithm != "AES-CBC" {
		t.Fatalf("expected AES-CBC algorithm, got %+v", candidate.KeyResults[0])
	}
	if candidate.KeyResults[0].PayloadClass != "org.apache.shiro.subject.SimplePrincipalCollection" {
		t.Fatalf("unexpected payload class: %+v", candidate.KeyResults[0])
	}
}

func TestBuildShiroRememberMeAnalysisFromPacketsRecognizesDeleteMeMarker(t *testing.T) {
	packets := []model.Packet{
		{
			ID:         21,
			Timestamp:  "2026-04-26T13:20:00Z",
			SourceIP:   "10.0.0.20",
			DestIP:     "10.0.0.10",
			SourcePort: 8080,
			DestPort:   52341,
			Protocol:   "HTTP",
			Info:       "HTTP/1.1 200 OK",
			Payload:    "HTTP/1.1 200 OK\r\nSet-Cookie: rememberMe=deleteMe; Path=/; HttpOnly\r\n\r\n",
			StreamID:   9,
		},
	}

	analysis, err := buildShiroRememberMeAnalysisFromPackets(context.Background(), packets, model.ShiroRememberMeRequest{})
	if err != nil {
		t.Fatalf("buildShiroRememberMeAnalysisFromPackets returned error: %v", err)
	}
	if analysis.CandidateCount != 1 {
		t.Fatalf("expected 1 candidate, got %d", analysis.CandidateCount)
	}
	candidate := analysis.Candidates[0]
	if candidate.DecodeOK {
		t.Fatalf("deleteMe marker should not decode as ciphertext")
	}
	if len(candidate.Notes) == 0 || !strings.Contains(strings.Join(candidate.Notes, " "), "deleteMe") {
		t.Fatalf("expected deleteMe note, got %+v", candidate.Notes)
	}
}

func mustMakeRememberMeCBC(t *testing.T, keyBase64 string, plaintext []byte) string {
	t.Helper()
	key, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("new cipher: %v", err)
	}
	iv := []byte("0123456789abcdef")
	padded := pkcs7Pad(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)
	return base64.StdEncoding.EncodeToString(append(iv, ciphertext...))
}

func pkcs7Pad(raw []byte, blockSize int) []byte {
	padding := blockSize - len(raw)%blockSize
	if padding == 0 {
		padding = blockSize
	}
	return append(append([]byte(nil), raw...), bytes.Repeat([]byte{byte(padding)}, padding)...)
}

package engine

import (
	"encoding/hex"
	"testing"
)

func TestParseWebSocketFrames(t *testing.T) {
	// Test unmasked server→client frame
	serverHex := "81322e00000008b14ef5aad7b1b7fab1385d5c84f32bc8bff4f647a9aa10b1edf883fe0585541d2d6ad18b8d52517e0054531efd"
	serverData, _ := hex.DecodeString(serverHex)

	frames := parseWebSocketFrames(serverData)
	if len(frames) != 1 {
		t.Fatalf("expected 1 frame, got %d", len(frames))
	}

	frame := frames[0]
	if frame.masked {
		t.Errorf("server frame should not be masked")
	}
	if frame.opcode != 0x01 {
		t.Errorf("expected opcode 0x01 (text), got 0x%02x", frame.opcode)
	}
	if len(frame.payload) != 50 {
		t.Errorf("expected payload length 50, got %d", len(frame.payload))
	}
}

func TestParseWebSocketFramesMasked(t *testing.T) {
	// Masked client→server frame: header 0x81 0xfe <16-bit len 0x009f> <4-byte mask> + 159 masked bytes.
	clientHex := "81fe009f800000007c2f121ee72f121e3380f0b9a89c95eb18f1f3a4cc19dda26dcf16c95a880e380c28ea68d71d915acd6d3f755f514dd876c4e3dfd4ea151ca848b3e809e0930ad9903a53f515db4ba0fb9ccf2e59af31f2864d7edd3caa79142c4f63cd7c2b73bfe6bae3cc35ec9c57d17a07a7950663372af68196bce7a7710be0bfa86874126e8041977989e6e7fd57d3c8ab2f8a8b1684e27e6297b65138f4dac1858bb16bbe1bf1"
	clientData, _ := hex.DecodeString(clientHex)

	frames := parseWebSocketFrames(clientData)
	if len(frames) == 0 {
		t.Fatal("expected at least 1 frame")
	}

	frame := frames[0]
	if !frame.masked {
		t.Errorf("client frame should be masked")
	}
	if len(frame.maskKey) != 4 {
		t.Errorf("expected 4-byte mask key, got %d", len(frame.maskKey))
	}
}

// TestParseWebSocketFramesMalformed guards against a previously-found crash:
// arbitrary (non-WebSocket) TCP bytes whose first byte sets the 127 extended-length
// flag caused binary.BigEndian.Uint64 to produce a huge value that overflowed int
// to a negative number, panicking the subsequent slice. The parser must instead
// return safely without panicking on any input.
func TestParseWebSocketFramesMalformed(t *testing.T) {
	cases := map[string]string{
		// 0x?? 0x7f triggers the 64-bit extended length path with garbage following.
		"ext64-overflow": "817fffffffffffffffffdeadbeefcafebabe",
		// 126 (16-bit) extended length but truncated buffer.
		"ext16-truncated": "01fe",
		// 127 (64-bit) extended length but truncated buffer.
		"ext64-truncated": "027f0011",
		// Masked flag set but no mask key bytes follow.
		"masked-truncated": "8185",
		// Plausible-looking length that runs past the buffer end.
		"len-overrun": "817e0f00aabb",
		// Random binary that is definitely not WebSocket framing.
		"random": "deadbeef00112233445566778899aabbccddeeff",
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(h)
			if err != nil {
				t.Fatalf("bad test hex: %v", err)
			}
			// Must not panic. Result may be empty or partial; we only assert safety.
			_ = parseWebSocketFrames(data)
		})
	}
}

func TestUnmaskWebSocketPayload(t *testing.T) {
	// Simple test with known mask
	maskKey := []byte{0x80, 0x00, 0x00, 0x00}
	masked := []byte{0x80, 0x00, 0x00, 0x00, 0x81, 0x01}

	unmasked := unmaskWebSocketPayload(masked, maskKey)

	expected := []byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x01}
	for i := range expected {
		if unmasked[i] != expected[i] {
			t.Errorf("byte %d: expected 0x%02x, got 0x%02x", i, expected[i], unmasked[i])
		}
	}
}

func TestDeriveVShellKeyHex(t *testing.T) {
	salt := "Pr0duct10n_S4lt_2024_VSh3ll_X"
	key := deriveVShellKeyHex(salt)

	if len(key) != 32 {
		t.Errorf("expected 32-byte hex key, got %d", len(key))
	}

	// Verify it's hex-encoded
	_, err := hex.DecodeString(string(key))
	if err != nil {
		t.Errorf("key should be valid hex: %v", err)
	}
}

func TestDecryptVShellWebSocketFrame(t *testing.T) {
	salt := "Pr0duct10n_S4lt_2024_VSh3ll_X"
	key := deriveVShellKeyHex(salt)

	// Full WebSocket frame: Server→client unmasked frame with VShell payload
	// Frame format: [0x81 0x32] + [VShell message: 4-byte len + 12-byte nonce + ciphertext + tag]
	serverHex := "81322e00000008b14ef5aad7b1b7fab1385d5c84f32bc8bff4f647a9aa10b1edf883fe0585541d2d6ad18b8d52517e0054531efd"
	frameData, _ := hex.DecodeString(serverHex)

	messages := extractVShellWebSocketPayloads(frameData, key)

	if len(messages) == 0 {
		t.Fatal("expected at least one decrypted message")
	}

	plaintext := string(messages[0].plaintext)
	expected := `{"type": "hb_ack"}`
	if plaintext != expected {
		t.Errorf("expected %q, got: %q", expected, plaintext)
	}
}

package engine

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

// buildVShellInnerMessage builds the VShell inner application frame:
// [4-byte LE total_len][12-byte nonce][ciphertext][16-byte GCM tag].
// total_len covers nonce+ciphertext+tag (everything after the 4-byte prefix),
// matching the protocol confirmed by the public reverse-engineering writeup.
func buildVShellInnerMessage(t *testing.T, key, plaintext []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	// Deterministic nonce for the test (12 zero bytes); GCM seal appends the tag.
	nonce := make([]byte, gcm.NonceSize())
	sealed := gcm.Seal(nil, nonce, plaintext, nil) // ciphertext || tag
	body := append(append([]byte{}, nonce...), sealed...)
	out := make([]byte, 4+len(body))
	binary.LittleEndian.PutUint32(out[:4], uint32(len(body)))
	copy(out[4:], body)
	return out
}

// buildMaskedClientFrame wraps an application payload in a client→server
// WebSocket text frame (FIN=1, opcode=0x1, MASK=1) with the given 4-byte mask.
func buildMaskedClientFrame(payload, mask []byte) []byte {
	masked := make([]byte, len(payload))
	for i, b := range payload {
		masked[i] = b ^ mask[i%4]
	}
	var hdr []byte
	if len(payload) < 126 {
		hdr = []byte{0x81, byte(0x80 | len(payload))}
	} else if len(payload) <= 0xffff {
		hdr = []byte{0x81, 0x80 | 126, byte(len(payload) >> 8), byte(len(payload))}
	} else {
		hdr = make([]byte, 10)
		hdr[0] = 0x81
		hdr[1] = 0x80 | 127
		binary.BigEndian.PutUint64(hdr[2:], uint64(len(payload)))
	}
	frame := append([]byte{}, hdr...)
	frame = append(frame, mask...)
	frame = append(frame, masked...)
	return frame
}

// TestWSFrameInnerPayloadsUnmasksClientFrame proves the production wiring:
// a masked client→server WebSocket frame carrying a VShell GCM message is
// unmasked by wsFrameInnerPayloads, and the recovered inner bytes decrypt via
// the same splitVShellFrames + decryptAESGCMFrame pipeline the decrypt path uses.
func TestWSFrameInnerPayloadsUnmasksClientFrame(t *testing.T) {
	salt := "Pr0duct10n_S4lt_2024_VSh3ll_X"
	key := deriveVShellKeyHex(salt) // hex(md5(salt)) → 32-byte AES-256 key

	plaintext := []byte(`{"type":"cmd","data":"whoami"}`)
	inner := buildVShellInnerMessage(t, key, plaintext)

	mask := []byte{0x1a, 0x2b, 0x3c, 0x4d} // realistic non-zero random mask
	frame := buildMaskedClientFrame(inner, mask)

	// Step 1: production helper strips WS framing + client mask.
	payloads := wsFrameInnerPayloads(frame)
	if len(payloads) != 1 {
		t.Fatalf("expected 1 inner payload, got %d", len(payloads))
	}
	if string(payloads[0]) != string(inner) {
		t.Fatalf("unmasked inner payload mismatch:\n got=%x\nwant=%x", payloads[0], inner)
	}

	// Step 2: the existing VShell pipeline splits + decrypts the inner bytes.
	frames := splitVShellFrames(payloads[0])
	if len(frames) == 0 {
		t.Fatal("splitVShellFrames returned no frames")
	}
	pt, err := decryptAESGCMFrame(key, frames[0])
	if err != nil {
		t.Fatalf("decryptAESGCMFrame failed: %v", err)
	}
	if string(pt) != string(plaintext) {
		t.Fatalf("decrypted plaintext mismatch: got %q want %q", pt, plaintext)
	}
}

// TestWSFrameInnerPayloadsServerFrame confirms the helper also handles
// unmasked server→client frames (no mask bit) and returns the raw payload.
func TestWSFrameInnerPayloadsServerFrame(t *testing.T) {
	salt := "Pr0duct10n_S4lt_2024_VSh3ll_X"
	key := deriveVShellKeyHex(salt)

	plaintext := []byte(`{"type":"hb_ack"}`)
	inner := buildVShellInnerMessage(t, key, plaintext)

	// Server frame: FIN=1, opcode=0x1, MASK=0, short length.
	frame := append([]byte{0x81, byte(len(inner))}, inner...)

	payloads := wsFrameInnerPayloads(frame)
	if len(payloads) != 1 {
		t.Fatalf("expected 1 inner payload, got %d", len(payloads))
	}
	frames := splitVShellFrames(payloads[0])
	pt, err := decryptAESGCMFrame(key, frames[0])
	if err != nil {
		t.Fatalf("decryptAESGCMFrame failed: %v", err)
	}
	if string(pt) != string(plaintext) {
		t.Fatalf("decrypted plaintext mismatch: got %q want %q", pt, plaintext)
	}
}

// TestWSFrameInnerPayloadsNonWebSocket confirms the helper returns nil for
// data that is not a WebSocket frame, so the caller falls back to raw handling.
func TestWSFrameInnerPayloadsNonWebSocket(t *testing.T) {
	// Looks like an HTTP request, not a WS data frame.
	if got := wsFrameInnerPayloads([]byte("GET /ws HTTP/1.1\r\nHost: x\r\n\r\n")); got != nil {
		t.Fatalf("expected nil for non-WebSocket data, got %d payloads", len(got))
	}
}

// TestWSFrameInnerPayloadsMultipleFrames confirms that a single TCP segment
// carrying several concatenated WebSocket frames yields one inner payload per
// data frame, each correctly unmasked. This mirrors the real capture where a
// client batches multiple VShell messages into one segment.
func TestWSFrameInnerPayloadsMultipleFrames(t *testing.T) {
	salt := "Pr0duct10n_S4lt_2024_VSh3ll_X"
	key := deriveVShellKeyHex(salt)

	plaintexts := [][]byte{
		[]byte(`{"type":"cmd","data":"id"}`),
		[]byte(`{"type":"cmd","data":"uname -a"}`),
		[]byte(`{"type":"hb"}`),
	}
	masks := [][]byte{
		{0x11, 0x22, 0x33, 0x44},
		{0xa1, 0xb2, 0xc3, 0xd4},
		{0x0f, 0xf0, 0x0f, 0xf0},
	}

	var stream []byte
	inners := make([][]byte, len(plaintexts))
	for i, pt := range plaintexts {
		inner := buildVShellInnerMessage(t, key, pt)
		inners[i] = inner
		stream = append(stream, buildMaskedClientFrame(inner, masks[i])...)
	}

	payloads := wsFrameInnerPayloads(stream)
	if len(payloads) != len(plaintexts) {
		t.Fatalf("expected %d inner payloads, got %d", len(plaintexts), len(payloads))
	}
	for i := range plaintexts {
		if string(payloads[i]) != string(inners[i]) {
			t.Fatalf("frame %d unmasked payload mismatch", i)
		}
		frames := splitVShellFrames(payloads[i])
		if len(frames) == 0 {
			t.Fatalf("frame %d: splitVShellFrames returned nothing", i)
		}
		pt, err := decryptAESGCMFrame(key, frames[0])
		if err != nil {
			t.Fatalf("frame %d: decrypt failed: %v", i, err)
		}
		if string(pt) != string(plaintexts[i]) {
			t.Fatalf("frame %d: got %q want %q", i, pt, plaintexts[i])
		}
	}
}

// TestWSFrameInnerPayloadsSkipsControlFrames confirms control frames
// (ping/pong/close, opcode 0x8-0xA) interleaved with data frames are skipped,
// while the data frame's payload is still recovered.
func TestWSFrameInnerPayloadsSkipsControlFrames(t *testing.T) {
	salt := "Pr0duct10n_S4lt_2024_VSh3ll_X"
	key := deriveVShellKeyHex(salt)

	inner := buildVShellInnerMessage(t, key, []byte(`{"type":"cmd","data":"ls"}`))
	dataFrame := buildMaskedClientFrame(inner, []byte{0x55, 0x66, 0x77, 0x88})

	// Unmasked server ping (opcode 0x9) and pong (0xA) framing around the data.
	ping := []byte{0x89, 0x00}
	pong := []byte{0x8a, 0x00}

	stream := append([]byte{}, ping...)
	stream = append(stream, dataFrame...)
	stream = append(stream, pong...)

	payloads := wsFrameInnerPayloads(stream)
	if len(payloads) != 1 {
		t.Fatalf("expected exactly 1 data payload (control frames skipped), got %d", len(payloads))
	}
	frames := splitVShellFrames(payloads[0])
	pt, err := decryptAESGCMFrame(key, frames[0])
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if string(pt) != `{"type":"cmd","data":"ls"}` {
		t.Fatalf("unexpected plaintext: %q", pt)
	}
}

// TestC2DecryptVShellUnmasksClientWebSocketStream is the end-to-end production
// test: a masked client→server WebSocket frame is fed through the full public
// C2Decrypt API (stream scope → collectVShellStreamDecryptCandidates →
// ws-unmask wiring → GCM pipeline) and must yield a decrypted record tagged
// with the ws-unmask transform. This is the regression guard for the bug where
// production never stripped the client mask, leaving client→server traffic
// permanently undecryptable.
func TestC2DecryptVShellUnmasksClientWebSocketStream(t *testing.T) {
	salt := "Pr0duct10n_S4lt_2024_VSh3ll_X"
	vkey := "vk_prod_2024"
	key := deriveVShellKeyHex(salt)

	plaintext := []byte(`{"VerifyKey":"vk_prod_2024","cmd":"ws-client-cmd"}`)
	inner := buildVShellInnerMessage(t, key, plaintext)
	frame := buildMaskedClientFrame(inner, []byte{0x1a, 0x2b, 0x3c, 0x4d})

	svc := NewService(NopEmitter{})
	defer svc.packetStore.Close()

	packets := []model.Packet{{
		ID:         301,
		Timestamp:  "2026-06-03T12:00:00Z",
		SourceIP:   "192.168.116.129",
		SourcePort: 51000,
		DestIP:     "103.45.67.89",
		DestPort:   8443,
		Protocol:   "TCP",
		Payload:    hexEncodeForTest(frame),
		StreamID:   77,
	}}
	if err := svc.packetStore.Append(packets); err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	svc.rawStreamIndex[streamCacheKey("TCP", 77)] = model.ReassembledStream{
		StreamID: 77,
		Protocol: "TCP",
		From:     "192.168.116.129",
		To:       "103.45.67.89",
		Chunks: []model.StreamChunk{
			{PacketID: 301, Direction: "client", Body: bytesToColonHex(frame)},
		},
	}

	result, err := svc.C2Decrypt(context.Background(), model.C2DecryptRequest{
		Family: "vshell",
		Scope:  model.C2DecryptScope{StreamIDs: []int64{77}},
		VShell: model.C2VShellDecryptOptions{VKey: vkey, Salt: salt, Mode: "auto"},
	})
	if err != nil {
		t.Fatalf("C2Decrypt() error = %v", err)
	}
	if result.DecryptedCount == 0 {
		for _, rec := range result.Records {
			t.Logf("record: transform=%v algo=%s err=%q preview=%q", rec.Tags, rec.Algorithm, rec.Error, rec.PlaintextPreview)
		}
		t.Fatalf("expected decrypted client WebSocket record, got status=%s candidates=%d", result.Status, result.TotalCandidates)
	}
	if !hasDecryptedRecordWithAlgorithm(result, "ws-client-cmd", "ws-unmask-client") {
		t.Fatalf("expected ws-unmask-client decrypt, got %+v", result.Records)
	}
}

func hexEncodeForTest(b []byte) string {
	const hexDigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexDigits[c>>4]
		out[i*2+1] = hexDigits[c&0x0f]
	}
	return string(out)
}

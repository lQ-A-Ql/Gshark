package engine

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestVShellDecryptAnalysis(t *testing.T) {
	key := deriveVShellKey("Pr0duct10n_S4lt_2024_VSh3ll_X")
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)

	// Server→client frame 3255: unmasked, 50 bytes, decrypts to {"type": "hb_ack"}
	serverPayload := "81322e00000008b14ef5aad7b1b7fab1385d5c84f32bc8bff4f647a9aa10b1edf883fe0585541d2d6ad18b8d52517e0054531efd"
	rawServer, _ := hex.DecodeString(serverPayload)
	serverData := rawServer[2:]
	msgLen := binary.LittleEndian.Uint32(serverData[:4])
	serverMsg := serverData[4 : 4+msgLen]
	nonce := serverMsg[:12]
	ct := serverMsg[12:]
	plaintext, _ := gcm.Open(nil, nonce, ct, nil)
	fmt.Printf("Server frame 3255: msgLen=%d plaintext=%q\n", msgLen, string(plaintext))

	// Client→server frame 3252: masked with key 0x80000000
	// This TCP segment likely contains MULTIPLE WebSocket frames
	clientPayload := "81fe009f800000007c2f121ee72f121e3380f0b9a89c95eb18f1f3a4cc19dda26dcf16c95a880e380c28ea68d71d915acd6d3f755f514dd876c4e3dfd4ea151ca848b3e809e0930ad9903a53f515db4ba0fb9ccf2e59af31f2864d7edd3caa79142c4f63cd7c2b73bfe6bae3cc35ec9c57d17a07a7950663372af68196bce7a7710be0bfa86874126e8041977989e6e7fd57d3c8ab2f8a8b1684e27e6297b65138f4dac1858bb16bbe1bf1"
	rawClient, _ := hex.DecodeString(clientPayload)

	// Parse as concatenated WebSocket frames
	frames := parseWebSocketFrames(rawClient)
	fmt.Printf("\nClient TCP segment: %d bytes, found %d WebSocket frames\n", len(rawClient), len(frames))

	for i, frame := range frames {
		fmt.Printf("\n  Frame %d: masked=%v payload=%d bytes", i, frame.masked, len(frame.payload))
		if frame.masked {
			fmt.Printf(" mask=%s", hex.EncodeToString(frame.maskKey))
		}
		fmt.Println()

		// Unmask if needed
		data := make([]byte, len(frame.payload))
		copy(data, frame.payload)
		if frame.masked {
			for j, b := range frame.payload {
				data[j] = b ^ frame.maskKey[j%4]
			}
		}

		// Skip WebSocket framing (opcode byte) — try VShell message parsing
		// VShell message: [4-byte LE length][12-byte nonce][ciphertext][16-byte GCM tag]
		if len(data) >= 4 {
			vshellLen := binary.LittleEndian.Uint32(data[:4])
			if int(vshellLen) == len(data)-4 && int(vshellLen) >= 12+16 {
				msg := data[4 : 4+vshellLen]
				n := msg[:12]
				c := msg[12:]
				if pt, err := gcm.Open(nil, n, c, nil); err == nil {
					fmt.Printf("    VShell message (len=%d): %q\n", vshellLen, string(pt))
					continue
				}
			}
		}

		// Try direct AES-GCM on the raw payload (no VShell length prefix)
		if len(data) >= 12+16 {
			n := data[:12]
			c := data[12:]
			if pt, err := gcm.Open(nil, n, c, nil); err == nil {
				fmt.Printf("    Direct AES-GCM: %q\n", string(pt))
				continue
			}
		}

		// Try skipping first byte (WebSocket opcode might interfere)
		if len(data) > 12+16 {
			n := data[1:13]
			c := data[13:]
			if pt, err := gcm.Open(nil, n, c, nil); err == nil {
				fmt.Printf("    Skip-1byte AES-GCM: %q\n", string(pt))
				continue
			}
		}

		fmt.Printf("    Could not decrypt (data prefix: %s)\n", hex.EncodeToString(data[:minTestHelper(16, len(data))]))
	}
}

// Legacy test-only WebSocket parser (removed - use production version from vshell_websocket_decrypt.go)
// type wsFrame and parseWebSocketFrames are now imported from vshell_websocket_decrypt.go

func deriveVShellKey(salt string) []byte {
	sum := md5.Sum([]byte(salt))
	return []byte(hex.EncodeToString(sum[:]))
}

func minTestHelper(a, b int) int {
	if a < b {
		return a
	}
	return b
}

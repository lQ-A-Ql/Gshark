package engine

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
)

// parseWebSocketFrames parses concatenated WebSocket frames from raw TCP data.
// Supports both masked (client→server) and unmasked (server→client) frames.
func parseWebSocketFrames(data []byte) []wsFrame {
	var frames []wsFrame
	offset := 0
	for offset < len(data) {
		if offset+2 > len(data) {
			break
		}
		b0 := data[offset]
		b1 := data[offset+1]
		isMasked := b1&0x80 != 0
		payloadLen := int(b1 & 0x7f)
		headerLen := 2

		if payloadLen == 126 {
			if offset+4 > len(data) {
				break
			}
			payloadLen = int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
			headerLen = 4
		} else if payloadLen == 127 {
			if offset+10 > len(data) {
				break
			}
			extended := binary.BigEndian.Uint64(data[offset+2 : offset+10])
			// Per RFC 6455 the most-significant bit MUST be 0, and a real frame
			// cannot exceed the remaining buffer. Guard against the int overflow
			// (huge uint64 → negative int) that arbitrary non-WebSocket bytes
			// would otherwise trigger when slicing below.
			if extended > uint64(len(data)) {
				break
			}
			payloadLen = int(extended)
			headerLen = 10
		}

		// Defensive bound: payloadLen is untrusted on non-WebSocket streams.
		if payloadLen < 0 || payloadLen > len(data) {
			break
		}

		maskKeyOffset := offset + headerLen
		payloadOffset := maskKeyOffset
		var maskKey []byte
		if isMasked {
			if maskKeyOffset+4 > len(data) {
				break
			}
			maskKey = data[maskKeyOffset : maskKeyOffset+4]
			payloadOffset = maskKeyOffset + 4
		}

		if payloadOffset < 0 || payloadOffset > len(data) || payloadOffset+payloadLen > len(data) {
			break
		}

		frames = append(frames, wsFrame{
			masked:  isMasked,
			maskKey: maskKey,
			payload: data[payloadOffset : payloadOffset+payloadLen],
			opcode:  b0 & 0x0f,
		})
		offset = payloadOffset + payloadLen
	}
	return frames
}

type wsFrame struct {
	masked  bool
	maskKey []byte
	payload []byte
	opcode  byte
}

// unmaskWebSocketPayload unmasks WebSocket client→server frames.
func unmaskWebSocketPayload(payload []byte, maskKey []byte) []byte {
	if len(maskKey) != 4 {
		return payload
	}
	unmasked := make([]byte, len(payload))
	for i, b := range payload {
		unmasked[i] = b ^ maskKey[i%4]
	}
	return unmasked
}

// decryptVShellWebSocketFrame attempts to decrypt VShell message(s) from WebSocket payload.
// VShell WebSocket message format variants:
// - [4-byte LE length][12-byte nonce][ciphertext][16-byte GCM tag]
// - OR direct: [12-byte nonce][ciphertext][16-byte GCM tag]
// - OR concatenated: multiple messages without individual length prefixes
// Returns multiple plaintexts if the payload contains multiple messages.
func decryptVShellWebSocketFrame(payload []byte, gcm cipher.AEAD) ([][]byte, bool) {
	var plaintexts [][]byte

	// Strategy 1: Try single message decryption (with or without length prefix)
	if pt, ok := trySingleVShellMessage(payload, gcm); ok {
		return [][]byte{pt}, true
	}

	// Strategy 2: Try multi-message split with length prefixes (4-byte LE per message)
	if pts, ok := tryMultiMessageWithLengthPrefix(payload, gcm); ok && len(pts) > 0 {
		return pts, true
	}

	// Strategy 3: Try scanning for GCM messages without length prefixes
	// This handles the case where multiple VShell messages are concatenated directly
	if pts, ok := tryScanGCMMessages(payload, gcm); ok && len(pts) > 0 {
		return pts, true
	}

	// Strategy 4: Try skipping 1-4 byte header (protocol variants)
	for skip := 1; skip <= 4 && skip < len(payload); skip++ {
		if pt, ok := trySingleVShellMessage(payload[skip:], gcm); ok {
			plaintexts = append(plaintexts, pt)
			break
		}
	}

	return plaintexts, len(plaintexts) > 0
}

// tryMultiMessageWithLengthPrefix attempts to parse multiple messages with 4-byte LE length prefixes.
func tryMultiMessageWithLengthPrefix(payload []byte, gcm cipher.AEAD) ([][]byte, bool) {
	var plaintexts [][]byte
	offset := 0

	for offset+4 <= len(payload) {
		msgLen := binary.LittleEndian.Uint32(payload[offset : offset+4])

		// Validate length reasonableness
		if msgLen == 0 || msgLen > 10*1024*1024 || int(msgLen) > len(payload)-offset-4 {
			break
		}

		// Extract message body
		msgData := payload[offset+4 : offset+4+int(msgLen)]

		// Try to decrypt
		if len(msgData) >= gcm.NonceSize()+gcm.Overhead() {
			nonce := msgData[:gcm.NonceSize()]
			ct := msgData[gcm.NonceSize():]
			if pt, err := gcm.Open(nil, nonce, ct, nil); err == nil {
				plaintexts = append(plaintexts, pt)
				offset += 4 + int(msgLen)
				continue
			}
		}
		break
	}

	return plaintexts, len(plaintexts) > 0
}

// tryScanGCMMessages scans payload for AES-GCM messages without length prefixes.
// This handles concatenated messages where each message is: [12-byte nonce][ciphertext][16-byte tag]
func tryScanGCMMessages(payload []byte, gcm cipher.AEAD) ([][]byte, bool) {
	var plaintexts [][]byte
	minMessageSize := gcm.NonceSize() + gcm.Overhead() // 12 + 16 = 28 bytes minimum

	offset := 0
	for offset < len(payload) {
		if offset+minMessageSize > len(payload) {
			break
		}

		// Try different message lengths at this offset
		found := false
		for end := offset + minMessageSize; end <= len(payload); end++ {
			candidate := payload[offset:end]
			if len(candidate) < minMessageSize {
				continue
			}

			nonce := candidate[:gcm.NonceSize()]
			ct := candidate[gcm.NonceSize():]

			if pt, err := gcm.Open(nil, nonce, ct, nil); err == nil {
				plaintexts = append(plaintexts, pt)
				offset = end
				found = true
				break
			}
		}

		if !found {
			break
		}
	}

	return plaintexts, len(plaintexts) > 0
}

// trySingleVShellMessage attempts to decrypt a single VShell message.
func trySingleVShellMessage(payload []byte, gcm cipher.AEAD) ([]byte, bool) {
	// Try with 4-byte length prefix (standard VShell format)
	if len(payload) >= 4 {
		msgLen := binary.LittleEndian.Uint32(payload[:4])
		if int(msgLen) == len(payload)-4 && int(msgLen) >= gcm.NonceSize()+gcm.Overhead() {
			msg := payload[4 : 4+msgLen]
			nonce := msg[:gcm.NonceSize()]
			ct := msg[gcm.NonceSize():]
			if pt, err := gcm.Open(nil, nonce, ct, nil); err == nil {
				return pt, true
			}
		}
	}

	// Try direct AES-GCM (no length prefix)
	if len(payload) >= gcm.NonceSize()+gcm.Overhead() {
		nonce := payload[:gcm.NonceSize()]
		ct := payload[gcm.NonceSize():]
		if pt, err := gcm.Open(nil, nonce, ct, nil); err == nil {
			return pt, true
		}
	}

	return nil, false
}

// wsFrameInnerPayloads parses WebSocket frames from raw stream bytes and returns
// the inner application payloads (unmasked for client→server frames), one entry
// per data frame. Control frames (ping/pong/close) are skipped.
//
// Unlike extractVShellWebSocketPayloads, this does NOT decrypt — it only strips
// the WebSocket framing + client mask so the caller can feed the inner bytes
// into the existing VShell GCM/CBC candidate pipeline. Per the VShell protocol,
// client→server frames carry a 4-byte XOR mask that MUST be removed before the
// inner [4-byte LE len][12-byte nonce][ciphertext][16-byte tag] is recoverable.
//
// Returns nil if the data does not parse into at least one WebSocket data frame,
// so callers can fall back to treating the bytes as a raw (non-WS) stream.
func wsFrameInnerPayloads(streamData []byte) [][]byte {
	frames := parseWebSocketFrames(streamData)
	if len(frames) == 0 {
		return nil
	}
	out := make([][]byte, 0, len(frames))
	sawDataFrame := false
	for _, frame := range frames {
		// Skip control frames (ping/pong/close: opcode 0x8-0xA).
		if frame.opcode >= 0x8 {
			continue
		}
		sawDataFrame = true
		payload := frame.payload
		if frame.masked {
			payload = unmaskWebSocketPayload(payload, frame.maskKey)
		}
		if len(payload) == 0 {
			continue
		}
		out = append(out, payload)
	}
	if !sawDataFrame {
		return nil
	}
	return out
}

// extractVShellWebSocketPayloads parses WebSocket frames from stream data and
// returns decrypted VShell messages.
func extractVShellWebSocketPayloads(streamData []byte, key []byte) []vshellWebSocketMessage {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil
	}

	frames := parseWebSocketFrames(streamData)
	messages := make([]vshellWebSocketMessage, 0, len(frames))

	for _, frame := range frames {
		// Skip control frames (ping/pong/close: opcode 0x8-0xA)
		if frame.opcode >= 0x8 {
			continue
		}

		payload := frame.payload
		if frame.masked {
			payload = unmaskWebSocketPayload(payload, frame.maskKey)
		}

		// Modified: handle multiple plaintexts
		plaintexts, ok := decryptVShellWebSocketFrame(payload, gcm)
		if ok {
			for _, plaintext := range plaintexts {
				messages = append(messages, vshellWebSocketMessage{
					payload:     payload,
					plaintext:   plaintext,
					masked:      frame.masked,
					frameLength: len(frame.payload),
				})
			}
		}
	}

	return messages
}

type vshellWebSocketMessage struct {
	payload     []byte
	plaintext   []byte
	masked      bool
	frameLength int
}

// deriveVShellKeyHex derives VShell AES-GCM key from salt using MD5.
// Returns the hex-encoded key (32 bytes) as used by VShell.
func deriveVShellKeyHex(salt string) []byte {
	sum := md5.Sum([]byte(salt))
	return []byte(hex.EncodeToString(sum[:]))
}

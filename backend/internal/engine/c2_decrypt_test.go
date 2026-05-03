package engine

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestC2DecryptVShellAESGCMWithSaltAndVKey(t *testing.T) {
	salt := "qwe123qwe"
	vkey := "verify-me"
	sum := md5.Sum([]byte(salt))
	key := []byte(hex.EncodeToString(sum[:]))
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher() error = %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("NewGCM() error = %v", err)
	}
	nonce := []byte{0x01, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	plaintext := []byte(`{"VerifyKey":"verify-me","cmd":"whoami"}`)
	frame := append(append([]byte{}, nonce...), gcm.Seal(nil, nonce, plaintext, nil)...)
	prefixed := make([]byte, 4+len(frame))
	binary.LittleEndian.PutUint32(prefixed[:4], uint32(len(frame)))
	copy(prefixed[4:], frame)

	svc := NewService(NopEmitter{}, nil)
	defer svc.packetStore.Close()
	if err := svc.packetStore.Append([]model.Packet{{
		ID:        1,
		Timestamp: "2026-05-02T10:00:00Z",
		Protocol:  "TCP",
		Payload:   base64.StdEncoding.EncodeToString(prefixed),
		StreamID:  9,
	}}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	result, err := svc.C2Decrypt(context.Background(), model.C2DecryptRequest{
		Family: "vshell",
		Scope:  model.C2DecryptScope{PacketIDs: []int64{1}},
		VShell: model.C2VShellDecryptOptions{VKey: vkey, Salt: salt, Mode: "auto"},
	})
	if err != nil {
		t.Fatalf("C2Decrypt() error = %v", err)
	}
	if result.DecryptedCount == 0 || result.Status == "failed" {
		t.Fatalf("expected decrypted VShell record, got %+v", result)
	}
	if !hasDecryptedRecord(result, "whoami", "verified") {
		t.Fatalf("expected verified plaintext, got %+v", result)
	}
}

func TestC2DecryptVShellAESGCMBigEndianFrame(t *testing.T) {
	salt := "paperplane"
	vkey := "fallsnow"
	sum := md5.Sum([]byte(salt + vkey))
	key := []byte(hex.EncodeToString(sum[:]))
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher() error = %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("NewGCM() error = %v", err)
	}
	nonce := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	plaintext := []byte(`{"VerifyKey":"fallsnow","cmd":"id"}`)
	frame := append(append([]byte{}, nonce...), gcm.Seal(nil, nonce, plaintext, nil)...)
	prefixed := make([]byte, 4+len(frame))
	binary.BigEndian.PutUint32(prefixed[:4], uint32(len(frame)))
	copy(prefixed[4:], frame)

	svc := NewService(NopEmitter{}, nil)
	defer svc.packetStore.Close()
	if err := svc.packetStore.Append([]model.Packet{{
		ID:        10,
		Timestamp: "2026-05-02T10:00:05Z",
		Protocol:  "TCP",
		Payload:   base64.StdEncoding.EncodeToString(prefixed),
		StreamID:  20,
	}}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	result, err := svc.C2Decrypt(context.Background(), model.C2DecryptRequest{
		Family: "vshell",
		Scope:  model.C2DecryptScope{PacketIDs: []int64{10}},
		VShell: model.C2VShellDecryptOptions{VKey: vkey, Salt: salt, Mode: "auto"},
	})
	if err != nil {
		t.Fatalf("C2Decrypt() error = %v", err)
	}
	if result.DecryptedCount == 0 || result.Status == "failed" {
		t.Fatalf("expected decrypted VShell record with big-endian framing, got %+v", result)
	}
	if !hasDecryptedRecord(result, "id", "verified") {
		t.Fatalf("expected verified plaintext, got %+v", result)
	}
}

func TestC2DecryptVShellRealTrafficSaltOnlyFrame(t *testing.T) {
	rawHex := "23000000" +
		"8a241e911a2a575afe7f6bcec57f5124557c52b2dfefe1ea45e9ae0d451c78e011cd57"

	stream, err := hex.DecodeString(rawHex)
	if err != nil {
		t.Fatalf("hex.DecodeString() error = %v", err)
	}

	svc := NewService(NopEmitter{}, nil)
	defer svc.packetStore.Close()
	if err := svc.packetStore.Append([]model.Packet{{
		ID:        100,
		Timestamp: "2026-05-02T12:00:00Z",
		Protocol:  "TCP",
		Payload:   hex.EncodeToString(stream),
		StreamID:  50,
	}}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	result, err := svc.C2Decrypt(context.Background(), model.C2DecryptRequest{
		Family: "vshell",
		Scope:  model.C2DecryptScope{PacketIDs: []int64{100}},
		VShell: model.C2VShellDecryptOptions{VKey: "fallsnow", Salt: "paperplane", Mode: "auto"},
	})
	if err != nil {
		t.Fatalf("C2Decrypt() error = %v", err)
	}
	if result.DecryptedCount == 0 {
		for _, rec := range result.Records {
			t.Logf("record: algo=%s err=%q preview=%q", rec.Algorithm, rec.Error, rec.PlaintextPreview)
		}
		t.Fatalf("expected decrypted record from real VShell traffic, got status=%s decrypted=%d", result.Status, result.DecryptedCount)
	}
	if !hasRecordWithAlgorithm(result, "md5(salt)") {
		t.Fatalf("expected real frame to decrypt with salt-only KDF, got %+v", result.Records)
	}
}

func TestC2DecryptVShellUsesRawStreamCandidateForSplitFrame(t *testing.T) {
	salt := "paperplane"
	vkey := "fallsnow"
	prefixed := encryptVShellGCMFrameForTest(t, salt, []byte(`{"VerifyKey":"fallsnow","cmd":"stream-split"}`), binary.LittleEndian)
	splitAt := 10

	svc := NewService(NopEmitter{}, nil)
	defer svc.packetStore.Close()
	packets := []model.Packet{
		{
			ID:         201,
			Timestamp:  "2026-05-02T12:10:00Z",
			SourceIP:   "192.168.116.129",
			SourcePort: 7788,
			DestIP:     "192.168.116.1",
			DestPort:   54750,
			Protocol:   "TCP",
			Payload:    hex.EncodeToString(prefixed[:splitAt]),
			StreamID:   23,
		},
		{
			ID:         202,
			Timestamp:  "2026-05-02T12:10:01Z",
			SourceIP:   "192.168.116.129",
			SourcePort: 7788,
			DestIP:     "192.168.116.1",
			DestPort:   54750,
			Protocol:   "TCP",
			Payload:    hex.EncodeToString(prefixed[splitAt:]),
			StreamID:   23,
		},
	}
	if err := svc.packetStore.Append(packets); err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	svc.rawStreamIndex[streamCacheKey("TCP", 23)] = model.ReassembledStream{
		StreamID: 23,
		Protocol: "TCP",
		From:     "192.168.116.129",
		To:       "192.168.116.1",
		Chunks: []model.StreamChunk{
			{PacketID: 201, Direction: "client", Body: bytesToColonHex(prefixed[:splitAt])},
			{PacketID: 202, Direction: "client", Body: bytesToColonHex(prefixed[splitAt:])},
		},
	}

	result, err := svc.C2Decrypt(context.Background(), model.C2DecryptRequest{
		Family: "vshell",
		Scope:  model.C2DecryptScope{StreamIDs: []int64{23}},
		VShell: model.C2VShellDecryptOptions{VKey: vkey, Salt: salt, Mode: "auto"},
	})
	if err != nil {
		t.Fatalf("C2Decrypt() error = %v", err)
	}
	if result.DecryptedCount == 0 {
		for _, rec := range result.Records {
			t.Logf("record: packet=%d transform=%v algo=%s err=%q preview=%q", rec.PacketID, rec.Tags, rec.Algorithm, rec.Error, rec.PlaintextPreview)
		}
		t.Fatalf("expected decrypted VShell stream record, got status=%s candidates=%d", result.Status, result.TotalCandidates)
	}
	if !hasDecryptedRecordWithAlgorithm(result, "stream-split", "raw-stream-client-hex") {
		t.Fatalf("expected decrypted raw stream candidate, got %+v", result.Records)
	}
}

func TestC2DecryptVShellRawStreamCandidateSurvivesPacketCandidateCap(t *testing.T) {
	salt := "paperplane"
	vkey := "fallsnow"
	prefixed := encryptVShellGCMFrameForTest(t, salt, []byte(`{"VerifyKey":"fallsnow","cmd":"stream-cap"}`), binary.LittleEndian)
	splitAt := 4

	svc := NewService(NopEmitter{}, nil)
	defer svc.packetStore.Close()
	packets := make([]model.Packet, 0, c2DecryptMaxRecords+100)
	for i := 0; i < c2DecryptMaxRecords+100; i++ {
		packets = append(packets, model.Packet{
			ID:         int64(1000 + i),
			Timestamp:  "2026-05-02T12:20:00Z",
			SourceIP:   "192.168.116.129",
			SourcePort: 7788,
			DestIP:     "192.168.116.1",
			DestPort:   54750,
			Protocol:   "TCP",
			Payload:    hex.EncodeToString([]byte{byte(i), byte(i >> 8), 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}),
			StreamID:   23,
		})
	}
	if err := svc.packetStore.Append(packets); err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	svc.rawStreamIndex[streamCacheKey("TCP", 23)] = model.ReassembledStream{
		StreamID: 23,
		Protocol: "TCP",
		From:     "192.168.116.129",
		To:       "192.168.116.1",
		Chunks: []model.StreamChunk{
			{PacketID: 1000, Direction: "client", Body: bytesToColonHex(prefixed[:splitAt])},
			{PacketID: 1001, Direction: "client", Body: bytesToColonHex(prefixed[splitAt:])},
		},
	}

	result, err := svc.C2Decrypt(context.Background(), model.C2DecryptRequest{
		Family: "vshell",
		Scope:  model.C2DecryptScope{StreamIDs: []int64{23}},
		VShell: model.C2VShellDecryptOptions{VKey: vkey, Salt: salt, Mode: "auto"},
	})
	if err != nil {
		t.Fatalf("C2Decrypt() error = %v", err)
	}
	if result.DecryptedCount == 0 {
		for _, rec := range result.Records {
			t.Logf("record: packet=%d transform=%v algo=%s err=%q preview=%q", rec.PacketID, rec.Tags, rec.Algorithm, rec.Error, rec.PlaintextPreview)
		}
		t.Fatalf("expected raw stream candidate to survive packet cap, got status=%s candidates=%d", result.Status, result.TotalCandidates)
	}
	if !hasDecryptedRecordWithAlgorithm(result, "stream-cap", "raw-stream-client-hex") {
		t.Fatalf("expected decrypted raw stream candidate before packet-level cap, got %+v", result.Records)
	}
}

func TestC2DecryptVShellKeepsHighValueServerFramePastRecordCap(t *testing.T) {
	salt := "paperplane"
	vkey := "fallsnow"
	clientStream := make([]byte, 0, (c2DecryptMaxRecords+80)*48)
	for i := 0; i < c2DecryptMaxRecords+80; i++ {
		clientStream = append(clientStream, encryptVShellGCMFrameForTest(t, salt, []byte{0x03, 0x03, 0x00, byte(i)}, binary.LittleEndian)...)
	}

	serverStream := make([]byte, 0, 80*64)
	for i := 0; i < 76; i++ {
		serverStream = append(serverStream, encryptVShellGCMFrameForTest(t, salt, []byte{0x05, 0x00, 0x00, 0x00, byte(i)}, binary.LittleEndian)...)
	}
	targetPlaintext := "hacked_by_fallsnow&paperplane(QAQ)\r\n"
	serverStream = append(serverStream, encryptVShellGCMFrameForTest(t, salt, []byte(targetPlaintext), binary.LittleEndian)...)

	svc := NewService(NopEmitter{}, nil)
	defer svc.packetStore.Close()
	if err := svc.packetStore.Append([]model.Packet{
		{
			ID:         6500,
			Timestamp:  "2026-05-03T10:00:00Z",
			SourceIP:   "192.168.116.1",
			SourcePort: 51512,
			DestIP:     "192.168.116.129",
			DestPort:   7788,
			Protocol:   "TCP",
			Payload:    hex.EncodeToString(clientStream[:64]),
			StreamID:   23,
		},
		{
			ID:         6526,
			Timestamp:  "2026-05-03T10:00:30Z",
			SourceIP:   "192.168.116.129",
			SourcePort: 7788,
			DestIP:     "192.168.116.1",
			DestPort:   51512,
			Protocol:   "TCP",
			Payload:    hex.EncodeToString(serverStream[len(serverStream)-64:]),
			StreamID:   23,
		},
	}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	svc.rawStreamIndex[streamCacheKey("TCP", 23)] = model.ReassembledStream{
		StreamID: 23,
		Protocol: "TCP",
		From:     "192.168.116.1",
		To:       "192.168.116.129",
		Chunks: []model.StreamChunk{
			{PacketID: 6500, Direction: "client", Body: bytesToColonHex(clientStream)},
			{PacketID: 6526, Direction: "server", Body: bytesToColonHex(serverStream)},
		},
	}

	result, err := svc.C2Decrypt(context.Background(), model.C2DecryptRequest{
		Family: "vshell",
		Scope:  model.C2DecryptScope{StreamIDs: []int64{23}},
		VShell: model.C2VShellDecryptOptions{VKey: vkey, Salt: salt, Mode: "auto"},
	})
	if err != nil {
		t.Fatalf("C2Decrypt() error = %v", err)
	}
	if len(result.Records) != c2DecryptMaxRecords {
		t.Fatalf("expected trimmed result cap %d, got %d", c2DecryptMaxRecords, len(result.Records))
	}
	if !hasDecryptedRecordWithAlgorithm(result, targetPlaintext, "raw-stream-server-hex") {
		for _, rec := range result.Records {
			if strings.Contains(rec.PlaintextPreview, "hacked_by") || rec.Direction == "server_to_client" {
				t.Logf("record: direction=%s tags=%v algo=%s preview=%q", rec.Direction, rec.Tags, rec.Algorithm, rec.PlaintextPreview)
			}
		}
		t.Fatalf("expected high-value late server plaintext to survive result cap, got status=%s decrypted=%d records=%d", result.Status, result.DecryptedCount, len(result.Records))
	}
}

func TestC2DecryptVShellDeprioritizesTimestampANSIAndShortNoisePastRecordCap(t *testing.T) {
	salt := "paperplane"
	vkey := "fallsnow"
	clientStream := make([]byte, 0, (c2DecryptMaxRecords+80)*64)
	noisePayloads := [][]byte{
		[]byte("2026-04-16 22:24:44"),
		[]byte("2026-04-16T14:39:26.139972268Z"),
		[]byte("\x1b[32m\x1b[0m\x1b[K"),
		{0x05, 0x03, 0x00, 0x00, 0x00, 0x1b, 0x00, 0x00, 0x00, 0xfc, 0xeb, 0x02, 0x00},
	}
	for i := 0; i < c2DecryptMaxRecords+80; i++ {
		clientStream = append(clientStream, encryptVShellGCMFrameForTest(t, salt, noisePayloads[i%len(noisePayloads)], binary.LittleEndian)...)
	}

	targetPlaintext := "hacked_by_fallsnow&paperplane(QAQ)\r\n"
	serverStream := encryptVShellGCMFrameForTest(t, salt, []byte(targetPlaintext), binary.LittleEndian)

	svc := NewService(NopEmitter{}, nil)
	defer svc.packetStore.Close()
	if err := svc.packetStore.Append([]model.Packet{
		{
			ID:         6600,
			Timestamp:  "2026-05-03T10:00:00Z",
			SourceIP:   "10.0.0.5",
			SourcePort: 4444,
			DestIP:     "10.0.0.8",
			DestPort:   51512,
			Protocol:   "TCP",
			Payload:    hex.EncodeToString(clientStream[:64]),
			StreamID:   24,
		},
		{
			ID:         6601,
			Timestamp:  "2026-05-03T10:00:01Z",
			SourceIP:   "10.0.0.8",
			SourcePort: 51512,
			DestIP:     "10.0.0.5",
			DestPort:   4444,
			Protocol:   "TCP",
			Payload:    hex.EncodeToString(serverStream),
			StreamID:   24,
		},
	}); err != nil {
		t.Fatalf("packet append error: %v", err)
	}
	svc.rawStreamIndex[streamCacheKey("TCP", 24)] = model.ReassembledStream{
		StreamID: 24,
		Protocol: "TCP",
		From:     "10.0.0.5",
		To:       "10.0.0.8",
		Chunks: []model.StreamChunk{
			{PacketID: 6600, Direction: "client", Body: bytesToColonHex(clientStream)},
			{PacketID: 6601, Direction: "server", Body: bytesToColonHex(serverStream)},
		},
	}

	result, err := svc.C2Decrypt(context.Background(), model.C2DecryptRequest{
		Family: "vshell",
		Scope:  model.C2DecryptScope{StreamIDs: []int64{24}},
		VShell: model.C2VShellDecryptOptions{VKey: vkey, Salt: salt, Mode: "auto"},
	})
	if err != nil {
		t.Fatalf("C2Decrypt() error = %v", err)
	}
	if len(result.Records) != c2DecryptMaxRecords {
		t.Fatalf("expected trimmed result cap %d, got %d", c2DecryptMaxRecords, len(result.Records))
	}
	if !hasDecryptedRecordWithAlgorithm(result, targetPlaintext, "raw-stream-server-hex") {
		for _, rec := range result.Records {
			if strings.Contains(rec.PlaintextPreview, "hacked_by") || rec.Direction == "server_to_client" {
				t.Logf("record: stream=%d direction=%s tags=%v algo=%s preview=%q", rec.StreamID, rec.Direction, rec.Tags, rec.Algorithm, rec.PlaintextPreview)
			}
		}
		t.Fatalf("expected high-value server plaintext to survive timestamp/ANSI/short-noise cap, got status=%s decrypted=%d records=%d", result.Status, result.DecryptedCount, len(result.Records))
	}
}

func TestVShellDecryptRecordScoreDeprioritizesTimestampANSIAndShortControl(t *testing.T) {
	target := model.C2DecryptedRecord{
		Confidence:       90,
		KeyStatus:        c2DecryptKeyStatusOK,
		PlaintextPreview: "hacked_by_fallsnow&paperplane(QAQ)\r\n",
		DecryptedLength:  37,
		Tags:             []string{"raw-stream-server-hex"},
	}
	noises := []model.C2DecryptedRecord{
		{Confidence: 90, KeyStatus: c2DecryptKeyStatusOK, PlaintextPreview: "2026-04-16 22:24:44", DecryptedLength: 19},
		{Confidence: 90, KeyStatus: c2DecryptKeyStatusOK, PlaintextPreview: "2026-04-16T14:39:26.139972268Z", DecryptedLength: 30},
		{Confidence: 90, KeyStatus: c2DecryptKeyStatusOK, PlaintextPreview: "\x1b[32m\x1b[0m\x1b[K", DecryptedLength: 11},
		{Confidence: 90, KeyStatus: c2DecryptKeyStatusOK, PlaintextPreview: string([]byte{0x05, 0x03, 0x00, 0x00, 0x00, 0x1b, 0x00, 0x00, 0x00, 0xfc, 0xeb, 0x02, 0x00}), DecryptedLength: 13},
	}
	targetScore := vshellDecryptRecordScore(target)
	for _, noise := range noises {
		if score := vshellDecryptRecordScore(noise); score >= targetScore {
			t.Fatalf("expected target score %d to outrank noise score %d for preview %q", targetScore, score, noise.PlaintextPreview)
		}
	}
}

func TestC2DecryptVShellKeepsLateRawStreamPastCandidateCap(t *testing.T) {
	salt := "paperplane"
	vkey := "fallsnow"
	noiseFrame := encryptVShellGCMFrameForTest(t, salt, []byte{0x05, 0x03, 0x00, 0x00, 0x00, 0x1b, 0x00, 0x00, 0x00, 0xfc, 0xeb, 0x02, 0x00}, binary.LittleEndian)
	targetPlaintext := "hacked_by_fallsnow&paperplane(QAQ)\r\n"
	targetFrame := encryptVShellGCMFrameForTest(t, salt, []byte(targetPlaintext), binary.LittleEndian)

	svc := NewService(NopEmitter{}, nil)
	defer svc.packetStore.Close()

	streamIDs := make([]int64, 0, c2DecryptMaxRecords+25)
	packets := make([]model.Packet, 0, c2DecryptMaxRecords+25)
	for i := 0; i < c2DecryptMaxRecords+24; i++ {
		streamID := int64(i)
		packetID := int64(7000 + i)
		streamIDs = append(streamIDs, streamID)
		packets = append(packets, model.Packet{
			ID:         packetID,
			Timestamp:  "2026-05-03T10:10:00Z",
			SourceIP:   "192.168.116.1",
			SourcePort: 51000 + i%1000,
			DestIP:     "192.168.116.129",
			DestPort:   7788,
			Protocol:   "TCP",
			Payload:    hex.EncodeToString(noiseFrame),
			StreamID:   streamID,
		})
		svc.rawStreamIndex[streamCacheKey("TCP", streamID)] = model.ReassembledStream{
			StreamID: streamID,
			Protocol: "TCP",
			From:     "192.168.116.1",
			To:       "192.168.116.129",
			Chunks: []model.StreamChunk{
				{PacketID: packetID, Direction: "client", Body: bytesToColonHex(noiseFrame)},
			},
		}
	}
	targetStreamID := int64(c2DecryptMaxRecords + 24)
	targetPacketID := int64(7000 + c2DecryptMaxRecords + 24)
	streamIDs = append(streamIDs, targetStreamID)
	packets = append(packets, model.Packet{
		ID:         targetPacketID,
		Timestamp:  "2026-05-03T10:12:00Z",
		SourceIP:   "192.168.116.129",
		SourcePort: 7788,
		DestIP:     "192.168.116.1",
		DestPort:   51512,
		Protocol:   "TCP",
		Payload:    hex.EncodeToString(targetFrame),
		StreamID:   targetStreamID,
	})
	svc.rawStreamIndex[streamCacheKey("TCP", targetStreamID)] = model.ReassembledStream{
		StreamID: targetStreamID,
		Protocol: "TCP",
		From:     "192.168.116.1",
		To:       "192.168.116.129",
		Chunks: []model.StreamChunk{
			{PacketID: targetPacketID, Direction: "server", Body: bytesToColonHex(targetFrame)},
		},
	}
	if err := svc.packetStore.Append(packets); err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	result, err := svc.C2Decrypt(context.Background(), model.C2DecryptRequest{
		Family: "vshell",
		Scope:  model.C2DecryptScope{StreamIDs: streamIDs},
		VShell: model.C2VShellDecryptOptions{VKey: vkey, Salt: salt, Mode: "auto"},
	})
	if err != nil {
		t.Fatalf("C2Decrypt() error = %v", err)
	}
	if len(result.Records) != c2DecryptMaxRecords {
		t.Fatalf("expected trimmed result cap %d, got %d", c2DecryptMaxRecords, len(result.Records))
	}
	if result.TotalCandidates <= c2DecryptMaxRecords {
		t.Fatalf("expected raw-stream candidates beyond cap, got totalCandidates=%d", result.TotalCandidates)
	}
	if !hasDecryptedRecordWithAlgorithm(result, targetPlaintext, "raw-stream-server-hex") {
		for _, rec := range result.Records {
			if strings.Contains(rec.PlaintextPreview, "hacked_by") || rec.Direction == "server_to_client" {
				t.Logf("record: stream=%d direction=%s tags=%v algo=%s preview=%q", rec.StreamID, rec.Direction, rec.Tags, rec.Algorithm, rec.PlaintextPreview)
			}
		}
		t.Fatalf("expected late server raw-stream plaintext to survive candidate-stage pressure, got status=%s decrypted=%d records=%d candidates=%d", result.Status, result.DecryptedCount, len(result.Records), result.TotalCandidates)
	}
	if !noteContains(result.Notes, "候选阶段已优先保留 raw-stream 双向重组结果") {
		t.Fatalf("expected raw-stream priority note, got %+v", result.Notes)
	}
}

func TestC2DecryptVShellAESCBCFallback(t *testing.T) {
	salt := "legacy-salt"
	sum := md5.Sum([]byte(salt))
	plaintext := []byte(`{"cmd":"ipconfig"}`)
	ciphertext := encryptC2AESCBCForTest(t, sum[:], sum[:], plaintext)

	svc := NewService(NopEmitter{}, nil)
	defer svc.packetStore.Close()
	if err := svc.packetStore.Append([]model.Packet{{
		ID:        2,
		Timestamp: "2026-05-02T10:00:01Z",
		Protocol:  "TCP",
		Payload:   hex.EncodeToString(ciphertext),
		StreamID:  10,
	}}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	result, err := svc.C2Decrypt(context.Background(), model.C2DecryptRequest{
		Family: "vshell",
		Scope:  model.C2DecryptScope{PacketIDs: []int64{2}},
		VShell: model.C2VShellDecryptOptions{Salt: salt, Mode: "aes_cbc_md5_salt"},
	})
	if err != nil {
		t.Fatalf("C2Decrypt() error = %v", err)
	}
	if result.DecryptedCount == 0 || !hasDecryptedRecord(result, "ipconfig", "") {
		t.Fatalf("expected cbc decrypted record, got %+v", result)
	}
}

func TestC2DecryptCSAESDirectKey(t *testing.T) {
	aesKey := []byte("0123456789abcdef")
	iv := []byte("abcdefghijklmnop")
	ciphertext := encryptC2AESCBCForTest(t, aesKey, iv, []byte(`{"command":"sleep","seconds":60}`))
	blob := append(append([]byte{}, iv...), ciphertext...)

	svc := NewService(NopEmitter{}, nil)
	defer svc.packetStore.Close()
	if err := svc.packetStore.Append([]model.Packet{{
		ID:        3,
		Timestamp: "2026-05-02T10:00:02Z",
		Protocol:  "HTTP",
		Payload:   "POST /submit.php HTTP/1.1\r\nHost: c2.test\r\n\r\n" + base64.StdEncoding.EncodeToString(blob),
		StreamID:  11,
	}}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	result, err := svc.C2Decrypt(context.Background(), model.C2DecryptRequest{
		Family: "cs",
		Scope:  model.C2DecryptScope{PacketIDs: []int64{3}},
		CS:     model.C2CSDecryptOptions{KeyMode: "aes_hmac", AESKey: hex.EncodeToString(aesKey), TransformMode: "auto"},
	})
	if err != nil {
		t.Fatalf("C2Decrypt() error = %v", err)
	}
	if result.DecryptedCount == 0 || !hasDecryptedRecord(result, "sleep", "") {
		t.Fatalf("expected CS decrypted record, got %+v", result)
	}
}

func TestC2DecryptHonorsCanceledContext(t *testing.T) {
	svc := NewService(NopEmitter{}, nil)
	defer svc.packetStore.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := svc.C2Decrypt(ctx, model.C2DecryptRequest{Family: "vshell", VShell: model.C2VShellDecryptOptions{Salt: "x"}})
	if err == nil {
		t.Fatal("expected canceled context error")
	}
}

func encryptC2AESCBCForTest(t *testing.T, key []byte, iv []byte, plaintext []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher() error = %v", err)
	}
	padding := block.BlockSize() - len(plaintext)%block.BlockSize()
	padded := append(append([]byte{}, plaintext...), bytesRepeatForTest(byte(padding), padding)...)
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)
	return out
}

func bytesRepeatForTest(value byte, count int) []byte {
	out := make([]byte, count)
	for i := range out {
		out[i] = value
	}
	return out
}

func encryptVShellGCMFrameForTest(t *testing.T, salt string, plaintext []byte, order binary.ByteOrder) []byte {
	t.Helper()
	sum := md5.Sum([]byte(salt))
	key := []byte(hex.EncodeToString(sum[:]))
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher() error = %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("NewGCM() error = %v", err)
	}
	nonce := []byte{0x8a, 0x24, 0x1e, 0x91, 0x1a, 0x2a, 0x57, 0x5a, 0xfe, 0x7f, 0x6b, 0xce}
	frame := append(append([]byte{}, nonce...), gcm.Seal(nil, nonce, plaintext, nil)...)
	prefixed := make([]byte, 4+len(frame))
	order.PutUint32(prefixed[:4], uint32(len(frame)))
	copy(prefixed[4:], frame)
	return prefixed
}

func hasDecryptedRecord(result model.C2DecryptResult, needle string, keyStatus string) bool {
	for _, record := range result.Records {
		if strings.Contains(record.PlaintextPreview, needle) && (keyStatus == "" || record.KeyStatus == keyStatus) {
			return true
		}
	}
	return false
}

func hasDecryptedRecordWithAlgorithm(result model.C2DecryptResult, plaintextNeedle string, algorithmNeedle string) bool {
	for _, record := range result.Records {
		if strings.Contains(record.PlaintextPreview, plaintextNeedle) && strings.Contains(record.Algorithm, algorithmNeedle) {
			return true
		}
		for _, tag := range record.Tags {
			if strings.Contains(record.PlaintextPreview, plaintextNeedle) && strings.Contains(tag, algorithmNeedle) {
				return true
			}
		}
	}
	return false
}

func hasRecordWithAlgorithm(result model.C2DecryptResult, algorithmNeedle string) bool {
	for _, record := range result.Records {
		if strings.Contains(record.Algorithm, algorithmNeedle) {
			return true
		}
		for _, tag := range record.Tags {
			if strings.Contains(tag, algorithmNeedle) {
				return true
			}
		}
	}
	return false
}

func noteContains(notes []string, needle string) bool {
	for _, note := range notes {
		if strings.Contains(note, needle) {
			return true
		}
	}
	return false
}

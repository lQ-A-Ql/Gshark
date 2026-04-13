package tshark

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestParseSDPCodecHints(t *testing.T) {
	hints := parseSDPCodecHints([]string{
		"rtpmap:96 H264/90000",
		"fmtp:96 packetization-mode=1; sprop-parameter-sets=Z0IAH5WoFAFuQA==,aM48gA==",
	})

	h264, ok := hints["96"]
	if !ok {
		t.Fatalf("expected payload type 96 in hints")
	}
	if h264.Name != "H264" {
		t.Fatalf("expected H264, got %q", h264.Name)
	}
	if h264.ClockRate != 90000 {
		t.Fatalf("expected clock rate 90000, got %d", h264.ClockRate)
	}
	if h264.Fmtp["packetization-mode"] != "1" {
		t.Fatalf("unexpected fmtp map: %#v", h264.Fmtp)
	}
}

func TestDetectMediaApplicationGameStreamPorts(t *testing.T) {
	app, tags := detectMediaApplication("rtsp setup stream", 48010, 47998)
	if app != "Moonlight / GameStream" {
		t.Fatalf("expected Moonlight / GameStream, got %q", app)
	}
	if !reflect.DeepEqual(tags, []string{"RTP", "GameStream Ports"}) {
		t.Fatalf("unexpected tags: %#v", tags)
	}
}

func TestReconstructH264Stream(t *testing.T) {
	builder := &mediaSessionBuilder{
		Codec: "H264",
		Packets: []rtpPacketRecord{
			{Payload: []byte{0x65, 0xAA, 0xBB}},
			{Payload: []byte{0x7C, 0x85, 0x11, 0x22}},
			{Payload: []byte{0x7C, 0x45, 0x33, 0x44}},
		},
	}

	payload, ext, err := reconstructH264Stream(builder)
	if err != nil {
		t.Fatalf("reconstructH264Stream returned error: %v", err)
	}
	if ext != ".h264" {
		t.Fatalf("expected .h264 extension, got %q", ext)
	}

	expected := []byte{
		0x00, 0x00, 0x00, 0x01, 0x65, 0xAA, 0xBB,
		0x00, 0x00, 0x00, 0x01, 0x65, 0x11, 0x22, 0x33, 0x44,
	}
	if !reflect.DeepEqual(payload, expected) {
		t.Fatalf("unexpected payload:\nwant=%#v\ngot =%#v", expected, payload)
	}
}

func TestParseGameStreamUDPPayload(t *testing.T) {
	raw, err := hexDecodeString("9000000000000000000000000000000000000000010000000500100020030001010000024d0100000000000167640c2aac2b403c")
	if err != nil {
		t.Fatalf("hexDecodeString() error = %v", err)
	}

	payload, seq, timestamp, ssrc, marker, ok := parseGameStreamUDPPayload(raw)
	if !ok {
		t.Fatalf("expected GameStream UDP payload to be recognized")
	}
	if seq != 0 {
		t.Fatalf("expected sequence 0, got %d", seq)
	}
	if timestamp != 0 {
		t.Fatalf("expected timestamp 0, got %d", timestamp)
	}
	if ssrc != "0x0" {
		t.Fatalf("expected ssrc 0x0, got %q", ssrc)
	}
	if marker {
		t.Fatalf("expected marker bit to be false")
	}

	builder := &mediaSessionBuilder{
		Application: "Moonlight / GameStream",
		Packets: []rtpPacketRecord{{
			Timestamp: timestamp,
			Payload:   payload,
		}},
	}
	processed := preprocessGameStreamPackets(builder)
	if len(processed.Packets) != 1 {
		t.Fatalf("expected one processed packet, got %d", len(processed.Packets))
	}
	if !bytes.HasPrefix(processed.Packets[0].Payload, []byte{0x00, 0x00, 0x00, 0x01, 0x67}) {
		previewLen := len(processed.Packets[0].Payload)
		if previewLen > 8 {
			previewLen = 8
		}
		t.Fatalf("expected stripped GameStream payload to start with Annex B SPS, got %#v", processed.Packets[0].Payload[:previewLen])
	}
}

func TestParseGameStreamUDPPayloadRejectsControlPacket(t *testing.T) {
	raw, err := hexDecodeString("800065fc86000004002601002200030000000846b3f435f84ee8a5daf4afaf3ede5c89e557209769e9fc5ede31db52ef8603000100280100240004000000e067e55e3609d67def3e71ec317d3e6f99208250071cfc9535cbd4b967679682")
	if err != nil {
		t.Fatalf("hexDecodeString() error = %v", err)
	}
	if _, _, _, _, _, ok := parseGameStreamUDPPayload(raw); ok {
		t.Fatalf("expected non-video GameStream control packet to be rejected")
	}
}

func TestDetectPacketCodecAnnexBH264(t *testing.T) {
	payload := []byte{0x00, 0x00, 0x00, 0x01, 0x67, 0x64, 0x00, 0x1f}
	if codec := detectPacketCodec(nil, payload); codec != "H264" {
		t.Fatalf("expected Annex-B payload to be detected as H264, got %q", codec)
	}
}

func TestIsLikelyRTPPayload(t *testing.T) {
	valid := []byte{
		0x80, 0x80, 0x76, 0x38,
		0x99, 0x59, 0x48, 0x23,
		0x88, 0x48, 0x19, 0xee,
		0x00, 0x01, 0x02, 0x03,
	}
	if !isLikelyRTPPayload(valid) {
		t.Fatalf("expected valid RTP-like payload to be recognized")
	}

	invalid := []byte{0x10, 0x20, 0x30, 0x40, 0x50}
	if isLikelyRTPPayload(invalid) {
		t.Fatalf("expected invalid payload to be rejected")
	}
}

func TestInferStaticRTPProfile(t *testing.T) {
	mediaType, codec, clockRate := inferStaticRTPProfile("0")
	if mediaType != "audio" || codec != "PCMU" || clockRate != 8000 {
		t.Fatalf("expected PT 0 to map to audio/PCMU/8000, got %q %q %d", mediaType, codec, clockRate)
	}

	mediaType, codec, clockRate = inferStaticRTPProfile("26")
	if mediaType != "video" || codec != "JPEG" || clockRate != 90000 {
		t.Fatalf("expected PT 26 to map to video/JPEG/90000, got %q %q %d", mediaType, codec, clockRate)
	}
}

func TestReconstructGameStreamBytestream(t *testing.T) {
	builder := &mediaSessionBuilder{
		Application: "Moonlight / GameStream",
		Packets: []rtpPacketRecord{
			{Payload: []byte{0x00, 0x00, 0x00, 0x01, 0x67, 0x64, 0x00, 0x1f}},
			{Payload: []byte{0xaa, 0xbb, 0xcc}},
			{Payload: []byte{0x01}},
			{Payload: []byte{0x02}},
			{Payload: []byte{0x03}},
			{Payload: []byte{0x04}},
			{Payload: []byte{0x05}},
			{Payload: []byte{0x06}},
		},
	}

	payload, ext, err := reconstructGameStreamBytestream(builder, "H264")
	if err != nil {
		t.Fatalf("reconstructGameStreamBytestream() error = %v", err)
	}
	if ext != ".h264" {
		t.Fatalf("expected .h264 extension, got %q", ext)
	}

	expected := []byte{0x00, 0x00, 0x00, 0x01, 0x67, 0x64, 0x00, 0x1f, 0xaa, 0xbb, 0xcc, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	if !bytes.Equal(payload, expected) {
		t.Fatalf("unexpected bytestream payload:\nwant=%#v\ngot =%#v", expected, payload)
	}
}

func TestBuildMediaAnalysisFromPacketStream(t *testing.T) {
	exportDir := t.TempDir()
	packet := model.Packet{
		ID:              1,
		Timestamp:       "2026-04-13 12:00:00",
		SourceIP:        "192.168.1.10",
		SourcePort:      50000,
		DestIP:          "192.168.1.20",
		DestPort:        50001,
		Protocol:        "UDP",
		DisplayProtocol: "UDP",
		Length:          58,
		RawHex:          "00112233445566778899aabb08004500002c0001000040110000c0a8010ac0a80114c350c351001800008060000100000010123456787c851122",
		IPHeaderLen:     20,
		L4HeaderLen:     8,
	}

	stats, artifacts, err := BuildMediaAnalysisFromPacketStream(exportDir, 1, MediaScanConfig{}, nil, func(onPacket func(model.Packet) error) error {
		return onPacket(packet)
	})
	if err != nil {
		t.Fatalf("BuildMediaAnalysisFromPacketStream() error = %v", err)
	}
	if stats.TotalMediaPackets != 1 {
		t.Fatalf("expected 1 media packet, got %+v", stats)
	}
	if len(stats.Sessions) != 1 {
		t.Fatalf("expected 1 media session, got %+v", stats.Sessions)
	}
	session := stats.Sessions[0]
	if session.Codec != "H264" {
		t.Fatalf("expected H264 session, got %+v", session)
	}
	if session.Artifact == nil {
		t.Fatalf("expected generated artifact, got %+v", session)
	}
	if artifacts[session.Artifact.Token] == "" {
		t.Fatalf("expected artifact path for token %q", session.Artifact.Token)
	}
}

func TestBuildMediaAnalysisFromPacketStreamStaticAudioPayloadType(t *testing.T) {
	exportDir := t.TempDir()
	packet := model.Packet{
		ID:              1,
		Timestamp:       "2026-04-13 12:00:00",
		SourceIP:        "10.0.0.1",
		SourcePort:      40000,
		DestIP:          "10.0.0.2",
		DestPort:        50000,
		Protocol:        "UDP",
		DisplayProtocol: "UDP",
		Length:          58,
		UDPPayloadHex:   "800000010000001012345678aabbccdd",
		IPHeaderLen:     20,
		L4HeaderLen:     8,
	}

	stats, artifacts, err := BuildMediaAnalysisFromPacketStream(exportDir, 1, MediaScanConfig{}, nil, func(onPacket func(model.Packet) error) error {
		return onPacket(packet)
	})
	if err != nil {
		t.Fatalf("BuildMediaAnalysisFromPacketStream() error = %v", err)
	}
	if len(stats.Sessions) != 1 {
		t.Fatalf("expected 1 session, got %+v", stats.Sessions)
	}
	if stats.Sessions[0].MediaType != "audio" {
		t.Fatalf("expected PT 0 RTP stream to classify as audio, got %+v", stats.Sessions[0])
	}
	if stats.Sessions[0].Artifact == nil {
		t.Fatalf("expected audio RTP stream to generate raw artifact, got %+v", stats.Sessions[0])
	}
	if stats.Sessions[0].Artifact.Format != "ulaw" {
		t.Fatalf("expected PCMU artifact format ulaw, got %+v", stats.Sessions[0].Artifact)
	}
	if artifacts[stats.Sessions[0].Artifact.Token] == "" {
		t.Fatalf("expected audio artifact path for token %q", stats.Sessions[0].Artifact.Token)
	}
}

func TestBuildMediaAnalysisFromGameStreamSample(t *testing.T) {
	if testing.Short() {
		t.Skip("skip sample-backed media regression in short mode")
	}
	if _, err := ResolveBinary(); err != nil {
		t.Skipf("tshark unavailable: %v", err)
	}

	samplePath := filepath.Clean(filepath.Join("..", "..", "..", "gamestream.pcapng"))
	if _, err := os.Stat(samplePath); err != nil {
		t.Skipf("sample capture not found: %v", err)
	}

	exportDir := t.TempDir()
	stats, artifacts, err := BuildMediaAnalysisFromFile(samplePath, exportDir)
	if err != nil {
		t.Fatalf("BuildMediaAnalysisFromFile() error = %v", err)
	}
	if stats.TotalMediaPackets <= 0 {
		t.Fatalf("expected media packets from sample, got %+v", stats)
	}
	if len(stats.Sessions) == 0 {
		t.Fatalf("expected extracted sessions from sample, got none")
	}

	foundGameStream := false
	artifactNames := map[string]struct{}{}
	artifactCount := 0
	for _, session := range stats.Sessions {
		if session.Application == "Moonlight / GameStream" {
			foundGameStream = true
			if session.Family != "Moonlight / GameStream" {
				t.Fatalf("expected GameStream family label for session %+v", session)
			}
		}
		if session.Artifact == nil {
			continue
		}
		artifactCount++
		if _, exists := artifactNames[session.Artifact.Name]; exists {
			t.Fatalf("artifact name collision detected: %s", session.Artifact.Name)
		}
		artifactNames[session.Artifact.Name] = struct{}{}

		path := artifacts[session.Artifact.Token]
		if path == "" {
			t.Fatalf("missing artifact path for token %s", session.Artifact.Token)
		}
		info, statErr := os.Stat(path)
		if statErr != nil {
			t.Fatalf("artifact path is not readable: %v", statErr)
		}
		if info.Size() <= 0 {
			t.Fatalf("artifact %s is empty", path)
		}
		if session.Artifact.SizeBytes <= 0 {
			t.Fatalf("artifact metadata reports invalid size: %+v", session.Artifact)
		}
	}

	if !foundGameStream {
		t.Fatalf("expected Moonlight / GameStream session in sample, got %+v", stats.Applications)
	}
	if artifactCount == 0 {
		t.Fatalf("expected at least one extracted video artifact, got none")
	}

	var video47998 *model.MediaSession
	var audio48000Count int
	for i := range stats.Sessions {
		session := &stats.Sessions[i]
		if session.SourcePort == 47998 && session.DestinationPort == 33314 && session.PacketCount > 100 {
			video47998 = session
		}
		if session.SourcePort == 48000 && session.MediaType == "audio" {
			audio48000Count++
			if session.Artifact != nil && session.Artifact.SizeBytes <= 0 {
				t.Fatalf("expected GameStream audio artifact metadata to report size, got %+v", session.Artifact)
			}
		}
	}
	if video47998 == nil {
		t.Fatalf("expected GameStream video session on 47998, got %+v", stats.Sessions)
	}
	if video47998.Codec != "H264" {
		t.Fatalf("expected 47998 session codec H264, got %+v", video47998)
	}
	if video47998.Artifact == nil {
		t.Fatalf("expected 47998 session to generate artifact, got %+v", video47998)
	}
	if audio48000Count == 0 {
		t.Fatalf("expected at least one audio-classified GameStream session on port 48000, got %+v", stats.Sessions)
	}
}

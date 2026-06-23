package tshark

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestBuildMediaAnalysisFromPacketStreamCoversErrorAndEmptyBranches(t *testing.T) {
	if _, _, err := BuildMediaAnalysisFromPacketStream(context.Background(), " ", 1, MediaScanConfig{}, nil, func(func(model.Packet) error) error { return nil }); err == nil {
		t.Fatal("empty export dir should fail")
	}
	if _, _, err := BuildMediaAnalysisFromPacketStream(context.Background(), t.TempDir(), 1, MediaScanConfig{}, nil, nil); err == nil {
		t.Fatal("nil iterator should fail")
	}

	iterErr := errors.New("iterator stopped")
	if _, _, err := BuildMediaAnalysisFromPacketStream(context.Background(), t.TempDir(), 1, MediaScanConfig{}, nil, func(func(model.Packet) error) error {
		return iterErr
	}); !errors.Is(err, iterErr) {
		t.Fatalf("iterator error = %v, want %v", err, iterErr)
	}

	var progress []string
	stats, artifacts, err := BuildMediaAnalysisFromPacketStream(context.Background(),
		t.TempDir(),
		0,
		MediaScanConfig{PreflightNotes: []string{"preflight-note"}},
		func(current, total int, label string) {
			progress = append(progress, strings.Join([]string{label, string(rune('0' + current)), string(rune('0' + total))}, "|"))
		},
		func(onPacket func(model.Packet) error) error {
			for _, packet := range []model.Packet{
				{ID: 1, Protocol: "TCP", SourcePort: 80, DestPort: 81},
				{ID: 2, Protocol: "UDP", SourcePort: 4000, DestPort: 4001},
				{ID: 3, Protocol: "UDP", SourcePort: 4000, DestPort: 4001, UDPPayloadHex: "00:01"},
			} {
				if err := onPacket(packet); err != nil {
					return err
				}
			}
			return nil
		},
	)
	if err != nil {
		t.Fatalf("empty media packet stream error = %v", err)
	}
	if stats.TotalMediaPackets != 0 || len(stats.Sessions) != 0 || len(artifacts) != 0 {
		t.Fatalf("expected stable empty media result, got stats=%+v artifacts=%+v", stats, artifacts)
	}
	if !containsMediaNote(stats.Notes, "preflight-note") {
		t.Fatalf("preflight note missing from %+v", stats.Notes)
	}
	if len(progress) == 0 {
		t.Fatal("expected progress callbacks")
	}
}

func TestStoredMediaPacketParsingBoundaries(t *testing.T) {
	if !isMediaCandidatePacket(model.Packet{Protocol: "tcp", SourcePort: 47998}) {
		t.Fatal("GameStream port should be treated as media candidate even when protocol is TCP")
	}
	if isMediaCandidatePacket(model.Packet{Protocol: "HTTP", SourcePort: 80, DestPort: 8080}) {
		t.Fatal("plain HTTP packet should not be a media candidate")
	}

	rtpPayload := []byte{0x80, 0x60, 0x12, 0x34, 0, 0, 0, 2, 0xCA, 0xFE, 0xBA, 0xBE, 0x65, 0xAA}
	packet := model.Packet{
		Protocol:    "UDP",
		RawHex:      buildIPv4UDPFrameHex(20, 8, rtpPayload),
		IPHeaderLen: 20,
		L4HeaderLen: 0,
	}
	if got := extractTransportPayloadFromStoredPacket(packet); !bytes.Equal(got, rtpPayload) {
		t.Fatalf("extractTransportPayloadFromStoredPacket() = %#v, want %#v", got, rtpPayload)
	}
	for _, bad := range []model.Packet{
		{RawHex: "zz"},
		{RawHex: "00:01:02", IPHeaderLen: 20, L4HeaderLen: 8},
		{RawHex: buildIPv4UDPFrameHex(20, 8, rtpPayload), IPHeaderLen: 24, L4HeaderLen: 8},
	} {
		if got := extractTransportPayloadFromStoredPacket(bad); got != nil {
			t.Fatalf("bad packet extracted payload %#v", got)
		}
	}

	ipv6Frame := make([]byte, 40+8+len(rtpPayload))
	ipv6Frame[0] = 0x60
	binary.BigEndian.PutUint16(ipv6Frame[4:6], uint16(8+len(rtpPayload)))
	if offset := locateNetworkLayerOffset(ipv6Frame, 40); offset != 0 {
		t.Fatalf("IPv6 network offset = %d, want 0", offset)
	}
	if offset := locateNetworkLayerOffset([]byte{1, 2, 3}, 20); offset != -1 {
		t.Fatalf("short frame offset = %d, want -1", offset)
	}

	if _, _, _, _, _, _, ok := parseRTPPacketFromPayload([]byte{0x80, 0x60}); ok {
		t.Fatal("short RTP packet should not parse")
	}
	withBadPadding := append([]byte{0xA0, 0x60, 0, 1, 0, 0, 0, 1, 0, 0, 0, 2, 0x65, 0x99}, 20)
	if _, _, _, _, _, _, ok := parseRTPPacketFromPayload(withBadPadding); ok {
		t.Fatal("invalid RTP padding should not parse")
	}
	withExtension := []byte{0x90, 0xE0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0xBE, 0xDE, 0, 1, 0, 0, 0, 0, 0x65}
	payload, seq, ts, ssrc, marker, pt, ok := parseRTPPacketFromPayload(withExtension)
	if !ok || seq != 2 || ts != 3 || ssrc != "0x4" || !marker || pt != "96" || !bytes.Equal(payload, []byte{0x65}) {
		t.Fatalf("extended RTP parse = payload=%#v seq=%d ts=%d ssrc=%q marker=%v pt=%q ok=%v", payload, seq, ts, ssrc, marker, pt, ok)
	}
}

func TestMediaCodecArtifactAndGameStreamBoundaries(t *testing.T) {
	if payload := parseHexPayload("zz"); payload != nil {
		t.Fatalf("invalid hex payload = %#v, want nil", payload)
	}
	if got := detectPacketCodec([]string{" OPUS "}, nil); got != " OPUS " {
		t.Fatalf("codec hint should win, got %q", got)
	}
	if got := detectPacketCodec(nil, []byte{0x60, 0x01, 0x80}); got != "H265" {
		t.Fatalf("H265 FU codec detection = %q", got)
	}
	if got := detectAnnexBCodec([]byte{0, 0, 1, 0x40, 0x01}); got != "H265" {
		t.Fatalf("Annex-B H265 detection = %q", got)
	}
	if got := detectAnnexBCodec([]byte{0, 0, 0, 1}); got != "" {
		t.Fatalf("start-code without header detection = %q", got)
	}

	builder := &mediaSessionBuilder{
		Codec: "H265",
		Packets: []rtpPacketRecord{
			{Payload: []byte{0x26, 0x01, 0xAA}},
		},
	}
	payload, ext, err := reconstructVideoElementaryStream(builder)
	if err != nil || ext != ".h265" || len(payload) == 0 {
		t.Fatalf("H265 video reconstruction = payload=%#v ext=%q err=%v", payload, ext, err)
	}
	if _, _, err := reconstructVideoElementaryStream(&mediaSessionBuilder{Codec: "VP9", Packets: []rtpPacketRecord{{Payload: []byte{1, 2, 3}}}}); err == nil {
		t.Fatal("unsupported codec should fail")
	}

	gamePackets := make([]rtpPacketRecord, 8)
	for i := range gamePackets {
		gamePackets[i] = rtpPacketRecord{Payload: []byte{0, 0, 0, 1, 0x40, 0x01, byte(i)}}
	}
	game := &mediaSessionBuilder{Application: "Moonlight / GameStream", Packets: gamePackets}
	payload, ext, err = reconstructGameStreamBytestream(game, "")
	if err != nil || ext != ".h265" || len(payload) == 0 {
		t.Fatalf("GameStream H265 reconstruction = payload=%#v ext=%q err=%v", payload, ext, err)
	}
	if _, _, err := reconstructGameStreamBytestream(&mediaSessionBuilder{Application: "Moonlight / GameStream", Packets: gamePackets}, "AV1"); err == nil {
		t.Fatal("unsupported GameStream codec should fail")
	}
	if _, _, err := reconstructGameStreamBytestream(&mediaSessionBuilder{Application: "Moonlight / GameStream", Packets: gamePackets[:2]}, "H264"); err == nil {
		t.Fatal("small GameStream packet window should fail")
	}

	if artifact, target, note := buildMediaArtifact(filepath.Join(t.TempDir(), "missing"), &mediaSessionBuilder{
		ID:          "session",
		Codec:       "H264",
		Application: "RTP",
		Packets:     []rtpPacketRecord{{Payload: []byte{0x65, 0xAA}}},
	}, "video"); artifact != nil || target != "" || note != "" {
		t.Fatalf("artifact write failure should return empty values, got artifact=%+v target=%q note=%q", artifact, target, note)
	}
	if artifact, target, note := buildMediaArtifact(t.TempDir(), &mediaSessionBuilder{}, "data"); artifact != nil || target != "" || note != "" {
		t.Fatalf("unsupported media type artifact = %+v %q %q", artifact, target, note)
	}
}

func TestMediaStaticProfilesAndSmallHelpersCoverRemainingBranches(t *testing.T) {
	if got := decodeH264ParameterSets(map[string]string{"sprop-parameter-sets": " ,!!!!,Z0IAH5WoFAFuQA=="}); len(got) != 1 {
		t.Fatalf("decodeH264ParameterSets() = %+v, want one valid set", got)
	}
	if got := appendAnnexBNAL([]byte{1}, nil); !reflect.DeepEqual(got, []byte{1}) {
		t.Fatalf("appendAnnexBNAL empty = %#v", got)
	}
	if got, err := hexDecodeString("abc"); err != nil || !reflect.DeepEqual(got, []byte{0x0A, 0xBC}) {
		t.Fatalf("hexDecodeString odd = %#v err=%v", got, err)
	}
	if _, err := hexDecodeString("xx"); err == nil {
		t.Fatal("bad hex should fail")
	}

	for _, tc := range []struct {
		pt        string
		mediaType string
		codec     string
		clock     int
	}{
		{"4", "audio", "G723", 8000},
		{"12", "audio", "QCELP", 8000},
		{"14", "audio", "MPA", 90000},
		{"15", "audio", "G728", 8000},
		{"16", "audio", "DVI4", 11025},
		{"17", "audio", "DVI4", 22050},
		{"18", "audio", "G729", 8000},
		{"25", "video", "CelB", 90000},
		{"26", "video", "JPEG", 90000},
		{"28", "video", "nv", 90000},
		{"31", "video", "H261", 90000},
		{"32", "video", "MPV", 90000},
		{"33", "video", "MP2T", 90000},
		{"34", "video", "H263", 90000},
	} {
		mediaType, codec, clock := inferStaticRTPProfile(tc.pt)
		if mediaType != tc.mediaType || codec != tc.codec || clock != tc.clock {
			t.Fatalf("inferStaticRTPProfile(%s) = %s/%s/%d, want %s/%s/%d", tc.pt, mediaType, codec, clock, tc.mediaType, tc.codec, clock)
		}
	}

	if got := inferSessionCodec(&mediaSessionBuilder{Packets: []rtpPacketRecord{{Payload: []byte{0x7C, 0x85}}}}); got != "H264" {
		t.Fatalf("inferSessionCodec RTP = %q", got)
	}
	if got := inferSessionCodec(&mediaSessionBuilder{Application: "Moonlight / GameStream", Packets: []rtpPacketRecord{{Payload: []byte{1, 2, 3}}}}); got != "" {
		t.Fatalf("inferSessionCodec GameStream unknown = %q", got)
	}
	if got := inferGameStreamMediaType(48000); got != "audio" {
		t.Fatalf("inferGameStreamMediaType audio = %q", got)
	}
	if app, tags := detectMediaApplication("moonlight nvst sunshine", 1234); app != "Moonlight / GameStream" || !mediaStringSliceContains(tags, "Moonlight") || !mediaStringSliceContains(tags, "GameStream") {
		t.Fatalf("detectMediaApplication = %q %+v", app, tags)
	}
	if ports := extractTransportPorts("client_port=1000-1001;server_port=2000, port=3000"); !reflect.DeepEqual(ports, []int{1000, 1001, 2000}) {
		t.Fatalf("extractTransportPorts = %+v", ports)
	}
	target := map[int][]mediaTrackHint{}
	addMediaTrackHint(target, 0, mediaTrackHint{MediaType: "video"})
	if len(target) != 0 {
		t.Fatalf("zero port should not add hint: %+v", target)
	}
	if got := safeMediaName(" !!! "); got != "" {
		t.Fatalf("safeMediaName punctuation = %q, want empty trimmed result", got)
	}
}

func buildIPv4UDPFrameHex(ipHeaderLen, l4HeaderLen int, payload []byte) string {
	frame := make([]byte, 14+ipHeaderLen+l4HeaderLen+len(payload))
	offset := 14
	frame[offset] = 0x45
	binary.BigEndian.PutUint16(frame[offset+2:offset+4], uint16(ipHeaderLen+l4HeaderLen+len(payload)))
	udp := offset + ipHeaderLen
	binary.BigEndian.PutUint16(frame[udp+4:udp+6], uint16(l4HeaderLen+len(payload)))
	copy(frame[udp+l4HeaderLen:], payload)
	return hex.EncodeToString(frame)
}

func containsMediaNote(notes []string, want string) bool {
	for _, note := range notes {
		if note == want {
			return true
		}
	}
	return false
}

func mediaStringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

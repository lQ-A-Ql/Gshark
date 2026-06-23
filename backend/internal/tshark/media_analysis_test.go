package tshark

import (
	"bytes"
	"context"
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

func TestReconstructH265StreamHandlesParameterSetsAggregationAndFragments(t *testing.T) {
	builder := &mediaSessionBuilder{
		Codec: "H265",
		CodecFmtp: map[string]string{
			"sprop-vps": "QAEMAf//Aw==",
			"sprop-sps": "QgEBAWAAAAMAsAAAAwAAAwBdoAKAgC0WNrk=",
			"sprop-pps": "RAHAc8GJ",
		},
		Packets: []rtpPacketRecord{
			{Payload: []byte{0x26, 0x01, 0xAA, 0xBB}},
			{Payload: []byte{0x60, 0x01, 0x00, 0x02, 0x28, 0x01, 0x00, 0x02, 0x2A, 0x01}},
			{Payload: []byte{0x62, 0x01, 0x81, 0xCC, 0xDD}},
			{Payload: []byte{0x62, 0x01, 0x41, 0xEE, 0xFF}},
			{Payload: []byte{0x62}},
		},
	}

	payload, ext, err := reconstructH265Stream(builder)
	if err != nil {
		t.Fatalf("reconstructH265Stream() error = %v", err)
	}
	if ext != ".h265" {
		t.Fatalf("expected .h265 extension, got %q", ext)
	}
	if count := bytes.Count(payload, []byte{0, 0, 0, 1}); count < 6 {
		t.Fatalf("expected parameter sets, single NAL, aggregation and fragment output, got %d Annex-B prefixes in %#v", count, payload)
	}
	if !bytes.Contains(payload, []byte{0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0xCC, 0xDD, 0xEE, 0xFF}) {
		t.Fatalf("expected fragmented H265 NAL to be rebuilt, got %#v", payload)
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

func TestMediaControlHintsDecodeAsAndRTPPortProbeUseFakeTShark(t *testing.T) {
	withFakeTSharkCommand(t, "")
	ClearCapabilityCache()
	ClearFieldScanCache("")
	t.Cleanup(func() {
		ClearCapabilityCache()
		ClearFieldScanCache("")
	})

	controlHints := map[int][]mediaTrackHint{}
	protocolMap := map[string]int{}
	applicationMap := map[string]int{}
	count, err := scanMediaControlHints(context.Background(), "media.pcap", controlHints, protocolMap, applicationMap)
	if err != nil {
		t.Fatalf("scanMediaControlHints(context.Background(), ) error = %v", err)
	}
	if count != 1 {
		t.Fatalf("control hint count = %d, want 1", count)
	}
	if len(controlHints[5004]) == 0 || len(controlHints[5005]) == 0 {
		t.Fatalf("expected RTSP transport and SDP hints for ports 5004/5005, got %+v", controlHints)
	}
	if got := controlHints[5004][0].CodecByPT["96"].Name; got != "H264" {
		t.Fatalf("expected H264 codec hint for PT 96, got %q", got)
	}

	sessions := map[string]*mediaSessionBuilder{}
	rtpCount, err := scanRTPMediaSessionsWithDecodeAs(context.Background(), "media.pcap", []int{0, 5004}, controlHints, sessions, protocolMap, applicationMap)
	if err != nil {
		t.Fatalf("scanRTPMediaSessionsWithDecodeAs(context.Background(), ) error = %v", err)
	}
	if rtpCount != 1 || len(sessions) != 1 {
		t.Fatalf("expected one decode-as RTP session, count=%d sessions=%+v", rtpCount, sessions)
	}
	var session *mediaSessionBuilder
	for _, item := range sessions {
		session = item
	}
	if session.MediaType != "video" || session.Codec != "H264" || session.ClockRate != 90000 {
		t.Fatalf("expected media hints to enrich RTP session, got %+v", session)
	}
	if session.PacketCount != 1 || len(session.Packets) != 1 || session.Packets[0].Time == "" {
		t.Fatalf("expected session packet to be recorded, got %+v", session)
	}
	if !reflect.DeepEqual(dedupePositivePorts([]int{5004, -1, 5004, 6000}), []int{5004, 6000}) {
		t.Fatalf("dedupePositivePorts did not sort/drop invalid values")
	}

	ports, err := DetectLikelyRTPPorts("media.pcap", []int{6000, 5004, 5004, -1}, 3)
	if err != nil {
		t.Fatalf("DetectLikelyRTPPorts() error = %v", err)
	}
	if !reflect.DeepEqual(ports, []int{5004}) {
		t.Fatalf("DetectLikelyRTPPorts() = %+v, want [5004]", ports)
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

func TestMediaTrackHintAndScalarHelpers(t *testing.T) {
	hints := []mediaTrackHint{
		{
			MediaType:      "audio",
			Application:    "RTSP / RTP",
			ControlSummary: "SETUP stream",
			Tags:           map[string]struct{}{"RTP": {}, "Control": {}},
			CodecByPT: map[string]mediaCodecHint{
				"0": {Name: "PCMU", ClockRate: 8000, Fmtp: map[string]string{"mode": "narrow"}},
			},
		},
	}
	builder := &mediaSessionBuilder{Tags: map[string]struct{}{}}
	applyMediaTrackHints(builder, hints, "96")
	if builder.MediaType != "audio" || builder.Application != "RTSP / RTP" || builder.Codec != "PCMU" || builder.ClockRate != 8000 {
		t.Fatalf("hint fallback should populate builder fields, got %+v", builder)
	}
	builder.CodecFmtp["mode"] = "changed"
	if hints[0].CodecByPT["0"].Fmtp["mode"] != "narrow" {
		t.Fatalf("CodecFmtp should be cloned from hint, got hint=%+v builder=%+v", hints, builder)
	}
	if !reflect.DeepEqual(sortedKeys(builder.Tags), []string{"Control", "RTP"}) {
		t.Fatalf("unexpected tags after hints: %+v", sortedKeys(builder.Tags))
	}

	mediaType, port, payloadTypes := parseSDPMediaEntry("video 5004 RTP/AVP 96 97", "6000")
	if mediaType != "video" || port != 6000 || !reflect.DeepEqual(payloadTypes, []string{"96", "97"}) {
		t.Fatalf("parseSDPMediaEntry override = %q %d %+v", mediaType, port, payloadTypes)
	}
	if mediaType, port, payloadTypes := parseSDPMediaEntry("audio", "7000"); mediaType != "" || port != 7000 || payloadTypes != nil {
		t.Fatalf("parseSDPMediaEntry fallback = %q %d %+v", mediaType, port, payloadTypes)
	}
	if got := extractTransportPorts("RTP/AVP;client_port=5004-5005;server_port=6000-6001;port=7000"); !reflect.DeepEqual(got, []int{5004, 5005, 6000, 6001}) {
		t.Fatalf("extractTransportPorts = %+v", got)
	}
	if got := splitAggregatedField(" one | | two |three "); !reflect.DeepEqual(got, []string{"one", "two", "three"}) {
		t.Fatalf("splitAggregatedField = %+v", got)
	}
	if got := pickByIndex([]string{" a ", "b"}, 0); got != "a" {
		t.Fatalf("pickByIndex trim = %q", got)
	}
	if got := pickByIndex([]string{"a"}, 3); got != "" {
		t.Fatalf("pickByIndex out of range = %q", got)
	}
	if got := safeMediaName("Moonlight / GameStream: H.264"); got != "moonlight___gamestream__h.264" {
		t.Fatalf("safeMediaName = %q", got)
	}
	if got := normalizeMediaCodecName("hevc"); got != "H265" {
		t.Fatalf("normalizeMediaCodecName = %q", got)
	}
	if got := dedupeInts([]int{3, 1, 0, 3, 2}); !reflect.DeepEqual(got, []int{1, 2, 3}) {
		t.Fatalf("dedupeInts = %+v", got)
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

func TestParseRTPPacketFromPayloadHandlesExtensionsPaddingAndRejectsBadPayloads(t *testing.T) {
	raw := []byte{
		0xb0, 0xe0, 0x12, 0x34,
		0x00, 0x00, 0x00, 0x2a,
		0x01, 0x02, 0x03, 0x04,
		0xbe, 0xde, 0x00, 0x01,
		0xaa, 0xbb, 0xcc, 0xdd,
		0x65, 0x66, 0x67,
		0x00, 0x00, 0x03,
	}
	payload, seq, timestamp, ssrc, marker, payloadType, ok := parseRTPPacketFromPayload(raw)
	if !ok {
		t.Fatal("expected RTP packet with extension and padding to parse")
	}
	if !bytes.Equal(payload, []byte{0x65, 0x66, 0x67}) || seq != 0x1234 || timestamp != 42 || ssrc != "0x1020304" || !marker || payloadType != "96" {
		t.Fatalf("parsed RTP packet = payload=%#v seq=%d ts=%d ssrc=%q marker=%v pt=%q", payload, seq, timestamp, ssrc, marker, payloadType)
	}

	badCases := [][]byte{
		nil,
		{0x80, 0x60, 0, 1},
		{0x90, 0x60, 0, 1, 0, 0, 0, 1, 1, 2, 3, 4},
		{0xa0, 0x60, 0, 1, 0, 0, 0, 1, 1, 2, 3, 4, 0x65, 0},
	}
	for _, bad := range badCases {
		if _, _, _, _, _, _, ok := parseRTPPacketFromPayload(bad); ok {
			t.Fatalf("expected bad RTP payload to be rejected: %#v", bad)
		}
	}
}

func TestConsumeStoredMediaPacketsBuildsSessionsAndGapCounts(t *testing.T) {
	sessions := map[string]*mediaSessionBuilder{}
	protocolMap := map[string]int{}
	applicationMap := map[string]int{}
	packet := model.Packet{
		ID:         1,
		Timestamp:  "2026-06-10 12:00:00",
		SourceIP:   "10.0.0.10",
		SourcePort: 40000,
		DestIP:     "10.0.0.20",
		DestPort:   5004,
	}

	if consumeStoredRTPPacket(packet, nil, 1, 10, "0x1", false, "96", sessions, protocolMap, applicationMap) {
		t.Fatal("empty RTP payload should not be consumed")
	}
	if !consumeStoredRTPPacket(packet, []byte{0x65, 0xaa}, 1, 10, "0x1", false, "96", sessions, protocolMap, applicationMap) {
		t.Fatal("expected first RTP packet to be consumed")
	}
	packet.ID = 2
	packet.Timestamp = "2026-06-10 12:00:01"
	if !consumeStoredRTPPacket(packet, []byte{0x65, 0xbb}, 4, 20, "0x1", true, "96", sessions, protocolMap, applicationMap) {
		t.Fatal("expected second RTP packet to be consumed")
	}
	if len(sessions) != 1 || protocolMap["RTP"] != 2 || applicationMap["RTP"] != 1 {
		t.Fatalf("session maps = sessions=%+v protocols=%+v apps=%+v", sessions, protocolMap, applicationMap)
	}
	var rtp *mediaSessionBuilder
	for _, item := range sessions {
		rtp = item
	}
	if rtp.PacketCount != 2 || rtp.GapCount != 2 || rtp.StartTime == "" || rtp.EndTime == "" {
		t.Fatalf("RTP builder = %+v", rtp)
	}

	gameSessions := map[string]*mediaSessionBuilder{}
	gameProtocols := map[string]int{}
	gameApps := map[string]int{}
	gamePacket := model.Packet{
		ID:         3,
		Timestamp:  "2026-06-10 12:00:02",
		SourceIP:   "10.0.0.10",
		SourcePort: 47998,
		DestIP:     "10.0.0.20",
		DestPort:   33314,
	}
	if consumeStoredGameStreamPacket(gamePacket, nil, 1, 10, "0x2", false, gameSessions, gameProtocols, gameApps) {
		t.Fatal("empty GameStream payload should not be consumed")
	}
	if !consumeStoredGameStreamPacket(gamePacket, []byte{0xaa}, 1, 10, "0x2", false, gameSessions, gameProtocols, gameApps) {
		t.Fatal("expected GameStream packet to be consumed")
	}
	gamePacket.ID = 4
	gamePacket.Timestamp = "2026-06-10 12:00:03"
	if !consumeStoredGameStreamPacket(gamePacket, []byte{0xbb}, 3, 20, "0x2", true, gameSessions, gameProtocols, gameApps) {
		t.Fatal("expected second GameStream packet to be consumed")
	}
	if !hasGameStreamSession(gameSessions) || gameProtocols["GameStream UDP"] != 2 || gameApps["Moonlight / GameStream"] != 1 {
		t.Fatalf("gamestream maps = sessions=%+v protocols=%+v apps=%+v", gameSessions, gameProtocols, gameApps)
	}
}

func TestMediaAudioAndProfileHelpersCoverKnownBranches(t *testing.T) {
	codecExt := map[string]string{
		"PCMU":          ".ulaw",
		"G.711A":        ".alaw",
		"G722":          ".g722",
		"L16":           ".l16",
		"MPEG4-GENERIC": ".aac",
		"OPUS":          ".opus",
		"MP3":           ".mpa",
		"unknown":       ".raw",
	}
	for codec, want := range codecExt {
		if got := audioArtifactExtension(&mediaSessionBuilder{Codec: codec}); got != want {
			t.Fatalf("audioArtifactExtension(%q) = %q, want %q", codec, got, want)
		}
	}

	builder := &mediaSessionBuilder{Codec: "PCMA", Packets: []rtpPacketRecord{{Payload: []byte{1, 2}}, {Payload: []byte{}}, {Payload: []byte{3}}}}
	payload, ext, err := reconstructAudioElementaryStream(builder)
	if err != nil {
		t.Fatalf("reconstructAudioElementaryStream() error = %v", err)
	}
	if !bytes.Equal(payload, []byte{1, 2, 3}) || ext != ".alaw" {
		t.Fatalf("audio reconstruction = payload=%#v ext=%q", payload, ext)
	}
	if _, _, err := reconstructAudioElementaryStream(nil); err == nil {
		t.Fatal("nil audio builder should fail")
	}
	if _, _, err := reconstructAudioElementaryStream(&mediaSessionBuilder{Packets: []rtpPacketRecord{{}}}); err == nil {
		t.Fatal("empty audio payload should fail")
	}

	staticCases := []struct {
		pt        string
		mediaType string
		codec     string
		clockRate int
	}{
		{"3", "audio", "GSM", 8000},
		{"8", "audio", "PCMA", 8000},
		{"9", "audio", "G722", 8000},
		{"10", "audio", "L16", 44100},
		{"14", "audio", "MPA", 90000},
		{"18", "audio", "G729", 8000},
		{"28", "video", "nv", 90000},
		{"31", "video", "H261", 90000},
		{"32", "video", "MPV", 90000},
		{"33", "video", "MP2T", 90000},
		{"34", "video", "H263", 90000},
	}
	for _, tt := range staticCases {
		mediaType, codec, clockRate := inferStaticRTPProfile(tt.pt)
		if mediaType != tt.mediaType || codec != tt.codec || clockRate != tt.clockRate {
			t.Fatalf("inferStaticRTPProfile(%q) = %q %q %d", tt.pt, mediaType, codec, clockRate)
		}
	}
	if mediaType, codec, clockRate := inferStaticRTPProfile("127"); mediaType != "" || codec != "" || clockRate != 0 {
		t.Fatalf("inferStaticRTPProfile unknown = %q %q %d", mediaType, codec, clockRate)
	}

	profileBuilder := &mediaSessionBuilder{PayloadType: "8"}
	applyStaticRTPProfile(profileBuilder)
	if profileBuilder.MediaType != "audio" || profileBuilder.Codec != "PCMA" || profileBuilder.ClockRate != 8000 {
		t.Fatalf("applyStaticRTPProfile() = %+v", profileBuilder)
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

	stats, artifacts, err := BuildMediaAnalysisFromPacketStream(context.Background(), exportDir, 1, MediaScanConfig{}, nil, func(onPacket func(model.Packet) error) error {
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

	stats, artifacts, err := BuildMediaAnalysisFromPacketStream(context.Background(), exportDir, 1, MediaScanConfig{}, nil, func(onPacket func(model.Packet) error) error {
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
	var audioGameStreamCount int
	for i := range stats.Sessions {
		session := &stats.Sessions[i]
		if session.SourcePort == 47998 && session.DestinationPort == 33314 && session.PacketCount > 100 {
			video47998 = session
		}
		if session.Application == "Moonlight / GameStream" && session.MediaType == "audio" {
			audioGameStreamCount++
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
	if audioGameStreamCount == 0 {
		t.Fatalf("expected at least one audio-classified GameStream session, got %+v", stats.Sessions)
	}
}

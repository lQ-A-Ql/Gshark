package tshark

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

type mediaCodecHint struct {
	Name      string
	ClockRate int
	Fmtp      map[string]string
}

type mediaTrackHint struct {
	MediaType      string
	Application    string
	ControlSummary string
	Tags           map[string]struct{}
	CodecByPT      map[string]mediaCodecHint
}

type rtpPacketRecord struct {
	PacketID   int64
	Time       string
	Epoch      float64
	Sequence   int
	Timestamp  uint32
	Marker     bool
	Payload    []byte
	CodecHints []string
}

type mediaSessionBuilder struct {
	ID              string
	MediaType       string
	Family          string
	Application     string
	Source          string
	SourcePort      int
	Destination     string
	DestinationPort int
	Transport       string
	SSRC            string
	PayloadType     string
	Codec           string
	ClockRate       int
	ControlSummary  string
	Tags            map[string]struct{}
	Notes           []string
	PacketCount     int
	GapCount        int
	StartTime       string
	EndTime         string
	CodecFmtp       map[string]string
	Packets         []rtpPacketRecord
}

type MediaScanConfig struct {
	SkipControlHints bool
	RTPDecodeAsPorts []int
	PreflightNotes   []string
}

var mediaControlFields = []string{
	"frame.number",
	"frame.time_epoch",
	"ip.src",
	"ipv6.src",
	"ip.dst",
	"ipv6.dst",
	"tcp.srcport",
	"udp.srcport",
	"tcp.dstport",
	"udp.dstport",
	"frame.protocols",
	"_ws.col.Protocol",
	"_ws.col.Info",
	"rtsp.method",
	"rtsp.url",
	"rtsp.transport",
	"rtsp.session",
	"sdp.media",
	"sdp.media.port",
	"sdp.media_attr",
	"sdp.session_name",
}

var mediaRTPFields = []string{
	"frame.number",
	"frame.time_epoch",
	"ip.src",
	"ipv6.src",
	"ip.dst",
	"ipv6.dst",
	"udp.srcport",
	"udp.dstport",
	"frame.protocols",
	"_ws.col.Protocol",
	"_ws.col.Info",
	"rtp.ssrc",
	"rtp.p_type",
	"rtp.seq",
	"rtp.timestamp",
	"rtp.marker",
	"rtp.payload",
	"h264.nal_unit_type",
	"h265.nal_unit_type",
}

var mediaGameStreamUDPFields = []string{
	"frame.number",
	"frame.time_epoch",
	"ip.src",
	"ipv6.src",
	"ip.dst",
	"ipv6.dst",
	"udp.srcport",
	"udp.dstport",
	"udp.payload",
}

const gameStreamRTPPayloadOffset = 16

func BuildMediaAnalysisFromFile(filePath, exportDir string) (model.MediaAnalysis, map[string]string, error) {
	return BuildMediaAnalysisFromFileWithConfig(filePath, exportDir, MediaScanConfig{}, nil)
}

func BuildMediaAnalysisFromFileWithProgress(
	filePath,
	exportDir string,
	progress func(current, total int, label string),
) (model.MediaAnalysis, map[string]string, error) {
	return BuildMediaAnalysisFromFileWithConfig(filePath, exportDir, MediaScanConfig{}, progress)
}

func BuildMediaAnalysisFromFileWithConfig(
	filePath,
	exportDir string,
	cfg MediaScanConfig,
	progress func(current, total int, label string),
) (model.MediaAnalysis, map[string]string, error) {
	stats := model.MediaAnalysis{}
	artifacts := map[string]string{}
	if strings.TrimSpace(filePath) == "" {
		return stats, artifacts, fmt.Errorf("empty capture path")
	}
	if strings.TrimSpace(exportDir) == "" {
		return stats, artifacts, fmt.Errorf("empty media export directory")
	}

	protocolMap := make(map[string]int)
	applicationMap := make(map[string]int)
	controlHints := make(map[int][]mediaTrackHint)
	sessionBuilders := make(map[string]*mediaSessionBuilder)

	baseSteps := 2
	if !cfg.SkipControlHints {
		baseSteps = 3
	}

	step := 1
	if !cfg.SkipControlHints {
		reportMediaProgress(progress, step, baseSteps, "扫描媒体控制信令")
		controlPackets, err := scanMediaControlHints(filePath, controlHints, protocolMap, applicationMap)
		if err != nil {
			return stats, artifacts, err
		}
		stats.TotalMediaPackets += controlPackets
		step++
	}

	reportMediaProgress(progress, step, baseSteps, "扫描 RTP / GameStream 会话")
	rtpPackets, err := scanRTPMediaSessions(filePath, controlHints, sessionBuilders, protocolMap, applicationMap, cfg.RTPDecodeAsPorts)
	if err != nil {
		return stats, artifacts, err
	}
	stats.TotalMediaPackets += rtpPackets

	builders := make([]*mediaSessionBuilder, 0, len(sessionBuilders))
	for _, builder := range sessionBuilders {
		if builder == nil || builder.PacketCount == 0 {
			continue
		}
		applyStaticRTPProfile(builder)
		if isGameStreamSession(builder) {
			builder.MediaType = firstNonEmpty(builder.MediaType, inferGameStreamMediaType(builder.SourcePort, builder.DestinationPort))
			if !strings.EqualFold(builder.MediaType, "audio") {
				builder.Codec = inferSessionCodec(builder)
			}
		} else if builder.Codec == "" {
			builder.Codec = inferSessionCodec(builder)
		}
		if builder.Application == "" {
			builder.Application = inferApplicationFromPorts(builder.SourcePort, builder.DestinationPort)
		}
		lowerApp := strings.ToLower(builder.Application)
		if strings.Contains(lowerApp, "moonlight") || strings.Contains(lowerApp, "gamestream") {
			builder.Family = "Moonlight / GameStream"
		} else if builder.Family == "" {
			builder.Family = "RTP"
		}
		builders = append(builders, builder)
	}

	sort.Slice(builders, func(i, j int) bool {
		if builders[i].StartTime == builders[j].StartTime {
			return builders[i].ID < builders[j].ID
		}
		return builders[i].StartTime < builders[j].StartTime
	})

	totalSteps := baseSteps + len(builders)
	reportMediaProgress(progress, baseSteps, totalSteps, "整理媒体会话")

	for idx, builder := range builders {
		reportMediaProgress(progress, 4+idx, totalSteps, fmt.Sprintf("重建媒体流 %d/%d", idx+1, len(builders)))
		// Default MediaType: if we have a video codec, it's video; if from SDP audio hint, it's audio; otherwise "video"
		mediaType := builder.MediaType
		if mediaType == "" {
			codec := strings.ToUpper(strings.TrimSpace(builder.Codec))
			if codec == "H264" || codec == "H265" || codec == "HEVC" || codec == "AVC" {
				mediaType = "video"
			} else if codec == "OPUS" || codec == "AAC" || codec == "PCMA" || codec == "PCMU" || codec == "G711" || codec == "G722" {
				mediaType = "audio"
			} else {
				mediaType = "video"
			}
		}
		session := model.MediaSession{
			ID:              builder.ID,
			MediaType:       mediaType,
			Family:          firstNonEmpty(builder.Family, "RTP"),
			Application:     firstNonEmpty(builder.Application, "RTP"),
			Source:          builder.Source,
			SourcePort:      builder.SourcePort,
			Destination:     builder.Destination,
			DestinationPort: builder.DestinationPort,
			Transport:       firstNonEmpty(builder.Transport, "UDP"),
			SSRC:            builder.SSRC,
			PayloadType:     builder.PayloadType,
			Codec:           builder.Codec,
			ClockRate:       builder.ClockRate,
			StartTime:       builder.StartTime,
			EndTime:         builder.EndTime,
			PacketCount:     builder.PacketCount,
			GapCount:        builder.GapCount,
			ControlSummary:  builder.ControlSummary,
			Tags:            sortedKeys(builder.Tags),
			Notes:           dedupeStrings(builder.Notes),
		}

		if artifact, targetPath, note := buildMediaArtifact(exportDir, builder, mediaType); artifact != nil {
			artifacts[artifact.Token] = targetPath
			session.Artifact = artifact
			if note != "" {
				session.Notes = append(session.Notes, note)
			}
		}

		stats.Sessions = append(stats.Sessions, session)
	}

	stats.Protocols = topBuckets(protocolMap, 0)
	stats.Applications = topBuckets(applicationMap, 0)
	stats.Notes = buildMediaAnalysisNotes(stats)
	stats.Notes = append(stats.Notes, cfg.PreflightNotes...)
	stats.Notes = dedupeStrings(stats.Notes)
	reportMediaProgress(progress, totalSteps, totalSteps, "媒体流分析完成")
	return stats, artifacts, nil
}

func BuildMediaAnalysisFromPacketStream(
	exportDir string,
	totalPackets int,
	cfg MediaScanConfig,
	progress func(current, total int, label string),
	iterate func(func(model.Packet) error) error,
) (model.MediaAnalysis, map[string]string, error) {
	stats := model.MediaAnalysis{}
	artifacts := map[string]string{}
	if strings.TrimSpace(exportDir) == "" {
		return stats, artifacts, fmt.Errorf("empty media export directory")
	}
	if iterate == nil {
		return stats, artifacts, fmt.Errorf("missing packet iterator")
	}

	protocolMap := make(map[string]int)
	applicationMap := make(map[string]int)
	sessionBuilders := make(map[string]*mediaSessionBuilder)

	if totalPackets <= 0 {
		totalPackets = 1
	}
	reportMediaProgress(progress, 0, totalPackets, "扫描已缓存数据包中的媒体流")
	mediaPackets, err := scanMediaSessionsFromPacketStream(totalPackets, iterate, sessionBuilders, protocolMap, applicationMap, progress)
	if err != nil {
		return stats, artifacts, err
	}
	stats.TotalMediaPackets = mediaPackets

	builders := make([]*mediaSessionBuilder, 0, len(sessionBuilders))
	for _, builder := range sessionBuilders {
		if builder == nil || builder.PacketCount == 0 {
			continue
		}
		applyStaticRTPProfile(builder)
		if isGameStreamSession(builder) {
			builder.MediaType = firstNonEmpty(builder.MediaType, inferGameStreamMediaType(builder.SourcePort, builder.DestinationPort))
			if !strings.EqualFold(builder.MediaType, "audio") {
				builder.Codec = inferSessionCodec(builder)
			}
		} else if builder.Codec == "" {
			builder.Codec = inferSessionCodec(builder)
		}
		if builder.Application == "" {
			builder.Application = inferApplicationFromPorts(builder.SourcePort, builder.DestinationPort)
		}
		lowerApp := strings.ToLower(builder.Application)
		if strings.Contains(lowerApp, "moonlight") || strings.Contains(lowerApp, "gamestream") {
			builder.Family = "Moonlight / GameStream"
		} else if builder.Family == "" {
			builder.Family = "RTP"
		}
		builders = append(builders, builder)
	}

	sort.Slice(builders, func(i, j int) bool {
		if builders[i].StartTime == builders[j].StartTime {
			return builders[i].ID < builders[j].ID
		}
		return builders[i].StartTime < builders[j].StartTime
	})

	totalSteps := 2 + len(builders)
	reportMediaProgress(progress, 1, totalSteps, "整理已缓存媒体会话")

	for idx, builder := range builders {
		reportMediaProgress(progress, 2+idx, totalSteps, fmt.Sprintf("重建媒体流 %d/%d", idx+1, len(builders)))

		mediaType := builder.MediaType
		if mediaType == "" {
			codec := strings.ToUpper(strings.TrimSpace(builder.Codec))
			if codec == "H264" || codec == "H265" || codec == "HEVC" || codec == "AVC" {
				mediaType = "video"
			} else if codec == "OPUS" || codec == "AAC" || codec == "PCMA" || codec == "PCMU" || codec == "G711" || codec == "G722" {
				mediaType = "audio"
			} else {
				mediaType = "video"
			}
		}

		session := model.MediaSession{
			ID:              builder.ID,
			MediaType:       mediaType,
			Family:          firstNonEmpty(builder.Family, "RTP"),
			Application:     firstNonEmpty(builder.Application, "RTP"),
			Source:          builder.Source,
			SourcePort:      builder.SourcePort,
			Destination:     builder.Destination,
			DestinationPort: builder.DestinationPort,
			Transport:       firstNonEmpty(builder.Transport, "UDP"),
			SSRC:            builder.SSRC,
			PayloadType:     builder.PayloadType,
			Codec:           builder.Codec,
			ClockRate:       builder.ClockRate,
			StartTime:       builder.StartTime,
			EndTime:         builder.EndTime,
			PacketCount:     builder.PacketCount,
			GapCount:        builder.GapCount,
			ControlSummary:  builder.ControlSummary,
			Tags:            sortedKeys(builder.Tags),
			Notes:           dedupeStrings(builder.Notes),
		}

		if artifact, targetPath, note := buildMediaArtifact(exportDir, builder, mediaType); artifact != nil {
			artifacts[artifact.Token] = targetPath
			session.Artifact = artifact
			if note != "" {
				session.Notes = append(session.Notes, note)
			}
		}

		stats.Sessions = append(stats.Sessions, session)
	}

	stats.Protocols = topBuckets(protocolMap, 0)
	stats.Applications = topBuckets(applicationMap, 0)
	stats.Notes = buildMediaAnalysisNotes(stats)
	stats.Notes = append(stats.Notes, "媒体分析优先复用了已缓存的数据包，避免再次全量扫描抓包文件。")
	stats.Notes = append(stats.Notes, cfg.PreflightNotes...)
	stats.Notes = dedupeStrings(stats.Notes)
	reportMediaProgress(progress, totalSteps, totalSteps, "媒体流分析完成")
	return stats, artifacts, nil
}

func reportMediaProgress(progress func(current, total int, label string), current, total int, label string) {
	if progress == nil {
		return
	}
	progress(current, total, label)
}

func scanMediaSessionsFromPacketStream(
	totalPackets int,
	iterate func(func(model.Packet) error) error,
	sessions map[string]*mediaSessionBuilder,
	protocolMap, applicationMap map[string]int,
	progress func(current, total int, label string),
) (int, error) {
	count := 0
	scanned := 0
	err := iterate(func(packet model.Packet) error {
		scanned++
		if scanned == 1 || scanned%5000 == 0 || scanned == totalPackets {
			reportMediaProgress(progress, scanned, totalPackets, fmt.Sprintf("扫描已缓存数据包 %d/%d", scanned, totalPackets))
		}

		if !isMediaCandidatePacket(packet) {
			return nil
		}

		transportPayload := extractTransportPayloadFromStoredPacket(packet)
		if len(transportPayload) == 0 {
			return nil
		}

		if isMoonlightGameStreamPort(packet.SourcePort, packet.DestPort) {
			payload, seq, timestamp, ssrc, marker, ok := parseGameStreamUDPPayload(transportPayload)
			if ok {
				if consumeStoredGameStreamPacket(packet, payload, seq, timestamp, ssrc, marker, sessions, protocolMap, applicationMap) {
					count++
				}
				return nil
			}
		}

		payload, seq, timestamp, ssrc, marker, payloadType, ok := parseRTPPacketFromPayload(transportPayload)
		if !ok {
			return nil
		}
		if consumeStoredRTPPacket(packet, payload, seq, timestamp, ssrc, marker, payloadType, sessions, protocolMap, applicationMap) {
			count++
		}
		return nil
	})
	return count, err
}

func scanMediaControlHints(filePath string, controlHints map[int][]mediaTrackHint, protocolMap, applicationMap map[string]int) (int, error) {
	count := 0
	err := scanFieldRowsWithOptions(filePath, mediaControlFields, fieldScanOptions{
		DisplayFilter: "rtsp || sdp",
		Occurrence:    "a",
		Aggregator:    "|",
	}, func(parts []string) {
		count++
		protocolMap["RTSP/SDP"]++

		srcPort := parseFlexibleInt(firstNonEmpty(safeTrim(parts, 6), safeTrim(parts, 7)))
		dstPort := parseFlexibleInt(firstNonEmpty(safeTrim(parts, 8), safeTrim(parts, 9)))
		text := strings.ToLower(strings.Join([]string{
			safeTrim(parts, 10),
			safeTrim(parts, 11),
			safeTrim(parts, 12),
			safeTrim(parts, 13),
			safeTrim(parts, 14),
			safeTrim(parts, 15),
			safeTrim(parts, 16),
			safeTrim(parts, 17),
			safeTrim(parts, 19),
			safeTrim(parts, 20),
		}, " "))
		app, tags := detectMediaApplication(text, srcPort, dstPort)
		applicationMap[app]++

		codecMap := parseSDPCodecHints(splitAggregatedField(safeTrim(parts, 19)))
		controlSummary := compactJoin(" / ",
			nonEmptyPrefixed("Method", safeTrim(parts, 13)),
			nonEmptyPrefixed("URL", safeTrim(parts, 14)),
			nonEmptyPrefixed("Session", safeTrim(parts, 16)),
			nonEmptyPrefixed("Transport", safeTrim(parts, 15)),
			nonEmptyPrefixed("SDP", safeTrim(parts, 20)),
		)

		for _, port := range extractTransportPorts(safeTrim(parts, 15)) {
			addMediaTrackHint(controlHints, port, mediaTrackHint{
				MediaType:      "video",
				Application:    app,
				ControlSummary: controlSummary,
				Tags:           sliceToSet(tags),
				CodecByPT:      cloneCodecHintMap(codecMap),
			})
		}

		mediaEntries := splitAggregatedField(safeTrim(parts, 17))
		mediaPorts := splitAggregatedField(safeTrim(parts, 18))
		for idx, entry := range mediaEntries {
			mediaType, port, payloadTypes := parseSDPMediaEntry(entry, pickByIndex(mediaPorts, idx))
			normalizedMediaType := strings.ToLower(strings.TrimSpace(mediaType))
			if (normalizedMediaType != "video" && normalizedMediaType != "audio") || port <= 0 {
				continue
			}
			hints := make(map[string]mediaCodecHint)
			for _, pt := range payloadTypes {
				if codec, ok := codecMap[pt]; ok {
					hints[pt] = codec
				}
			}
			addMediaTrackHint(controlHints, port, mediaTrackHint{
				MediaType:      normalizedMediaType,
				Application:    app,
				ControlSummary: controlSummary,
				Tags:           sliceToSet(tags),
				CodecByPT:      hints,
			})
		}
	})
	return count, err
}

func scanRTPMediaSessions(filePath string, controlHints map[int][]mediaTrackHint, sessions map[string]*mediaSessionBuilder, protocolMap, applicationMap map[string]int, decodeAsPorts []int) (int, error) {
	count := 0
	if len(decodeAsPorts) > 0 {
		targetedCount, err := scanRTPMediaSessionsWithDecodeAs(filePath, decodeAsPorts, controlHints, sessions, protocolMap, applicationMap)
		if err != nil {
			return 0, err
		}
		if targetedCount > 0 {
			count += targetedCount
			if hasGameStreamSession(sessions) {
				return count, nil
			}
			return count, nil
		}
	}
	err := scanFieldRowsWithOptions(filePath, mediaRTPFields, fieldScanOptions{
		DisplayFilter: "rtp",
	}, func(parts []string) {
		if consumeRTPMediaRow(parts, controlHints, sessions, protocolMap, applicationMap, nil) {
			count++
		}
	})
	if err != nil {
		return count, err
	}
	if hasGameStreamSession(sessions) {
		return count, nil
	}
	gameStreamCount, err := scanGameStreamUDPSessions(filePath, controlHints, sessions, protocolMap, applicationMap)
	if err != nil {
		return count, err
	}
	return count + gameStreamCount, nil
}

func scanRTPMediaSessionsWithDecodeAs(filePath string, decodeAsPorts []int, controlHints map[int][]mediaTrackHint, sessions map[string]*mediaSessionBuilder, protocolMap, applicationMap map[string]int) (int, error) {
	fields := normalizeFieldScanFields(mediaRTPFields)
	args := []string{
		"-n",
		"-r", strings.TrimSpace(filePath),
	}
	for _, port := range decodeAsPorts {
		if port <= 0 {
			continue
		}
		args = append(args, "-d", fmt.Sprintf("udp.port==%d,rtp", port))
	}
	args = append(args,
		"-Y", "rtp",
		"-T", "fields",
		"-E", "separator=\t",
		"-E", "occurrence=f",
		"-E", "aggregator=,",
		"-E", "quote=n",
	)
	for _, field := range fields {
		args = append(args, "-e", field)
	}
	count := 0
	err := runDirectFieldScan(args, len(fields), func(parts []string) {
		if consumeRTPMediaRow(parts, controlHints, sessions, protocolMap, applicationMap, []string{"非标准端口 RTP decode-as"}) {
			count++
		}
	})
	return count, err
}

func DetectLikelyRTPPorts(filePath string, candidatePorts []int, sampleLimit int) ([]int, error) {
	if sampleLimit <= 0 {
		sampleLimit = 24
	}

	ports := dedupePositivePorts(candidatePorts)
	if len(ports) == 0 {
		return nil, nil
	}

	matched := make([]int, 0, len(ports))
	for _, port := range ports {
		hits := 0
		samples := 0
		args := []string{
			"-n",
			"-r", strings.TrimSpace(filePath),
			"-Y", fmt.Sprintf("udp.port==%d && udp.payload", port),
			"-c", strconv.Itoa(sampleLimit),
			"-T", "fields",
			"-E", "separator=\t",
			"-E", "occurrence=f",
			"-E", "aggregator=,",
			"-E", "quote=n",
			"-e", "udp.payload",
		}
		err := runDirectFieldScan(args, 1, func(parts []string) {
			samples++
			if isLikelyRTPPayload(parseHexPayload(safeTrim(parts, 0))) {
				hits++
			}
		})
		if err != nil {
			return matched, err
		}
		if hits >= 3 || (hits >= 2 && hits == samples) {
			matched = append(matched, port)
		}
	}
	sort.Ints(matched)
	return matched, nil
}

func isLikelyRTPPayload(payload []byte) bool {
	if len(payload) < 12 {
		return false
	}
	if payload[0]&0xC0 != 0x80 {
		return false
	}

	csrcCount := int(payload[0] & 0x0F)
	headerLen := 12 + csrcCount*4
	if len(payload) < headerLen {
		return false
	}

	if payload[0]&0x10 != 0 {
		if len(payload) < headerLen+4 {
			return false
		}
		extWords := int(binary.BigEndian.Uint16(payload[headerLen+2 : headerLen+4]))
		headerLen += 4 + extWords*4
		if len(payload) < headerLen {
			return false
		}
	}

	payloadType := int(payload[1] & 0x7F)
	if payloadType > 127 {
		return false
	}

	sequence := binary.BigEndian.Uint16(payload[2:4])
	timestamp := binary.BigEndian.Uint32(payload[4:8])
	ssrc := binary.BigEndian.Uint32(payload[8:12])
	if payloadType == 0 || payloadType == 8 {
		return true
	}
	return sequence != 0 || timestamp != 0 || ssrc != 0
}

func dedupePositivePorts(ports []int) []int {
	if len(ports) == 0 {
		return nil
	}
	seen := make(map[int]struct{}, len(ports))
	out := make([]int, 0, len(ports))
	for _, port := range ports {
		if port <= 0 {
			continue
		}
		if _, ok := seen[port]; ok {
			continue
		}
		seen[port] = struct{}{}
		out = append(out, port)
	}
	sort.Ints(out)
	return out
}

func consumeRTPMediaRow(parts []string, controlHints map[int][]mediaTrackHint, sessions map[string]*mediaSessionBuilder, protocolMap, applicationMap map[string]int, extraNotes []string) bool {
	payload := parseHexPayload(safeTrim(parts, 16))
	if len(payload) == 0 {
		return false
	}
	protocolMap["RTP"]++

	src := firstNonEmpty(safeTrim(parts, 2), safeTrim(parts, 3))
	dst := firstNonEmpty(safeTrim(parts, 4), safeTrim(parts, 5))
	srcPort := parseFlexibleInt(safeTrim(parts, 6))
	dstPort := parseFlexibleInt(safeTrim(parts, 7))
	ssrc := formatHex(safeTrim(parts, 11))
	payloadType := strings.TrimSpace(safeTrim(parts, 12))
	key := fmt.Sprintf("%s:%d>%s:%d|%s|pt=%s", src, srcPort, dst, dstPort, ssrc, payloadType)

	builder, ok := sessions[key]
	if !ok {
		builder = &mediaSessionBuilder{
			ID:              key,
			Family:          "RTP",
			Application:     inferApplicationFromPorts(srcPort, dstPort),
			MediaType:       inferGameStreamMediaType(srcPort, dstPort),
			Source:          src,
			SourcePort:      srcPort,
			Destination:     dst,
			DestinationPort: dstPort,
			Transport:       "UDP",
			SSRC:            ssrc,
			PayloadType:     payloadType,
			Tags:            map[string]struct{}{"RTP": {}},
			Notes:           append([]string(nil), extraNotes...),
		}
		if isMoonlightGameStreamPort(srcPort, dstPort) {
			builder.Tags["GameStream"] = struct{}{}
		}
		applyMediaTrackHints(builder, controlHints[srcPort], payloadType)
		applyMediaTrackHints(builder, controlHints[dstPort], payloadType)
		if builder.Application == "" {
			builder.Application = "RTP"
		}
		applicationMap[builder.Application]++
		sessions[key] = builder
	} else if len(extraNotes) > 0 {
		builder.Notes = append(builder.Notes, extraNotes...)
	}

	packetTime := normalizeTimestamp(safeTrim(parts, 1))
	builder.PacketCount++
	if builder.StartTime == "" {
		builder.StartTime = packetTime
	}
	builder.EndTime = packetTime

	seq := parseFlexibleInt(safeTrim(parts, 13))
	if n := len(builder.Packets); n > 0 {
		prev := builder.Packets[n-1].Sequence
		if prev >= 0 && seq >= 0 {
			diff := (seq - prev + 65536) % 65536
			if diff > 1 {
				builder.GapCount += diff - 1
			}
		}
	}

	codecHints := make([]string, 0, 2)
	if safeTrim(parts, 17) != "" {
		codecHints = append(codecHints, "H264")
	}
	if safeTrim(parts, 18) != "" {
		codecHints = append(codecHints, "H265")
	}

	builder.Packets = append(builder.Packets, rtpPacketRecord{
		PacketID:   parseInt64(safeTrim(parts, 0)),
		Time:       packetTime,
		Epoch:      parseEpochSeconds(safeTrim(parts, 1)),
		Sequence:   seq,
		Timestamp:  uint32(parseFlexibleInt(safeTrim(parts, 14))),
		Marker:     parseTruthy(safeTrim(parts, 15)),
		Payload:    payload,
		CodecHints: codecHints,
	})

	if builder.Codec == "" {
		builder.Codec = detectPacketCodec(codecHints, payload)
	}
	return true
}

func isMediaCandidatePacket(packet model.Packet) bool {
	protocol := strings.ToUpper(strings.TrimSpace(firstNonEmpty(packet.Protocol, packet.DisplayProtocol)))
	if protocol == "UDP" || protocol == "RTP" {
		return true
	}
	return isMoonlightGameStreamPort(packet.SourcePort, packet.DestPort)
}

func extractTransportPayloadFromStoredPacket(packet model.Packet) []byte {
	if strings.TrimSpace(packet.UDPPayloadHex) != "" {
		payload := parseHexPayload(packet.UDPPayloadHex)
		if len(payload) > 0 {
			return payload
		}
	}
	if strings.TrimSpace(packet.RawHex) == "" {
		return nil
	}
	frame := parseHexPayload(packet.RawHex)
	if len(frame) == 0 {
		return nil
	}

	networkOffset := locateNetworkLayerOffset(frame, packet.IPHeaderLen)
	if networkOffset < 0 {
		return nil
	}

	l4HeaderLen := packet.L4HeaderLen
	if l4HeaderLen <= 0 {
		l4HeaderLen = 8
	}
	payloadOffset := networkOffset + packet.IPHeaderLen + l4HeaderLen
	if payloadOffset <= 0 || payloadOffset > len(frame) {
		return nil
	}

	end := len(frame)
	if networkOffset+packet.IPHeaderLen+4 <= len(frame) {
		udpOffset := networkOffset + packet.IPHeaderLen
		if udpOffset+6 <= len(frame) {
			udpLen := int(binary.BigEndian.Uint16(frame[udpOffset+4 : udpOffset+6]))
			if udpLen > l4HeaderLen {
				expectedEnd := udpOffset + udpLen
				if expectedEnd > payloadOffset && expectedEnd <= len(frame) {
					end = expectedEnd
				}
			}
		}
	}
	if end <= payloadOffset {
		return nil
	}

	payload := make([]byte, end-payloadOffset)
	copy(payload, frame[payloadOffset:end])
	return payload
}

func locateNetworkLayerOffset(frame []byte, ipHeaderLen int) int {
	maxOffset := len(frame) - 20
	if maxOffset < 0 {
		return -1
	}
	if maxOffset > 64 {
		maxOffset = 64
	}

	for offset := 0; offset <= maxOffset; offset++ {
		version := frame[offset] >> 4
		switch version {
		case 4:
			headerLen := int(frame[offset]&0x0F) * 4
			if headerLen < 20 {
				continue
			}
			if ipHeaderLen > 0 && headerLen != ipHeaderLen {
				continue
			}
			totalLenOffset := offset + 2
			if totalLenOffset+2 > len(frame) {
				continue
			}
			totalLen := int(binary.BigEndian.Uint16(frame[totalLenOffset : totalLenOffset+2]))
			if totalLen <= headerLen || offset+totalLen > len(frame) {
				continue
			}
			return offset
		case 6:
			headerLen := 40
			if ipHeaderLen > 0 && ipHeaderLen != headerLen {
				continue
			}
			payloadLenOffset := offset + 4
			if payloadLenOffset+2 > len(frame) {
				continue
			}
			payloadLen := int(binary.BigEndian.Uint16(frame[payloadLenOffset : payloadLenOffset+2]))
			if payloadLen <= 0 || offset+headerLen+payloadLen > len(frame) {
				continue
			}
			return offset
		}
	}
	return -1
}

func parseRTPPacketFromPayload(raw []byte) ([]byte, int, uint32, string, bool, string, bool) {
	if !isLikelyRTPPayload(raw) {
		return nil, 0, 0, "", false, "", false
	}

	csrcCount := int(raw[0] & 0x0F)
	headerLen := 12 + csrcCount*4
	if len(raw) < headerLen {
		return nil, 0, 0, "", false, "", false
	}

	if raw[0]&0x10 != 0 {
		if len(raw) < headerLen+4 {
			return nil, 0, 0, "", false, "", false
		}
		extWords := int(binary.BigEndian.Uint16(raw[headerLen+2 : headerLen+4]))
		headerLen += 4 + extWords*4
		if len(raw) < headerLen {
			return nil, 0, 0, "", false, "", false
		}
	}

	end := len(raw)
	if raw[0]&0x20 != 0 {
		padding := int(raw[len(raw)-1])
		if padding <= 0 || padding > len(raw)-headerLen {
			return nil, 0, 0, "", false, "", false
		}
		end -= padding
	}
	if end <= headerLen {
		return nil, 0, 0, "", false, "", false
	}

	payload := make([]byte, end-headerLen)
	copy(payload, raw[headerLen:end])
	return payload,
		int(binary.BigEndian.Uint16(raw[2:4])),
		binary.BigEndian.Uint32(raw[4:8]),
		fmt.Sprintf("0x%X", binary.BigEndian.Uint32(raw[8:12])),
		raw[1]&0x80 != 0,
		fmt.Sprintf("%d", raw[1]&0x7F),
		true
}

func consumeStoredRTPPacket(packet model.Packet, payload []byte, seq int, timestamp uint32, ssrc string, marker bool, payloadType string, sessions map[string]*mediaSessionBuilder, protocolMap, applicationMap map[string]int) bool {
	if len(payload) == 0 {
		return false
	}
	protocolMap["RTP"]++

	key := fmt.Sprintf("%s:%d>%s:%d|%s|pt=%s", packet.SourceIP, packet.SourcePort, packet.DestIP, packet.DestPort, ssrc, payloadType)
	builder, ok := sessions[key]
	if !ok {
		builder = &mediaSessionBuilder{
			ID:              key,
			Family:          "RTP",
			Application:     inferApplicationFromPorts(packet.SourcePort, packet.DestPort),
			MediaType:       inferGameStreamMediaType(packet.SourcePort, packet.DestPort),
			Source:          packet.SourceIP,
			SourcePort:      packet.SourcePort,
			Destination:     packet.DestIP,
			DestinationPort: packet.DestPort,
			Transport:       "UDP",
			SSRC:            ssrc,
			PayloadType:     payloadType,
			Tags:            map[string]struct{}{"RTP": {}},
			Notes:           []string{"使用已缓存数据包离线重建：避免再次全量扫描抓包文件。"},
		}
		if isMoonlightGameStreamPort(packet.SourcePort, packet.DestPort) {
			builder.Tags["GameStream"] = struct{}{}
		}
		if builder.Application == "" {
			builder.Application = "RTP"
		}
		applicationMap[builder.Application]++
		sessions[key] = builder
	}

	builder.PacketCount++
	if builder.StartTime == "" {
		builder.StartTime = packet.Timestamp
	}
	builder.EndTime = packet.Timestamp
	if n := len(builder.Packets); n > 0 {
		prev := builder.Packets[n-1].Sequence
		if prev >= 0 && seq >= 0 {
			diff := (seq - prev + 65536) % 65536
			if diff > 1 {
				builder.GapCount += diff - 1
			}
		}
	}

	builder.Packets = append(builder.Packets, rtpPacketRecord{
		PacketID:   packet.ID,
		Time:       packet.Timestamp,
		Epoch:      0,
		Sequence:   seq,
		Timestamp:  timestamp,
		Marker:     marker,
		Payload:    payload,
		CodecHints: nil,
	})
	if builder.Codec == "" {
		builder.Codec = detectPacketCodec(nil, payload)
	}
	return true
}

func consumeStoredGameStreamPacket(packet model.Packet, payload []byte, seq int, timestamp uint32, ssrc string, marker bool, sessions map[string]*mediaSessionBuilder, protocolMap, applicationMap map[string]int) bool {
	if len(payload) == 0 {
		return false
	}
	protocolMap["GameStream UDP"]++

	payloadType := "0"
	key := fmt.Sprintf("%s:%d>%s:%d|%s|pt=%s", packet.SourceIP, packet.SourcePort, packet.DestIP, packet.DestPort, ssrc, payloadType)
	builder, ok := sessions[key]
	if !ok {
		builder = &mediaSessionBuilder{
			ID:              key,
			Family:          "RTP",
			Application:     inferApplicationFromPorts(packet.SourcePort, packet.DestPort),
			MediaType:       inferGameStreamMediaType(packet.SourcePort, packet.DestPort),
			Source:          packet.SourceIP,
			SourcePort:      packet.SourcePort,
			Destination:     packet.DestIP,
			DestinationPort: packet.DestPort,
			Transport:       "UDP",
			SSRC:            ssrc,
			PayloadType:     payloadType,
			Tags:            map[string]struct{}{"RTP": {}, "GameStream": {}},
			Notes:           []string{"使用已缓存数据包离线重建：抓包未被 tshark 识别为 RTP。"},
		}
		if builder.Application == "" {
			builder.Application = "Moonlight / GameStream"
		}
		applicationMap[builder.Application]++
		sessions[key] = builder
	}

	builder.PacketCount++
	if builder.StartTime == "" {
		builder.StartTime = packet.Timestamp
	}
	builder.EndTime = packet.Timestamp
	if n := len(builder.Packets); n > 0 {
		prev := builder.Packets[n-1].Sequence
		if prev >= 0 && seq >= 0 {
			diff := (seq - prev + 65536) % 65536
			if diff > 1 {
				builder.GapCount += diff - 1
			}
		}
	}

	builder.Packets = append(builder.Packets, rtpPacketRecord{
		PacketID:   packet.ID,
		Time:       packet.Timestamp,
		Epoch:      0,
		Sequence:   seq,
		Timestamp:  timestamp,
		Marker:     marker,
		Payload:    payload,
		CodecHints: nil,
	})
	return true
}

func hasGameStreamSession(sessions map[string]*mediaSessionBuilder) bool {
	for _, builder := range sessions {
		if builder == nil || builder.PacketCount == 0 {
			continue
		}
		if isGameStreamSession(builder) {
			return true
		}
	}
	return false
}

func scanGameStreamUDPSessions(filePath string, controlHints map[int][]mediaTrackHint, sessions map[string]*mediaSessionBuilder, protocolMap, applicationMap map[string]int) (int, error) {
	count := 0
	err := scanFieldRowsWithOptions(filePath, mediaGameStreamUDPFields, fieldScanOptions{
		DisplayFilter: gameStreamPortDisplayFilter(),
	}, func(parts []string) {
		raw := parseHexPayload(safeTrim(parts, 8))
		payload, seq, timestamp, ssrc, marker, ok := parseGameStreamUDPPayload(raw)
		if !ok {
			return
		}

		count++
		protocolMap["GameStream UDP"]++

		src := firstNonEmpty(safeTrim(parts, 2), safeTrim(parts, 3))
		dst := firstNonEmpty(safeTrim(parts, 4), safeTrim(parts, 5))
		srcPort := parseFlexibleInt(safeTrim(parts, 6))
		dstPort := parseFlexibleInt(safeTrim(parts, 7))
		payloadType := fmt.Sprintf("%d", raw[1]&0x7F)
		key := fmt.Sprintf("%s:%d>%s:%d|%s|pt=%s", src, srcPort, dst, dstPort, ssrc, payloadType)

		builder, exists := sessions[key]
		if !exists {
			builder = &mediaSessionBuilder{
				ID:              key,
				Family:          "RTP",
				Application:     inferApplicationFromPorts(srcPort, dstPort),
				MediaType:       inferGameStreamMediaType(srcPort, dstPort),
				Source:          src,
				SourcePort:      srcPort,
				Destination:     dst,
				DestinationPort: dstPort,
				Transport:       "UDP",
				SSRC:            ssrc,
				PayloadType:     payloadType,
				Tags:            map[string]struct{}{"RTP": {}, "GameStream": {}},
				Notes:           []string{"使用 GameStream UDP 回退解析：抓包未被 tshark 识别为 RTP。"},
			}
			applyMediaTrackHints(builder, controlHints[srcPort], payloadType)
			applyMediaTrackHints(builder, controlHints[dstPort], payloadType)
			if builder.Application == "" {
				builder.Application = "Moonlight / GameStream"
			}
			applicationMap[builder.Application]++
			sessions[key] = builder
		}

		packetTime := normalizeTimestamp(safeTrim(parts, 1))
		builder.PacketCount++
		if builder.StartTime == "" {
			builder.StartTime = packetTime
		}
		builder.EndTime = packetTime

		if n := len(builder.Packets); n > 0 {
			prev := builder.Packets[n-1].Sequence
			if prev >= 0 && seq >= 0 {
				diff := (seq - prev + 65536) % 65536
				if diff > 1 {
					builder.GapCount += diff - 1
				}
			}
		}

		builder.Packets = append(builder.Packets, rtpPacketRecord{
			PacketID:   parseInt64(safeTrim(parts, 0)),
			Time:       packetTime,
			Epoch:      parseEpochSeconds(safeTrim(parts, 1)),
			Sequence:   seq,
			Timestamp:  timestamp,
			Marker:     marker,
			Payload:    payload,
			CodecHints: nil,
		})
	})
	return count, err
}

func gameStreamPortDisplayFilter() string {
	ports := []int{47984, 47989, 47990, 47998, 47999, 48000, 48002, 48010}
	clauses := make([]string, 0, len(ports))
	for _, port := range ports {
		clauses = append(clauses, fmt.Sprintf("udp.port==%d", port))
	}
	return strings.Join(clauses, " || ")
}

func parseGameStreamUDPPayload(raw []byte) ([]byte, int, uint32, string, bool, bool) {
	if len(raw) <= gameStreamRTPPayloadOffset {
		return nil, 0, 0, "", false, false
	}
	if raw[0]&0xC0 != 0x80 {
		return nil, 0, 0, "", false, false
	}

	payload := raw[gameStreamRTPPayloadOffset:]
	if len(payload) < 16 {
		return nil, 0, 0, "", false, false
	}
	flags := payload[8]
	extraFlags := payload[9]
	if flags&^byte(0x07) != 0 {
		return nil, 0, 0, "", false, false
	}
	if extraFlags&^byte(0x01) != 0 {
		return nil, 0, 0, "", false, false
	}

	seq := int(binary.BigEndian.Uint16(raw[2:4]))
	timestamp := binary.BigEndian.Uint32(raw[4:8])
	ssrc := fmt.Sprintf("0x%X", binary.BigEndian.Uint32(raw[8:12]))
	marker := raw[1]&0x80 != 0

	trimmed := make([]byte, len(payload))
	copy(trimmed, payload)
	return trimmed, seq, timestamp, ssrc, marker, true
}

func reconstructVideoElementaryStream(builder *mediaSessionBuilder) ([]byte, string, error) {
	// For Moonlight / GameStream sessions, pre-process RTP payloads:
	// 1. Filter out FEC redundancy packets
	// 2. Strip NV proprietary headers (16 or 24 bytes) to expose raw H.264/H.265 data
	if isGameStreamSession(builder) {
		builder = preprocessGameStreamPackets(builder)
	}

	codec := strings.ToUpper(strings.TrimSpace(builder.Codec))

	// Defensive fallback: after NV header stripping the payloads are now bare
	// NAL data, so re-detect codec from the processed packets when still unknown.
	if codec == "" && isGameStreamSession(builder) {
		for _, pkt := range builder.Packets {
			if len(pkt.Payload) > 0 {
				if detected := detectPacketCodec(nil, pkt.Payload); detected != "" {
					codec = strings.ToUpper(detected)
					builder.Codec = detected
					break
				}
			}
		}
	}

	if isGameStreamSession(builder) {
		if payload, ext, err := reconstructGameStreamBytestream(builder, codec); err == nil && len(payload) > 0 {
			return payload, ext, nil
		}
		return nil, "", fmt.Errorf("unsupported GameStream video payload")
	}

	switch codec {
	case "H264":
		return reconstructH264Stream(builder)
	case "H265", "HEVC":
		return reconstructH265Stream(builder)
	default:
		return nil, "", fmt.Errorf("unsupported codec: %s", builder.Codec)
	}
}

func buildMediaArtifact(exportDir string, builder *mediaSessionBuilder, mediaType string) (*model.MediaArtifact, string, string) {
	var (
		payload []byte
		ext     string
		err     error
		note    string
	)

	switch strings.ToLower(strings.TrimSpace(mediaType)) {
	case "video":
		payload, ext, err = reconstructVideoElementaryStream(builder)
		note = "已生成可下载的视频裸流文件"
	case "audio":
		payload, ext, err = reconstructAudioElementaryStream(builder)
		note = "已生成可下载的音频裸流文件"
	default:
		return nil, "", ""
	}
	if err != nil || len(payload) == 0 {
		return nil, "", ""
	}

	name := buildMediaArtifactName(builder, ext)
	token := shortMediaToken(builder.ID)
	targetPath := filepath.Join(exportDir, name)
	if writeErr := os.WriteFile(targetPath, payload, 0o644); writeErr != nil {
		return nil, "", ""
	}
	info, _ := os.Stat(targetPath)
	size := int64(len(payload))
	if info != nil {
		size = info.Size()
	}
	return &model.MediaArtifact{
		Token:     token,
		Name:      name,
		Codec:     builder.Codec,
		Format:    strings.TrimPrefix(ext, "."),
		SizeBytes: size,
	}, targetPath, note
}

func reconstructAudioElementaryStream(builder *mediaSessionBuilder) ([]byte, string, error) {
	if builder == nil || len(builder.Packets) == 0 {
		return nil, "", fmt.Errorf("empty audio session")
	}
	payload := make([]byte, 0, len(builder.Packets)*160)
	for _, packet := range builder.Packets {
		if len(packet.Payload) == 0 {
			continue
		}
		payload = append(payload, packet.Payload...)
	}
	if len(payload) == 0 {
		return nil, "", fmt.Errorf("empty audio payload")
	}
	return payload, audioArtifactExtension(builder), nil
}

func audioArtifactExtension(builder *mediaSessionBuilder) string {
	codec := strings.ToUpper(strings.TrimSpace(builder.Codec))
	switch codec {
	case "PCMU", "G711U", "G.711U", "MULAW":
		return ".ulaw"
	case "PCMA", "G711A", "G.711A", "ALAW":
		return ".alaw"
	case "G722":
		return ".g722"
	case "L16":
		return ".l16"
	case "AAC", "MPEG4-GENERIC":
		return ".aac"
	case "OPUS":
		return ".opus"
	case "MPA", "MP3":
		return ".mpa"
	default:
		return ".raw"
	}
}

// isGameStreamSession returns true if the session is identified as Moonlight / GameStream.
func isGameStreamSession(builder *mediaSessionBuilder) bool {
	if builder == nil {
		return false
	}
	lowerFamily := strings.ToLower(builder.Family)
	lowerApp := strings.ToLower(builder.Application)
	if strings.Contains(lowerFamily, "gamestream") || strings.Contains(lowerFamily, "moonlight") {
		return true
	}
	if strings.Contains(lowerApp, "gamestream") || strings.Contains(lowerApp, "moonlight") {
		return true
	}
	return isMoonlightGameStreamPort(builder.SourcePort, builder.DestinationPort)
}

// nvIsDataPacket checks the NV FEC info field at RTP payload offset 12.
// Returns true if this is a data packet (index < data_pts), false if FEC redundancy.
// If the payload is too short to contain the FEC info, it returns true (pass through).
func nvIsDataPacket(payload []byte) bool {
	if len(payload) < 16 {
		return true // too short to have NV header, pass through
	}
	fecInfo := binary.LittleEndian.Uint32(payload[12:16])
	dataPts := (fecInfo & 0xFFC00000) >> 22
	index := (fecInfo & 0x003FF000) >> 12
	return index < dataPts
}

// nvVideoHeaderSize returns the NV proprietary header size to strip.
// When the RTP timestamp changes (new frame), the header is 24 bytes (16 + 8).
// For continuation packets with the same timestamp, the header is 16 bytes.
func nvVideoHeaderSize(prevTimestamp, currentTimestamp uint32, isFirst bool) int {
	if isFirst || prevTimestamp != currentTimestamp {
		return 24 // 16-byte NV header + 8-byte frame header
	}
	return 16 // 16-byte NV header only
}

// preprocessGameStreamPackets creates a shallow copy of the builder with packets
// that have been filtered (FEC removed) and had their NV headers stripped.
func preprocessGameStreamPackets(builder *mediaSessionBuilder) *mediaSessionBuilder {
	filtered := make([]rtpPacketRecord, 0, len(builder.Packets))

	var prevTimestamp uint32
	isFirst := true

	for _, pkt := range builder.Packets {
		if len(pkt.Payload) < 16 {
			continue // too short for NV header
		}

		// Step 1: FEC filter — discard redundancy packets
		if !nvIsDataPacket(pkt.Payload) {
			continue
		}

		// Step 2: Strip NV proprietary header
		headerSize := nvVideoHeaderSize(prevTimestamp, pkt.Timestamp, isFirst)
		prevTimestamp = pkt.Timestamp
		isFirst = false

		if headerSize >= len(pkt.Payload) {
			continue // nothing left after stripping header
		}

		stripped := make([]byte, len(pkt.Payload)-headerSize)
		copy(stripped, pkt.Payload[headerSize:])

		filtered = append(filtered, rtpPacketRecord{
			PacketID:   pkt.PacketID,
			Time:       pkt.Time,
			Epoch:      pkt.Epoch,
			Sequence:   pkt.Sequence,
			Timestamp:  pkt.Timestamp,
			Marker:     pkt.Marker,
			Payload:    stripped,
			CodecHints: pkt.CodecHints,
		})
	}

	// Return a shallow copy with the processed packets
	result := *builder
	result.Packets = filtered
	return &result
}

func reconstructH264Stream(builder *mediaSessionBuilder) ([]byte, string, error) {
	out := make([]byte, 0, len(builder.Packets)*64)
	for _, nal := range decodeH264ParameterSets(builder.CodecFmtp) {
		out = appendAnnexBNAL(out, nal)
	}

	inFragment := false
	for _, packet := range builder.Packets {
		payload := packet.Payload
		if len(payload) == 0 {
			continue
		}
		nalType := payload[0] & 0x1f
		switch {
		case nalType > 0 && nalType < 24:
			out = appendAnnexBNAL(out, payload)
			inFragment = false
		case nalType == 24:
			offset := 1
			for offset+2 <= len(payload) {
				size := int(payload[offset])<<8 | int(payload[offset+1])
				offset += 2
				if size <= 0 || offset+size > len(payload) {
					break
				}
				out = appendAnnexBNAL(out, payload[offset:offset+size])
				offset += size
			}
			inFragment = false
		case nalType == 28:
			if len(payload) < 2 {
				continue
			}
			indicator := payload[0]
			header := payload[1]
			start := header&0x80 != 0
			end := header&0x40 != 0
			rebuiltHeader := (indicator & 0xE0) | (header & 0x1F)
			if start || !inFragment {
				out = append(out, 0x00, 0x00, 0x00, 0x01, rebuiltHeader)
			}
			out = append(out, payload[2:]...)
			inFragment = !end
		}
	}
	if len(out) == 0 {
		return nil, "", fmt.Errorf("empty H264 stream")
	}
	return out, ".h264", nil
}

func reconstructH265Stream(builder *mediaSessionBuilder) ([]byte, string, error) {
	out := make([]byte, 0, len(builder.Packets)*64)
	for _, nal := range decodeH265ParameterSets(builder.CodecFmtp) {
		out = appendAnnexBNAL(out, nal)
	}

	inFragment := false
	for _, packet := range builder.Packets {
		payload := packet.Payload
		if len(payload) < 2 {
			continue
		}
		nalType := int((payload[0] >> 1) & 0x3F)
		switch {
		case nalType >= 0 && nalType < 48:
			out = appendAnnexBNAL(out, payload)
			inFragment = false
		case nalType == 48:
			offset := 2
			for offset+2 <= len(payload) {
				size := int(payload[offset])<<8 | int(payload[offset+1])
				offset += 2
				if size <= 0 || offset+size > len(payload) {
					break
				}
				out = appendAnnexBNAL(out, payload[offset:offset+size])
				offset += size
			}
			inFragment = false
		case nalType == 49:
			if len(payload) < 3 {
				continue
			}
			fuHeader := payload[2]
			start := fuHeader&0x80 != 0
			end := fuHeader&0x40 != 0
			nalHeader0 := (payload[0] & 0x81) | ((fuHeader & 0x3F) << 1)
			nalHeader1 := payload[1]
			if start || !inFragment {
				out = append(out, 0x00, 0x00, 0x00, 0x01, nalHeader0, nalHeader1)
			}
			out = append(out, payload[3:]...)
			inFragment = !end
		}
	}
	if len(out) == 0 {
		return nil, "", fmt.Errorf("empty H265 stream")
	}
	return out, ".h265", nil
}

func applyMediaTrackHints(builder *mediaSessionBuilder, hints []mediaTrackHint, payloadType string) {
	for _, hint := range hints {
		if builder.MediaType == "" {
			builder.MediaType = hint.MediaType
		}
		if builder.Application == "" {
			builder.Application = hint.Application
		}
		if builder.ControlSummary == "" {
			builder.ControlSummary = hint.ControlSummary
		}
		for tag := range hint.Tags {
			builder.Tags[tag] = struct{}{}
		}
		codec, ok := hint.CodecByPT[payloadType]
		if !ok && len(hint.CodecByPT) == 1 {
			for _, item := range hint.CodecByPT {
				codec = item
				ok = true
			}
		}
		if ok {
			if builder.Codec == "" {
				builder.Codec = codec.Name
			}
			if builder.ClockRate == 0 {
				builder.ClockRate = codec.ClockRate
			}
			if len(builder.CodecFmtp) == 0 && len(codec.Fmtp) > 0 {
				builder.CodecFmtp = cloneStringMap(codec.Fmtp)
			}
		}
	}
}

func parseSDPCodecHints(attrs []string) map[string]mediaCodecHint {
	out := make(map[string]mediaCodecHint)
	for _, attr := range attrs {
		value := strings.TrimSpace(attr)
		lower := strings.ToLower(value)
		switch {
		case strings.HasPrefix(lower, "rtpmap:"):
			payloadType, name, clock := parseSDPRTPMap(value)
			if payloadType == "" || name == "" {
				continue
			}
			codec := out[payloadType]
			codec.Name = normalizeMediaCodecName(name)
			codec.ClockRate = clock
			if codec.Fmtp == nil {
				codec.Fmtp = map[string]string{}
			}
			out[payloadType] = codec
		case strings.HasPrefix(lower, "fmtp:"):
			payloadType, params := parseSDPFmtp(value)
			if payloadType == "" {
				continue
			}
			codec := out[payloadType]
			if codec.Fmtp == nil {
				codec.Fmtp = map[string]string{}
			}
			for key, item := range params {
				codec.Fmtp[key] = item
			}
			out[payloadType] = codec
		}
	}
	return out
}

func parseSDPRTPMap(raw string) (string, string, int) {
	raw = strings.TrimSpace(raw)
	parts := strings.SplitN(raw, ":", 2)
	if len(parts) != 2 {
		return "", "", 0
	}
	right := strings.TrimSpace(parts[1])
	fields := strings.Fields(right)
	if len(fields) < 2 {
		return "", "", 0
	}
	payloadType := strings.TrimSpace(fields[0])
	encodingParts := strings.Split(strings.TrimSpace(fields[1]), "/")
	if len(encodingParts) == 0 {
		return payloadType, "", 0
	}
	clockRate := 0
	if len(encodingParts) > 1 {
		clockRate = parseFlexibleInt(encodingParts[1])
	}
	return payloadType, encodingParts[0], clockRate
}

func parseSDPFmtp(raw string) (string, map[string]string) {
	raw = strings.TrimSpace(raw)
	parts := strings.SplitN(raw, ":", 2)
	if len(parts) != 2 {
		return "", nil
	}
	right := strings.TrimSpace(parts[1])
	fields := strings.Fields(right)
	if len(fields) < 2 {
		return "", nil
	}
	payloadType := strings.TrimSpace(fields[0])
	paramText := strings.Join(fields[1:], " ")
	params := map[string]string{}
	for _, item := range strings.Split(paramText, ";") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		pair := strings.SplitN(item, "=", 2)
		key := strings.ToLower(strings.TrimSpace(pair[0]))
		if key == "" {
			continue
		}
		if len(pair) == 1 {
			params[key] = ""
			continue
		}
		params[key] = strings.TrimSpace(pair[1])
	}
	return payloadType, params
}

func parseSDPMediaEntry(raw, overridePort string) (string, int, []string) {
	fields := strings.Fields(strings.TrimSpace(raw))
	if len(fields) < 4 {
		return "", parseFlexibleInt(overridePort), nil
	}
	mediaType := strings.TrimSpace(fields[0])
	port := parseFlexibleInt(firstNonEmpty(overridePort, fields[1]))
	payloadTypes := make([]string, 0, len(fields)-3)
	for _, item := range fields[3:] {
		item = strings.TrimSpace(item)
		if item != "" {
			payloadTypes = append(payloadTypes, item)
		}
	}
	return mediaType, port, payloadTypes
}

func parseHexPayload(raw string) []byte {
	parts := splitHexBytes(raw)
	if len(parts) == 0 {
		return nil
	}
	decoded, err := hexDecodeString(strings.Join(parts, ""))
	if err != nil {
		return nil
	}
	return decoded
}

func detectPacketCodec(hints []string, payload []byte) string {
	for _, hint := range hints {
		if strings.TrimSpace(hint) != "" {
			return hint
		}
	}
	if len(payload) == 0 {
		return ""
	}

	if codec := detectAnnexBCodec(payload); codec != "" {
		return codec
	}

	nalType := payload[0] & 0x1F
	if nalType == 24 || nalType == 28 {
		return "H264"
	}
	if len(payload) >= 2 {
		h265Type := int((payload[0] >> 1) & 0x3F)
		if h265Type == 48 || h265Type == 49 {
			return "H265"
		}
	}
	return ""
}

func detectAnnexBCodec(payload []byte) string {
	offset, prefixLen, ok := findAnnexBStartCode(payload)
	if !ok {
		return ""
	}
	headerOffset := offset + prefixLen
	if headerOffset >= len(payload) {
		return ""
	}

	h264Type := int(payload[headerOffset] & 0x1F)
	if h264Type > 0 && h264Type < 24 {
		return "H264"
	}
	if headerOffset+1 < len(payload) {
		h265Type := int((payload[headerOffset] >> 1) & 0x3F)
		if h265Type >= 0 && h265Type < 48 {
			return "H265"
		}
	}
	return ""
}

func findAnnexBStartCode(payload []byte) (int, int, bool) {
	if len(payload) < 4 {
		return 0, 0, false
	}
	if idx := bytes.Index(payload, []byte{0x00, 0x00, 0x00, 0x01}); idx >= 0 {
		return idx, 4, true
	}
	if idx := bytes.Index(payload, []byte{0x00, 0x00, 0x01}); idx >= 0 {
		return idx, 3, true
	}
	return 0, 0, false
}

func inferSessionCodec(builder *mediaSessionBuilder) string {
	if isGameStreamSession(builder) {
		processed := preprocessGameStreamPackets(builder)
		for _, packet := range processed.Packets {
			if codec := detectPacketCodec(packet.CodecHints, packet.Payload); codec != "" {
				return codec
			}
		}
		return ""
	}

	// First pass: try detecting codec from raw payload (works for standard RTP)
	for _, packet := range builder.Packets {
		if codec := detectPacketCodec(packet.CodecHints, packet.Payload); codec != "" {
			return codec
		}
	}

	return ""
}

func applyStaticRTPProfile(builder *mediaSessionBuilder) {
	if builder == nil {
		return
	}
	mediaType, codec, clockRate := inferStaticRTPProfile(builder.PayloadType)
	if builder.MediaType == "" && mediaType != "" {
		builder.MediaType = mediaType
	}
	if builder.Codec == "" && codec != "" {
		builder.Codec = codec
	}
	if builder.ClockRate == 0 && clockRate > 0 {
		builder.ClockRate = clockRate
	}
}

func inferStaticRTPProfile(payloadType string) (mediaType, codec string, clockRate int) {
	pt := parseFlexibleInt(payloadType)
	switch pt {
	case 0:
		return "audio", "PCMU", 8000
	case 3:
		return "audio", "GSM", 8000
	case 4:
		return "audio", "G723", 8000
	case 8:
		return "audio", "PCMA", 8000
	case 9:
		return "audio", "G722", 8000
	case 10, 11:
		return "audio", "L16", 44100
	case 12:
		return "audio", "QCELP", 8000
	case 13:
		return "audio", "CN", 8000
	case 14:
		return "audio", "MPA", 90000
	case 15:
		return "audio", "G728", 8000
	case 16:
		return "audio", "DVI4", 11025
	case 17:
		return "audio", "DVI4", 22050
	case 18:
		return "audio", "G729", 8000
	case 25:
		return "video", "CelB", 90000
	case 26:
		return "video", "JPEG", 90000
	case 28:
		return "video", "nv", 90000
	case 31:
		return "video", "H261", 90000
	case 32:
		return "video", "MPV", 90000
	case 33:
		return "video", "MP2T", 90000
	case 34:
		return "video", "H263", 90000
	default:
		return "", "", 0
	}
}

func inferGameStreamMediaType(ports ...int) string {
	for _, port := range ports {
		switch port {
		case 47998:
			return "video"
		case 48000:
			return "audio"
		}
	}
	return ""
}

func detectMediaApplication(text string, ports ...int) (string, []string) {
	app := "RTSP / RTP"
	tags := []string{"RTP"}
	if strings.Contains(text, "moonlight") {
		app = "Moonlight"
		tags = append(tags, "Moonlight")
	}
	if strings.Contains(text, "gamestream") || strings.Contains(text, "nvst") || strings.Contains(text, "sunshine") {
		app = "Moonlight / GameStream"
		tags = append(tags, "GameStream")
	}
	if isMoonlightGameStreamPort(ports...) {
		app = "Moonlight / GameStream"
		tags = append(tags, "GameStream Ports")
	}
	return app, dedupeStrings(tags)
}

func inferApplicationFromPorts(ports ...int) string {
	if isMoonlightGameStreamPort(ports...) {
		return "Moonlight / GameStream"
	}
	return "RTP"
}

func isMoonlightGameStreamPort(ports ...int) bool {
	for _, port := range ports {
		switch port {
		case 47984, 47989, 47990, 47998, 47999, 48000, 48002, 48010:
			return true
		}
	}
	return false
}

func reconstructGameStreamBytestream(builder *mediaSessionBuilder, codec string) ([]byte, string, error) {
	if builder == nil || len(builder.Packets) == 0 {
		return nil, "", fmt.Errorf("empty GameStream session")
	}
	if len(builder.Packets) < 8 {
		return nil, "", fmt.Errorf("gamestream packet window too small")
	}

	detectedCodec := strings.ToUpper(strings.TrimSpace(codec))
	if detectedCodec == "" {
		for _, packet := range builder.Packets {
			if codec := detectAnnexBCodec(packet.Payload); codec != "" {
				detectedCodec = strings.ToUpper(codec)
				break
			}
		}
	}
	if detectedCodec == "" {
		return nil, "", fmt.Errorf("gamestream bytestream codec unknown")
	}

	sawAnnexB := false
	total := 0
	for _, packet := range builder.Packets {
		if len(packet.Payload) == 0 {
			continue
		}
		total += len(packet.Payload)
		if !sawAnnexB && strings.EqualFold(detectedCodec, detectAnnexBCodec(packet.Payload)) {
			sawAnnexB = true
		}
	}
	if !sawAnnexB || total == 0 {
		return nil, "", fmt.Errorf("gamestream bytestream not detected")
	}

	out := make([]byte, 0, total)
	for _, packet := range builder.Packets {
		if len(packet.Payload) == 0 {
			continue
		}
		out = append(out, packet.Payload...)
	}

	switch detectedCodec {
	case "H264":
		return out, ".h264", nil
	case "H265", "HEVC":
		return out, ".h265", nil
	default:
		return nil, "", fmt.Errorf("unsupported gamestream bytestream codec: %s", detectedCodec)
	}
}

func extractTransportPorts(raw string) []int {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return nil
	}
	ports := make([]int, 0, 4)
	for _, key := range []string{"client_port=", "server_port=", "port="} {
		idx := strings.Index(raw, key)
		if idx < 0 {
			continue
		}
		value := raw[idx+len(key):]
		end := strings.IndexAny(value, ";, ")
		if end >= 0 {
			value = value[:end]
		}
		for _, item := range strings.Split(value, "-") {
			port := parseFlexibleInt(item)
			if port > 0 {
				ports = append(ports, port)
			}
		}
	}
	return dedupeInts(ports)
}

func addMediaTrackHint(target map[int][]mediaTrackHint, port int, hint mediaTrackHint) {
	if port <= 0 {
		return
	}
	target[port] = append(target[port], hint)
}

func splitAggregatedField(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	items := strings.Split(raw, "|")
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func pickByIndex(items []string, idx int) string {
	if idx < 0 || idx >= len(items) {
		return ""
	}
	return strings.TrimSpace(items[idx])
}

func shortMediaToken(seed string) string {
	sum := sha1.Sum([]byte(seed))
	return fmt.Sprintf("media-%x", sum[:6])
}

func buildMediaArtifactName(builder *mediaSessionBuilder, ext string) string {
	ssrc := strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(builder.SSRC)), "0X")
	if ssrc == "" {
		ssrc = "0"
	}
	payloadType := safeMediaName(firstNonEmpty(builder.PayloadType, "pt"))
	name := fmt.Sprintf(
		"%s_%s_pt%s_ssrc%s_%s_%d_%s_%d%s",
		safeMediaName(firstNonEmpty(builder.Application, "rtp")),
		safeMediaName(firstNonEmpty(builder.Codec, "video")),
		payloadType,
		safeMediaName(ssrc),
		safeMediaName(firstNonEmpty(builder.Source, "src")),
		builder.SourcePort,
		safeMediaName(firstNonEmpty(builder.Destination, "dst")),
		builder.DestinationPort,
		ext,
	)
	return name
}

func safeMediaName(raw string) string {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return "unknown"
	}
	var b strings.Builder
	for _, ch := range raw {
		switch {
		case ch >= 'a' && ch <= 'z':
			b.WriteRune(ch)
		case ch >= '0' && ch <= '9':
			b.WriteRune(ch)
		case ch == '.' || ch == '-' || ch == '_':
			b.WriteRune(ch)
		default:
			b.WriteByte('_')
		}
	}
	return strings.Trim(b.String(), "_")
}

func decodeH264ParameterSets(fmtp map[string]string) [][]byte {
	raw := strings.TrimSpace(fmtp["sprop-parameter-sets"])
	if raw == "" {
		return nil
	}
	out := make([][]byte, 0, 2)
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if decoded, err := base64.StdEncoding.DecodeString(item); err == nil && len(decoded) > 0 {
			out = append(out, decoded)
		}
	}
	return out
}

func decodeH265ParameterSets(fmtp map[string]string) [][]byte {
	keys := []string{"sprop-vps", "sprop-sps", "sprop-pps"}
	out := make([][]byte, 0, len(keys))
	for _, key := range keys {
		raw := strings.TrimSpace(fmtp[key])
		if raw == "" {
			continue
		}
		if decoded, err := base64.StdEncoding.DecodeString(raw); err == nil && len(decoded) > 0 {
			out = append(out, decoded)
		}
	}
	return out
}

func appendAnnexBNAL(dst []byte, nal []byte) []byte {
	if len(nal) == 0 {
		return dst
	}
	dst = append(dst, 0x00, 0x00, 0x00, 0x01)
	dst = append(dst, nal...)
	return dst
}

func hexDecodeString(raw string) ([]byte, error) {
	if len(raw)%2 != 0 {
		raw = "0" + raw
	}
	out := make([]byte, len(raw)/2)
	for i := 0; i < len(raw); i += 2 {
		value, err := strconv.ParseUint(raw[i:i+2], 16, 8)
		if err != nil {
			return nil, err
		}
		out[i/2] = byte(value)
	}
	return out, nil
}

func cloneCodecHintMap(input map[string]mediaCodecHint) map[string]mediaCodecHint {
	if len(input) == 0 {
		return nil
	}
	out := make(map[string]mediaCodecHint, len(input))
	for key, value := range input {
		out[key] = mediaCodecHint{
			Name:      value.Name,
			ClockRate: value.ClockRate,
			Fmtp:      cloneStringMap(value.Fmtp),
		}
	}
	return out
}

func cloneStringMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	out := make(map[string]string, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}

func sliceToSet(items []string) map[string]struct{} {
	out := make(map[string]struct{}, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		out[item] = struct{}{}
	}
	return out
}

func sortedKeys(items map[string]struct{}) []string {
	if len(items) == 0 {
		return nil
	}
	out := make([]string, 0, len(items))
	for key := range items {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func dedupeStrings(items []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

func dedupeInts(items []int) []int {
	seen := map[int]struct{}{}
	out := make([]int, 0, len(items))
	for _, item := range items {
		if item <= 0 {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	sort.Ints(out)
	return out
}

func normalizeMediaCodecName(raw string) string {
	value := strings.ToUpper(strings.TrimSpace(raw))
	switch value {
	case "H264", "AVC":
		return "H264"
	case "H265", "HEVC":
		return "H265"
	default:
		return value
	}
}

func buildMediaAnalysisNotes(stats model.MediaAnalysis) []string {
	notes := make([]string, 0, 4)
	if len(stats.Sessions) == 0 {
		return []string{"当前抓包未识别到可还原的 RTP 媒体会话。"}
	}
	for _, session := range stats.Sessions {
		if strings.Contains(session.Application, "Moonlight") || strings.Contains(session.Application, "GameStream") {
			notes = append(notes, "已识别到 Moonlight / GameStream 相关控制面或媒体端口，可直接导出视频裸流做二次分析。")
			break
		}
	}
	for _, session := range stats.Sessions {
		if session.Artifact != nil {
			if strings.EqualFold(session.MediaType, "audio") {
				notes = append(notes, "已为可识别的音频会话生成裸流文件，可直接下载做二次分析。")
			} else {
				notes = append(notes, "视频会话已生成裸流文件，若本地存在 ffmpeg 可进一步转封装为 MP4。")
			}
			break
		}
	}
	if len(notes) == 0 {
		notes = append(notes, "已识别到 RTP 媒体会话，但暂未判定为可导出的视频裸流，可能仅包含音频流、控制流或未知编码。")
	}
	for _, session := range stats.Sessions {
		if session.GapCount > 0 {
			notes = append(notes, "存在 RTP 序号间断，说明抓包有丢包或乱序，恢复后的视频可能出现花屏或跳帧。")
			break
		}
	}
	return dedupeStrings(notes)
}

package engine

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/gshark/sentinel/backend/internal/model"
	"github.com/gshark/sentinel/backend/internal/tshark"
)

const (
	c2DecryptMaxRecords       = 500
	c2DecryptPreviewMaxBytes  = 4096
	c2DecryptKeyStatusNA      = "not_applicable"
	c2DecryptKeyStatusOK      = "verified"
	c2DecryptKeyStatusWeak    = "unverified"
	c2DecryptDirectionUnknown = "unknown"
)

type c2DecryptCandidate struct {
	packet    model.Packet
	raw       []byte
	label     string
	transform string
	direction string
}

type c2CSDecryptStats struct {
	total           int
	httpFocused     int
	metadata        int
	hmacVerified    int
	decryptedWeak   int
	hmacRejected    int
	cryptoRejected  int
	metadataSkipped int
}

func (s *Service) C2Decrypt(ctx context.Context, req model.C2DecryptRequest) (model.C2DecryptResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, finishTask := s.TrackCaptureTask(ctx, "c2-decrypt")
	defer finishTask()
	if err := ctx.Err(); err != nil {
		return model.C2DecryptResult{}, err
	}
	family := strings.ToLower(strings.TrimSpace(req.Family))
	if family != "cs" && family != "vshell" {
		return model.C2DecryptResult{}, errors.New("family must be cs or vshell")
	}
	result := model.C2DecryptResult{
		Family:  family,
		Status:  "failed",
		Records: []model.C2DecryptedRecord{},
		Notes:   []string{},
	}
	candidates, err := s.collectC2DecryptCandidates(ctx, family, req.Scope)
	if err != nil {
		return result, err
	}
	result.TotalCandidates = len(candidates)
	if len(candidates) == 0 {
		result.Notes = append(result.Notes, "当前抓包没有可用于该 family 的候选 payload；请先确认 C2 analysis 已形成候选证据，或 TLS/HTTP payload 已经可见。")
		return result, nil
	}
	switch family {
	case "vshell":
		result = decryptVShellCandidates(ctx, req, candidates, result)
	case "cs":
		result = decryptCSCandidates(ctx, req, candidates, result)
	}
	for _, record := range result.Records {
		if record.Error != "" {
			result.FailedCount++
		} else if record.PlaintextPreview != "" {
			result.DecryptedCount++
		}
	}
	if result.DecryptedCount > 0 && result.FailedCount > 0 {
		result.Status = "partial"
	} else if result.DecryptedCount > 0 {
		result.Status = "completed"
	} else {
		result.Status = "failed"
	}
	return result, ctx.Err()
}

func (s *Service) collectC2DecryptCandidates(ctx context.Context, family string, scope model.C2DecryptScope) ([]c2DecryptCandidate, error) {
	analysis, err := s.C2SampleAnalysis(ctx)
	if err != nil {
		return nil, err
	}
	packetIDs := map[int64]struct{}{}
	streamIDs := map[int64]struct{}{}
	for _, id := range scope.PacketIDs {
		if id > 0 {
			packetIDs[id] = struct{}{}
		}
	}
	for _, id := range scope.StreamIDs {
		if id >= 0 {
			streamIDs[id] = struct{}{}
		}
	}
	useCandidates := scope.UseCandidates || (!scope.UseCandidates && !scope.UseAggregates && len(packetIDs) == 0 && len(streamIDs) == 0)
	useAggregates := scope.UseAggregates || (!scope.UseCandidates && !scope.UseAggregates && len(packetIDs) == 0 && len(streamIDs) == 0)
	familyAnalysis := analysis.CS
	if family == "vshell" {
		familyAnalysis = analysis.VShell
	}
	if useCandidates {
		for _, candidate := range familyAnalysis.Candidates {
			if candidate.PacketID > 0 {
				packetIDs[candidate.PacketID] = struct{}{}
			}
			if candidate.StreamID >= 0 {
				streamIDs[candidate.StreamID] = struct{}{}
			}
		}
	}
	if useAggregates {
		for _, item := range familyAnalysis.HostURIAggregates {
			for _, id := range item.Packets {
				packetIDs[id] = struct{}{}
			}
			for _, id := range item.Streams {
				streamIDs[id] = struct{}{}
			}
		}
		for _, item := range familyAnalysis.DNSAggregates {
			for _, id := range item.Packets {
				packetIDs[id] = struct{}{}
			}
		}
		for _, item := range familyAnalysis.StreamAggregates {
			for _, id := range item.Packets {
				packetIDs[id] = struct{}{}
			}
			if item.StreamID >= 0 {
				streamIDs[item.StreamID] = struct{}{}
			}
		}
	}
	out := make([]c2DecryptCandidate, 0, c2DecryptMaxRecords)
	seen := map[string]struct{}{}
	packetCandidates := make([]c2DecryptCandidate, 0, c2DecryptMaxRecords)
	packetSeen := map[string]struct{}{}
	streamRepresentatives := map[int64]model.Packet{}
	if s.packetStore == nil {
		return out, nil
	}
	err = s.packetStore.Iterate(nil, func(packet model.Packet) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		_, packetSelected := packetIDs[packet.ID]
		_, streamSelected := streamIDs[packet.StreamID]
		csGlobalDecryptCandidate := family == "cs" && isLikelyCSPacketLevelDecryptSource(packet)
		if len(packetIDs) > 0 || len(streamIDs) > 0 {
			if !packetSelected && !streamSelected && !csGlobalDecryptCandidate {
				return nil
			}
		}
		if packet.StreamID >= 0 {
			if _, exists := streamRepresentatives[packet.StreamID]; !exists {
				streamRepresentatives[packet.StreamID] = packet
			}
			if packetSelected {
				streamIDs[packet.StreamID] = struct{}{}
			}
		}
		for _, candidate := range extractC2PacketCandidateBytes(packet, family) {
			if len(packetCandidates) >= c2DecryptMaxRecords {
				break
			}
			appendC2DecryptCandidate(&packetCandidates, packetSeen, candidate)
		}
		return nil
	})
	if err == nil && family == "vshell" {
		if streamErr := s.collectVShellStreamDecryptCandidates(ctx, streamIDs, streamRepresentatives, seen, &out); streamErr != nil {
			err = streamErr
		}
	}
	if err == nil && family == "cs" {
		_ = s.collectCSHTTPFieldDecryptCandidates(ctx, seen, &out)
	}
	if err == nil {
		for _, candidate := range packetCandidates {
			if appendC2DecryptCandidate(&out, seen, candidate) {
				break
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if c2DecryptCandidatePriority(out[i]) != c2DecryptCandidatePriority(out[j]) {
			return c2DecryptCandidatePriority(out[i]) < c2DecryptCandidatePriority(out[j])
		}
		if out[i].packet.ID != out[j].packet.ID {
			return out[i].packet.ID < out[j].packet.ID
		}
		return out[i].transform < out[j].transform
	})
	return out, err
}

func c2DecryptCandidatePriority(candidate c2DecryptCandidate) int {
	if strings.HasPrefix(candidate.transform, "raw-stream-") {
		return 0
	}
	if strings.HasPrefix(candidate.transform, "cs-http-") {
		return 0
	}
	if strings.HasPrefix(candidate.transform, "cs-metadata-") {
		return 2
	}
	return 1
}

func appendC2DecryptCandidate(out *[]c2DecryptCandidate, seen map[string]struct{}, candidate c2DecryptCandidate) bool {
	return appendC2DecryptCandidateWithLimit(out, seen, candidate, c2DecryptMaxRecords)
}

func appendC2DecryptCandidateUnbounded(out *[]c2DecryptCandidate, seen map[string]struct{}, candidate c2DecryptCandidate) {
	appendC2DecryptCandidateWithLimit(out, seen, candidate, 0)
}

func appendC2DecryptCandidateWithLimit(out *[]c2DecryptCandidate, seen map[string]struct{}, candidate c2DecryptCandidate, limit int) bool {
	if limit > 0 && len(*out) >= limit {
		return true
	}
	if len(candidate.raw) == 0 {
		return limit > 0 && len(*out) >= limit
	}
	key := fmt.Sprintf("%d|%d|%s|%s|%x", candidate.packet.ID, candidate.packet.StreamID, candidate.transform, candidate.direction, candidate.raw)
	if _, ok := seen[key]; ok {
		return limit > 0 && len(*out) >= limit
	}
	seen[key] = struct{}{}
	*out = append(*out, candidate)
	return limit > 0 && len(*out) >= limit
}

func extractC2PacketCandidateBytes(packet model.Packet, family string) []c2DecryptCandidate {
	if family == "cs" {
		return extractCSPacketCandidateBytes(packet)
	}
	values := make([]string, 0, 8)
	if strings.TrimSpace(packet.Payload) != "" {
		values = append(values, packet.Payload)
		if body := httpBody(packet.Payload); body != "" {
			values = append(values, body)
		}
		for _, value := range httpPayloadValues(packet.Payload) {
			values = append(values, value)
		}
	}
	if transportPayload := extractPacketTransportPayload(packet); transportPayload != "" {
		values = append(values, transportPayload)
	}
	if strings.TrimSpace(packet.RawHex) != "" {
		values = append(values, packet.RawHex)
	}
	if strings.TrimSpace(packet.UDPPayloadHex) != "" {
		values = append(values, packet.UDPPayloadHex)
	}
	out := make([]c2DecryptCandidate, 0, len(values)*4)
	for _, value := range values {
		for _, transformed := range decodeC2TransformCandidates(value, "auto") {
			if family == "cs" && len(transformed.raw) < 8 {
				continue
			}
			if family == "vshell" && len(transformed.raw) < 8 {
				continue
			}
			out = append(out, c2DecryptCandidate{
				packet:    packet,
				raw:       transformed.raw,
				label:     transformed.label,
				transform: transformed.transform,
			})
		}
	}
	return out
}

func extractCSPacketCandidateBytes(packet model.Packet) []c2DecryptCandidate {
	out := make([]c2DecryptCandidate, 0, 8)
	if strings.TrimSpace(packet.Payload) != "" {
		for _, value := range csHTTPDecryptPayloadValues(packet.Payload) {
			appendC2TransformedPacketCandidates(&out, packet, value, "cs-http")
		}
		for _, value := range csMetadataPayloadValues(packet.Payload) {
			appendC2TransformedPacketCandidates(&out, packet, value, "cs-metadata")
		}
	}
	if transportPayload := extractPacketTransportPayload(packet); transportPayload != "" && isLikelyCSHTTPDecryptPacket(packet, "") {
		appendC2TransformedPacketCandidates(&out, packet, transportPayload, "cs-http-transport")
	}
	if strings.TrimSpace(packet.RawHex) != "" && isLikelyCSHTTPDecryptPacket(packet, "") {
		appendC2TransformedPacketCandidates(&out, packet, packet.RawHex, "cs-http-rawhex")
	}
	return out
}

func appendC2TransformedPacketCandidates(out *[]c2DecryptCandidate, packet model.Packet, value string, prefix string) {
	for _, transformed := range decodeC2TransformCandidates(value, "auto") {
		if len(transformed.raw) < 8 {
			continue
		}
		*out = append(*out, c2DecryptCandidate{
			packet:    packet,
			raw:       transformed.raw,
			label:     transformed.label,
			transform: prefix + "-" + transformed.transform,
		})
	}
}

func csHTTPDecryptPayloadValues(payload string) []string {
	normalized := strings.ReplaceAll(payload, "\r\n", "\n")
	firstLine := strings.TrimSpace(strings.SplitN(normalized, "\n", 2)[0])
	fields := strings.Fields(firstLine)
	if len(fields) == 0 {
		return nil
	}
	method := strings.ToUpper(fields[0])
	isResponse200 := strings.HasPrefix(strings.ToUpper(firstLine), "HTTP/") && strings.Contains(firstLine, " 200")
	isPostLike := method == "POST" || method == "PUT" || method == "PATCH"
	if !isResponse200 && !isPostLike {
		return nil
	}
	out := []string{}
	if body := strings.TrimSpace(httpBody(payload)); body != "" {
		out = append(out, body)
		if values, err := url.ParseQuery(body); err == nil {
			for _, list := range values {
				out = append(out, list...)
			}
		}
	}
	return out
}

func csMetadataPayloadValues(payload string) []string {
	normalized := strings.ReplaceAll(payload, "\r\n", "\n")
	firstLine := strings.TrimSpace(strings.SplitN(normalized, "\n", 2)[0])
	fields := strings.Fields(firstLine)
	if len(fields) == 0 || strings.ToUpper(fields[0]) != "GET" {
		return nil
	}
	out := []string{}
	for _, line := range strings.Split(normalized, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(trimmed), "cookie:") || strings.HasPrefix(strings.ToLower(trimmed), "authorization:") {
			out = append(out, strings.TrimSpace(strings.SplitN(trimmed, ":", 2)[1]))
		}
	}
	if len(fields) >= 2 {
		if parsed, err := url.Parse(fields[1]); err == nil {
			for _, list := range parsed.Query() {
				out = append(out, list...)
			}
		}
	}
	return out
}

func isLikelyCSHTTPDecryptPacket(packet model.Packet, payload string) bool {
	text := strings.TrimSpace(payload)
	if text == "" {
		text = strings.TrimSpace(packet.Payload)
	}
	info := strings.ToUpper(packet.Info + "\n" + text)
	return strings.Contains(info, "HTTP/1.") && (strings.Contains(info, " 200") || strings.Contains(info, "POST ") || strings.Contains(info, "PUT ") || strings.Contains(info, "PATCH "))
}

func isLikelyCSPacketLevelDecryptSource(packet model.Packet) bool {
	payload := strings.TrimSpace(packet.Payload)
	if payload == "" {
		return false
	}
	if len(csHTTPDecryptPayloadValues(payload)) > 0 || len(csMetadataPayloadValues(payload)) > 0 {
		return true
	}
	return isLikelyCSHTTPDecryptPacket(packet, payload)
}

func (s *Service) collectCSHTTPFieldDecryptCandidates(ctx context.Context, seen map[string]struct{}, out *[]c2DecryptCandidate) error {
	s.mu.RLock()
	pcap := strings.TrimSpace(s.pcap)
	s.mu.RUnlock()
	if pcap == "" || len(*out) >= c2DecryptMaxRecords {
		return nil
	}
	cmd, err := tshark.CommandContext(ctx,
		"-r", pcap,
		"-Y", `http && (http.request.method == POST || (http.response.code == 200 && http.content_length < 100000) || http.cookie || http.authorization)`,
		"-T", "fields",
		"-E", "separator=/t",
		"-e", "frame.number",
		"-e", "tcp.stream",
		"-e", "frame.time_epoch",
		"-e", "ip.src",
		"-e", "tcp.srcport",
		"-e", "ip.dst",
		"-e", "tcp.dstport",
		"-e", "http.request.method",
		"-e", "http.request.uri",
		"-e", "http.response.code",
		"-e", "http.cookie",
		"-e", "http.authorization",
		"-e", "http.file_data",
		"-e", "data.data",
	)
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	readErr := readCSHTTPFieldCandidates(ctx, stdout, seen, out)
	waitErr := cmd.Wait()
	if readErr != nil {
		return readErr
	}
	if waitErr != nil {
		return waitErr
	}
	return nil
}

func readCSHTTPFieldCandidates(ctx context.Context, reader io.Reader, seen map[string]struct{}, out *[]c2DecryptCandidate) error {
	buf := bufio.NewReaderSize(reader, 1024*1024)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		line, err := buf.ReadString('\n')
		if len(*out) < c2DecryptMaxRecords && len(strings.TrimSpace(line)) > 0 {
			appendCSHTTPFieldCandidatesFromLine(line, seen, out)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
	return nil
}

func appendCSHTTPFieldCandidatesFromLine(line string, seen map[string]struct{}, out *[]c2DecryptCandidate) {
	fields := strings.Split(strings.TrimRight(line, "\r\n"), "\t")
	for len(fields) < 14 {
		fields = append(fields, "")
	}
	frameID, _ := strconv.ParseInt(strings.TrimSpace(fields[0]), 10, 64)
	streamID, _ := strconv.ParseInt(strings.TrimSpace(fields[1]), 10, 64)
	sourcePort, _ := strconv.Atoi(strings.TrimSpace(fields[4]))
	destPort, _ := strconv.Atoi(strings.TrimSpace(fields[6]))
	method := strings.ToUpper(strings.TrimSpace(fields[7]))
	status := strings.TrimSpace(fields[9])
	packet := model.Packet{
		ID:         frameID,
		StreamID:   streamID,
		Timestamp:  strings.TrimSpace(fields[2]),
		SourceIP:   strings.TrimSpace(fields[3]),
		SourcePort: sourcePort,
		DestIP:     strings.TrimSpace(fields[5]),
		DestPort:   destPort,
		Protocol:   "HTTP",
	}
	direction := c2DecryptDirectionUnknown
	if method == "POST" || method == "PUT" || method == "PATCH" {
		direction = "client_to_server"
	} else if status == "200" {
		direction = "server_to_client"
	}
	for _, item := range []struct {
		value string
		tag   string
	}{
		{fields[12], "http_file_data"},
		{fields[13], "data_data"},
	} {
		raw, ok := decodeColonOrPlainHex(item.value)
		if !ok || len(raw) < 8 || len(raw) > 128*1024 {
			continue
		}
		candidate := c2DecryptCandidate{
			packet:    packet,
			raw:       raw,
			label:     "tshark:" + item.tag,
			transform: "cs-http-tshark-" + item.tag + "-hex",
			direction: direction,
		}
		if appendC2DecryptCandidate(out, seen, candidate) {
			return
		}
	}
	for _, item := range []struct {
		value string
		tag   string
	}{
		{fields[10], "cookie"},
		{fields[11], "authorization"},
		{fields[8], "uri"},
	} {
		for _, transformed := range decodeC2TransformCandidates(item.value, "auto") {
			if len(transformed.raw) < 8 {
				continue
			}
			candidate := c2DecryptCandidate{
				packet:    packet,
				raw:       transformed.raw,
				label:     transformed.label,
				transform: "cs-metadata-tshark-" + item.tag + "-" + transformed.transform,
				direction: "client_to_server",
			}
			if appendC2DecryptCandidate(out, seen, candidate) {
				return
			}
		}
	}
}

func decodeColonOrPlainHex(raw string) ([]byte, bool) {
	cleaned := regexp.MustCompile(`(?i)[^0-9a-f]`).ReplaceAllString(raw, "")
	if len(cleaned) < 8 || len(cleaned)%2 != 0 {
		return nil, false
	}
	decoded, err := hex.DecodeString(cleaned)
	return decoded, err == nil
}

func (s *Service) collectVShellStreamDecryptCandidates(ctx context.Context, streamIDs map[int64]struct{}, representatives map[int64]model.Packet, seen map[string]struct{}, out *[]c2DecryptCandidate) error {
	if len(streamIDs) == 0 {
		return nil
	}
	ids := make([]int64, 0, len(streamIDs))
	for id := range streamIDs {
		if id >= 0 {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, streamID := range ids {
		if err := ctx.Err(); err != nil {
			return err
		}
		stream := s.RawStream(ctx, "TCP", streamID)
		if len(stream.Chunks) == 0 {
			continue
		}
		for _, assembled := range assembleVShellStreamDirections(stream) {
			for _, transformed := range decodeC2TransformCandidates(assembled.body, "auto") {
				if len(transformed.raw) < 8 {
					continue
				}
				packet := streamRepresentativePacket(streamID, assembled.direction, stream, representatives[streamID])
				candidate := c2DecryptCandidate{
					packet:    packet,
					raw:       transformed.raw,
					label:     fmt.Sprintf("tcp-stream:%d:%s", streamID, assembled.direction),
					transform: "raw-stream-" + assembled.direction + "-" + transformed.transform,
					direction: streamChunkRecordDirection(assembled.direction),
				}
				appendC2DecryptCandidateUnbounded(out, seen, candidate)
			}
		}
	}
	return nil
}

type vshellStreamDirectionPayload struct {
	direction string
	body      string
}

func assembleVShellStreamDirections(stream model.ReassembledStream) []vshellStreamDirectionPayload {
	type directionState struct {
		body  string
		order int
	}
	byDirection := map[string]directionState{}
	order := make([]string, 0, 2)
	for _, chunk := range stream.Chunks {
		direction := strings.ToLower(strings.TrimSpace(chunk.Direction))
		if direction == "" {
			direction = c2DecryptDirectionUnknown
		}
		body := strings.TrimSpace(chunk.Body)
		if body == "" {
			continue
		}
		state, exists := byDirection[direction]
		if !exists {
			state.order = len(order)
			order = append(order, direction)
		}
		state.body = joinStreamChunkBodies(state.body, body)
		byDirection[direction] = state
	}
	sort.SliceStable(order, func(i, j int) bool {
		return byDirection[order[i]].order < byDirection[order[j]].order
	})
	out := make([]vshellStreamDirectionPayload, 0, len(order))
	for _, direction := range order {
		body := byDirection[direction].body
		if body == "" {
			continue
		}
		out = append(out, vshellStreamDirectionPayload{direction: direction, body: body})
	}
	return out
}

func streamRepresentativePacket(streamID int64, direction string, stream model.ReassembledStream, fallback model.Packet) model.Packet {
	packet := fallback
	if packet.StreamID < 0 || packet.StreamID == 0 && streamID != 0 {
		packet.StreamID = streamID
	}
	for _, chunk := range stream.Chunks {
		if !strings.EqualFold(chunk.Direction, direction) {
			continue
		}
		if chunk.PacketID > 0 {
			packet.ID = chunk.PacketID
		}
		break
	}
	if packet.Protocol == "" {
		packet.Protocol = "TCP"
	}
	return packet
}

func streamChunkRecordDirection(direction string) string {
	switch strings.ToLower(strings.TrimSpace(direction)) {
	case "client":
		return "client_to_server"
	case "server":
		return "server_to_client"
	default:
		return c2DecryptDirectionUnknown
	}
}

type c2TransformedBytes struct {
	raw       []byte
	label     string
	transform string
}

func decodeC2TransformCandidates(raw string, mode string) []c2TransformedBytes {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	modes := []string{mode}
	if mode == "" || mode == "auto" {
		modes = []string{"raw", "hex", "base64", "base64url", "netbios", "netbiosu"}
	}
	out := make([]c2TransformedBytes, 0, len(modes))
	seen := map[string]struct{}{}
	for _, item := range extractLoosePayloadTokens(raw) {
		for _, transform := range modes {
			decoded, ok := decodeC2Transform(item, transform)
			if !ok || len(decoded) == 0 {
				continue
			}
			key := transform + "|" + string(decoded)
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, c2TransformedBytes{raw: decoded, label: item, transform: transform})
		}
	}
	return out
}

func extractLoosePayloadTokens(raw string) []string {
	tokens := []string{raw}
	for _, pair := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ';' || r == '&' || r == '\r' || r == '\n' || unicode.IsSpace(r)
	}) {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		if idx := strings.Index(pair, "="); idx >= 0 && idx+1 < len(pair) {
			tokens = append(tokens, pair[idx+1:])
		}
		tokens = append(tokens, strings.Trim(pair, `"'`))
	}
	out := make([]string, 0, len(tokens))
	seen := map[string]struct{}{}
	for _, token := range tokens {
		token = strings.TrimSpace(strings.Trim(token, `"'`))
		if token == "" {
			continue
		}
		if decoded, err := url.PathUnescape(token); err == nil {
			token = decoded
		}
		if _, ok := seen[token]; ok {
			continue
		}
		seen[token] = struct{}{}
		out = append(out, token)
	}
	return out
}

func decodeC2Transform(raw string, transform string) ([]byte, bool) {
	raw = strings.TrimSpace(raw)
	switch transform {
	case "raw":
		return []byte(raw), true
	case "hex":
		cleaned := regexp.MustCompile(`(?i)[^0-9a-f]`).ReplaceAllString(raw, "")
		if len(cleaned) < 8 || len(cleaned)%2 != 0 {
			return nil, false
		}
		decoded, err := hex.DecodeString(cleaned)
		return decoded, err == nil
	case "base64":
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding} {
			if decoded, err := enc.DecodeString(raw); err == nil {
				return decoded, true
			}
		}
	case "base64url":
		for _, enc := range []*base64.Encoding{base64.URLEncoding, base64.RawURLEncoding} {
			if decoded, err := enc.DecodeString(raw); err == nil {
				return decoded, true
			}
		}
	case "netbios", "netbiosu":
		decoded, ok := decodeNetBIOSBytes(raw, transform == "netbiosu")
		return decoded, ok
	}
	return nil, false
}

func decryptVShellCandidates(ctx context.Context, req model.C2DecryptRequest, candidates []c2DecryptCandidate, result model.C2DecryptResult) model.C2DecryptResult {
	mode := strings.TrimSpace(req.VShell.Mode)
	if mode == "" {
		mode = "auto"
	}
	salt := strings.TrimSpace(req.VShell.Salt)
	if salt == "" {
		result.Notes = append(result.Notes, "VShell 解密需要 salt；vkey 仅用于验证明文，不作为默认 AES key。")
		return result
	}
	vkey := strings.TrimSpace(req.VShell.VKey)
	if len(candidates) > c2DecryptMaxRecords {
		result.Notes = append(result.Notes, fmt.Sprintf("VShell 候选阶段已优先保留 raw-stream 双向重组结果，结果阶段按高价值明文裁剪；当前候选 %d 条。", len(candidates)))
	}

	type vshellKeySet struct {
		label  string
		gcmKey []byte
		cbcKey []byte
	}
	keySets := make([]vshellKeySet, 0, 3)

	sum1 := md5.Sum([]byte(salt))
	keySets = append(keySets, vshellKeySet{
		label:  "md5(salt)",
		gcmKey: []byte(hex.EncodeToString(sum1[:])),
		cbcKey: sum1[:],
	})
	if vkey != "" {
		sum2 := md5.Sum([]byte(salt + vkey))
		keySets = append(keySets, vshellKeySet{
			label:  "md5(salt+vkey)",
			gcmKey: []byte(hex.EncodeToString(sum2[:])),
			cbcKey: sum2[:],
		})
		saltPad := make([]byte, 32)
		copy(saltPad, []byte(salt))
		sum3 := md5.Sum(append(saltPad, []byte(vkey)...))
		keySets = append(keySets, vshellKeySet{
			label:  "md5(saltPad32+vkey)",
			gcmKey: []byte(hex.EncodeToString(sum3[:])),
			cbcKey: sum3[:],
		})
	}

	records := make([]model.C2DecryptedRecord, 0, c2DecryptMaxRecords)
	for _, candidate := range candidates {
		if ctx.Err() != nil {
			break
		}
		frames := splitVShellFrames(candidate.raw)
		if len(frames) == 0 {
			frames = [][]byte{candidate.raw}
		}
		for _, frame := range frames {
			if ctx.Err() != nil {
				break
			}
			var record model.C2DecryptedRecord
			ok := false
			for _, ks := range keySets {
				record, ok = tryDecryptVShellFrame(candidate, frame, mode, ks.label, ks.gcmKey, ks.cbcKey, vkey)
				if ok {
					break
				}
			}
			if !ok {
				record = baseDecryptRecord(candidate, frame, "vshell-auto")
				record.Error = "VShell 解密失败：salt/mode 不匹配，或当前 frame 并非可解密负载"
			}
			records = append(records, record)
		}
	}
	if len(records) > c2DecryptMaxRecords {
		result.Records = append(result.Records, trimVShellDecryptRecords(records, c2DecryptMaxRecords)...)
		result.Notes = append(result.Notes, fmt.Sprintf("VShell 解密共生成 %d 条 frame 结果；后端已按可读明文、验证状态与取证关键词优先保留前 %d 条，避免低信息帧挤掉关键明文。", len(records), c2DecryptMaxRecords))
	} else {
		result.Records = append(result.Records, records...)
	}
	result.Notes = append(result.Notes, "VShell auto 会按 md5(salt)、md5(salt+vkey)、md5(saltPad32+vkey) 三种密钥派生分别尝试 AES-GCM 与 AES-CBC；不同版本存在实现差异，未验证 vkey 的明文需人工复核。")
	return result
}

type scoredVShellDecryptRecord struct {
	index  int
	score  int
	record model.C2DecryptedRecord
}

func trimVShellDecryptRecords(records []model.C2DecryptedRecord, limit int) []model.C2DecryptedRecord {
	if limit <= 0 {
		return nil
	}
	if len(records) <= limit {
		return records
	}
	scored := make([]scoredVShellDecryptRecord, 0, len(records))
	for index, record := range records {
		scored = append(scored, scoredVShellDecryptRecord{
			index:  index,
			score:  vshellDecryptRecordScore(record),
			record: record,
		})
	}
	sort.SliceStable(scored, func(i, j int) bool {
		if scored[i].score == scored[j].score {
			return scored[i].index < scored[j].index
		}
		return scored[i].score > scored[j].score
	})
	selected := append([]scoredVShellDecryptRecord(nil), scored[:limit]...)
	sort.SliceStable(selected, func(i, j int) bool {
		return selected[i].index < selected[j].index
	})
	out := make([]model.C2DecryptedRecord, 0, len(selected))
	for _, item := range selected {
		out = append(out, item.record)
	}
	return out
}

func vshellDecryptRecordScore(record model.C2DecryptedRecord) int {
	score := record.Confidence
	if record.Error != "" {
		score -= 1000
	} else if record.PlaintextPreview != "" {
		score += 200
	}
	switch record.KeyStatus {
	case c2DecryptKeyStatusOK:
		score += 160
	case c2DecryptKeyStatusWeak:
		score += 50
	}
	if len(record.Parsed) > 0 {
		score += 140
	}

	text := record.PlaintextPreview
	cleanText, ansiStripped := stripANSIC2ControlSequencesForScore(text)
	textScore := visibleC2TextScore(text)
	cleanTextScore := visibleC2TextScore(cleanText)
	if cleanTextScore < textScore {
		textScore = cleanTextScore
	}
	score += textScore
	if record.DecryptedLength > 12 {
		score += 20
	}
	if record.DecryptedLength >= 24 && record.DecryptedLength <= c2DecryptPreviewMaxBytes {
		score += 25
	}
	if record.DecryptedLength > c2DecryptPreviewMaxBytes {
		score -= 20
	}
	hasSignal := hasForensicC2TextSignal(cleanText)
	if isTimestampOnlyC2Text(cleanText) {
		score -= 260
	}
	if ansiStripped && !hasSignal && cleanTextScore < 30 {
		score -= 160
	}
	if record.DecryptedLength > 0 && record.DecryptedLength <= 24 && textScore < 20 && !hasSignal {
		score -= 180
	}

	searchable := strings.ToLower(text + " " + cleanText + " " + record.Algorithm + " " + strings.Join(record.Tags, " "))
	highValueTokens := []string{
		"hacked_by", "fallsnow", "paperplane", "verifykey", "whoami", "cmd.exe",
		"powershell", "/bin/", "c:\\", "{\"", "[\"", "\"cmd\"", "cmd:",
	}
	for _, token := range highValueTokens {
		if strings.Contains(searchable, token) {
			score += 180
		}
	}
	if strings.Contains(searchable, "hacked_by_fallsnow&paperplane") {
		score += 400
	}
	if strings.Contains(searchable, "raw-stream") {
		score += 20
	}
	return score
}

var (
	c2ScoreANSIRegexp     = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]`)
	c2ScoreFullTimeRegexp = regexp.MustCompile(`^\d{4}[-/]\d{2}[-/]\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?$`)
	c2ScoreClockRegexp    = regexp.MustCompile(`^\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?$`)
)

func stripANSIC2ControlSequencesForScore(text string) (string, bool) {
	stripped := c2ScoreANSIRegexp.ReplaceAllString(text, "")
	stripped = strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == '\t' {
			return r
		}
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, stripped)
	return strings.TrimSpace(stripped), stripped != text
}

func isTimestampOnlyC2Text(text string) bool {
	normalized := strings.TrimSpace(text)
	if normalized == "" {
		return false
	}
	if c2ScoreFullTimeRegexp.MatchString(normalized) || c2ScoreClockRegexp.MatchString(normalized) {
		return true
	}
	if len(normalized) == 10 || len(normalized) == 13 {
		for _, r := range normalized {
			if r < '0' || r > '9' {
				return false
			}
		}
		value, err := strconv.ParseInt(normalized, 10, 64)
		if err != nil {
			return false
		}
		if len(normalized) == 10 {
			value *= 1000
		}
		const minEpochMs int64 = 946684800000  // 2000-01-01
		const maxEpochMs int64 = 4102444800000 // 2100-01-01
		return value >= minEpochMs && value <= maxEpochMs
	}
	return false
}

func hasForensicC2TextSignal(text string) bool {
	normalized := strings.TrimSpace(strings.ToLower(text))
	if normalized == "" {
		return false
	}
	if strings.HasPrefix(normalized, "{") || strings.HasPrefix(normalized, "[") {
		return true
	}
	tokens := []string{
		"ok", "id", "cmd", "whoami", "powershell", "verifykey", "hacked_by",
		"fallsnow", "paperplane", "/bin/", "/etc/", "/home/", "/tmp/", "/usr/",
		"c:\\", "\\\\",
	}
	for _, token := range tokens {
		if strings.Contains(normalized, token) {
			return true
		}
	}
	if regexp.MustCompile(`\b\d+(?:\.\d+){1,3}\b`).MatchString(normalized) {
		return true
	}
	if regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`).MatchString(normalized) {
		return true
	}
	if regexp.MustCompile(`[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}`).MatchString(normalized) {
		return true
	}
	return regexp.MustCompile(`\b[a-z0-9-]+(?:\.[a-z0-9-]+)+\b`).MatchString(normalized)
}

func visibleC2TextScore(text string) int {
	if text == "" {
		return 0
	}
	visible := 0
	semantic := 0
	control := 0
	total := 0
	for _, r := range text {
		total++
		switch {
		case r == '\r' || r == '\n' || r == '\t':
			visible++
		case unicode.IsPrint(r) && !unicode.IsControl(r):
			visible++
			if unicode.IsLetter(r) || unicode.IsNumber(r) || unicode.IsPunct(r) || unicode.IsSymbol(r) {
				semantic++
			}
		case unicode.IsControl(r):
			control++
		}
	}
	if total == 0 {
		return 0
	}
	score := visible*2 + semantic*4 - control*8
	ratio := float64(visible) / float64(total)
	switch {
	case ratio >= 0.8:
		score += 40
	case ratio >= 0.5:
		score += 15
	case ratio < 0.3:
		score -= 45
	}
	if strings.TrimSpace(text) != "" {
		score += 15
	}
	return score
}

func tryDecryptVShellFrame(candidate c2DecryptCandidate, frame []byte, mode string, keyLabel string, gcmKey []byte, cbcKey []byte, vkey string) (model.C2DecryptedRecord, bool) {
	if mode == "auto" || mode == "aes_gcm_md5_salt" {
		if plaintext, err := decryptAESGCMFrame(gcmKey, frame); err == nil {
			record := buildDecryptedRecord(candidate, frame, plaintext, "vshell-aes-gcm-"+keyLabel, verifyVShellPlaintext(plaintext, vkey))
			record.Tags = append(record.Tags, "key:"+keyLabel)
			return record, true
		}
	}
	if mode == "auto" || mode == "aes_cbc_md5_salt" {
		if plaintext, err := decryptAESCBC(frame, cbcKey, cbcKey); err == nil {
			record := buildDecryptedRecord(candidate, frame, plaintext, "vshell-aes-cbc-"+keyLabel, verifyVShellPlaintext(plaintext, vkey))
			record.Tags = append(record.Tags, "key:"+keyLabel)
			return record, true
		}
	}
	return model.C2DecryptedRecord{}, false
}

func splitVShellFrames(raw []byte) [][]byte {
	if frames := splitVShellFramesEndian(raw, binary.LittleEndian); len(frames) > 0 {
		return frames
	}
	if frames := splitVShellFramesEndian(raw, binary.BigEndian); len(frames) > 0 {
		return frames
	}
	return [][]byte{raw}
}

func splitVShellFramesEndian(raw []byte, order binary.ByteOrder) [][]byte {
	frames := make([][]byte, 0, 4)
	remaining := raw
	for len(remaining) >= 4 {
		size := int(order.Uint32(remaining[:4]))
		if size <= 0 || size > len(remaining)-4 || size > 8*1024*1024 {
			break
		}
		frames = append(frames, remaining[4:4+size])
		remaining = remaining[4+size:]
	}
	return frames
}

func decryptAESGCMFrame(key []byte, frame []byte) ([]byte, error) {
	if len(frame) < 12+16 {
		return nil, errors.New("frame too short for aes-gcm")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := frame[:gcm.NonceSize()]
	return gcm.Open(nil, nonce, frame[gcm.NonceSize():], nil)
}

func decryptCSCandidates(ctx context.Context, req model.C2DecryptRequest, candidates []c2DecryptCandidate, result model.C2DecryptResult) model.C2DecryptResult {
	aesKey, hmacKey, notes := resolveCSKeys(req, candidates)
	result.Notes = append(result.Notes, notes...)
	if len(aesKey) == 0 {
		metadataCount := countCSMetadataCandidates(candidates)
		if metadataCount > 0 {
			result.Notes = append(result.Notes, fmt.Sprintf("已从 GET Cookie/URI 等位置提取 %d 条疑似 CS metadata 密文候选；metadata 需要 TeamServer RSA private key 才能恢复 Raw key/AES rand。", metadataCount))
		}
		result.Notes = append(result.Notes, "CS 解密需要 AES/HMAC、Raw key(AES rand) 或 TeamServer RSA private key；仅靠 PCAP 通常只能拿到 metadata 密文，无法直接算出 Raw key。")
		return result
	}
	transformMode := strings.TrimSpace(req.CS.TransformMode)
	if transformMode == "" {
		transformMode = "auto"
	}
	stats := c2CSDecryptStats{total: len(candidates)}
	for _, candidate := range candidates {
		if ctx.Err() != nil || len(result.Records) >= c2DecryptMaxRecords {
			break
		}
		if isCSMetadataCandidate(candidate) {
			stats.metadataSkipped++
			continue
		}
		if isCSHTTPFocusedCandidate(candidate) {
			stats.httpFocused++
		}
		record, outcome := tryDecryptCSBlob(candidate, candidate.raw, aesKey, hmacKey)
		if outcome == "hmac-verified" {
			stats.hmacVerified++
		} else if outcome == "decrypted-weak" {
			stats.decryptedWeak++
		} else if outcome == "hmac-rejected" {
			stats.hmacRejected++
		} else {
			stats.cryptoRejected++
		}
		ok := outcome == "hmac-verified" || outcome == "decrypted-weak"
		if ok {
			result.Records = append(result.Records, record)
			continue
		}
		decodedCandidates := decodeC2TransformCandidates(candidate.label, transformMode)
		if len(decodedCandidates) == 0 && utf8.Valid(candidate.raw) {
			decodedCandidates = decodeC2TransformCandidates(string(candidate.raw), transformMode)
		}
		if len(decodedCandidates) == 0 {
			record = baseDecryptRecord(candidate, candidate.raw, "cs-aes-cbc")
			record.Error = "CS 解密失败：key/transform 不匹配，或 payload 不是当前首版支持的 AES-CBC blob"
			result.Records = append(result.Records, record)
			continue
		}
		for _, transformed := range decodedCandidates {
			if len(result.Records) >= c2DecryptMaxRecords {
				break
			}
			record, outcome = tryDecryptCSBlob(candidate, transformed.raw, aesKey, hmacKey)
			if outcome == "hmac-verified" {
				stats.hmacVerified++
			} else if outcome == "decrypted-weak" {
				stats.decryptedWeak++
			} else if outcome == "hmac-rejected" {
				stats.hmacRejected++
			} else {
				stats.cryptoRejected++
			}
			ok = outcome == "hmac-verified" || outcome == "decrypted-weak"
			if !ok {
				record = baseDecryptRecord(candidate, transformed.raw, "cs-aes-cbc")
				record.Error = "CS 解密失败：HMAC 不匹配、key/transform 不匹配，或 payload 不是当前支持的 CS AES-CBC blob"
			}
			result.Records = append(result.Records, record)
		}
	}
	result.Notes = append(result.Notes, buildCSDecryptStatsNotes(stats)...)
	result.Notes = append(result.Notes, "CS 已按 keyed offline workbench 处理 HTTP POST / 200 response 负载；GET Cookie/URI metadata 默认只作为 Raw key 恢复输入，不当作任务/回传明文解密。")
	result.Notes = append(result.Notes, "Raw key 获取路径：PCAP 提供 RSA-encrypted metadata；TeamServer 的 .cobaltstrike.beacon_keys/RSA private key 解 metadata 后得到 Raw key，再按 SHA256(Raw key) 派生 AES/HMAC session keys。")
	result.Notes = append(result.Notes, "HTTPS 样本仍需先通过 TLS keylog/private key 让 HTTP payload 可见。")
	return result
}

func resolveCSKeys(req model.C2DecryptRequest, candidates []c2DecryptCandidate) ([]byte, []byte, []string) {
	notes := []string{}
	switch strings.TrimSpace(req.CS.KeyMode) {
	case "aes_hmac":
		aesKey := parseFlexibleKey(req.CS.AESKey)
		hmacKey := parseFlexibleKey(req.CS.HMACKey)
		if len(aesKey) > 0 && len(hmacKey) == 0 {
			notes = append(notes, "已使用 AES key；未提供 HMAC key，结果只能标记为 unverified，可能出现误解密噪声。")
		}
		return aesKey, hmacKey, notes
	case "aes_rand":
		aesRand := parseFlexibleKey(req.CS.AESRand)
		aesKey, hmacKey := deriveCSKeysFromAESRand(aesRand)
		return aesKey, hmacKey, append(notes, "已按 SHA256(Raw key/AES rand) 派生 AES/HMAC session keys；Raw key 通常来自 RSA private key 解 GET metadata，不是单靠 PCAP 直接提取。")
	case "rsa_private_key":
		privateKey, err := parseRSAPrivateKey(req.CS.RSAPrivateKey)
		if err != nil {
			return nil, nil, []string{"RSA private key 解析失败: " + err.Error()}
		}
		for _, candidate := range candidates {
			for _, transformed := range decodeC2TransformCandidates(string(candidate.raw), "auto") {
				if !isCSMetadataCandidate(candidate) {
					continue
				}
				plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, transformed.raw)
				if err != nil || len(plaintext) < 16 {
					continue
				}
				aesKey, hmacKey := deriveCSKeysFromAESRand(plaintext[:16])
				return aesKey, hmacKey, []string{"已从 RSA metadata 候选中恢复 AES rand 并派生 session keys。"}
			}
		}
		return nil, nil, []string{"RSA private key 可解析，但未从当前 GET Cookie/URI metadata 候选恢复 AES rand；请确认 profile transform、Cookie 位置或 beacon_keys 是否匹配该样本。"}
	default:
		return nil, nil, []string{"CS keyMode 需为 aes_hmac、aes_rand 或 rsa_private_key。"}
	}
}

func tryDecryptCSBlob(candidate c2DecryptCandidate, raw []byte, aesKey []byte, hmacKey []byte) (model.C2DecryptedRecord, string) {
	if len(aesKey) != 16 && len(aesKey) != 24 && len(aesKey) != 32 {
		return model.C2DecryptedRecord{}, "invalid-key"
	}
	if len(hmacKey) > 0 {
		for _, variant := range csEncryptedBlobVariants(raw) {
			if len(variant.mac) == 0 {
				continue
			}
			expected := hmac.New(sha256.New, hmacKey)
			expected.Write(variant.macBody)
			sum := expected.Sum(nil)
			if len(sum) < len(variant.mac) || !hmac.Equal(variant.mac, sum[:len(variant.mac)]) {
				continue
			}
			if record, ok := decryptCSAESBlob(candidate, variant.ciphertext, aesKey, c2DecryptKeyStatusOK); ok {
				record.RawLength = len(raw)
				record.Tags = append(record.Tags, "hmac-verified", variant.tag)
				return record, "hmac-verified"
			}
			return model.C2DecryptedRecord{}, "crypto-rejected"
		}
		return model.C2DecryptedRecord{}, "hmac-rejected"
	}
	for _, variant := range csEncryptedBlobVariants(raw) {
		if record, ok := decryptCSAESBlob(candidate, variant.ciphertext, aesKey, c2DecryptKeyStatusWeak); ok {
			record.RawLength = len(raw)
			record.Tags = append(record.Tags, variant.tag)
			return record, "decrypted-weak"
		}
	}
	return model.C2DecryptedRecord{}, "crypto-rejected"
}

type csEncryptedBlobVariant struct {
	ciphertext []byte
	macBody    []byte
	mac        []byte
	tag        string
}

func csEncryptedBlobVariants(raw []byte) []csEncryptedBlobVariant {
	out := make([]csEncryptedBlobVariant, 0, 4)
	add := func(ciphertext, macBody, mac []byte, tag string) {
		if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
			return
		}
		out = append(out, csEncryptedBlobVariant{
			ciphertext: ciphertext,
			macBody:    macBody,
			mac:        mac,
			tag:        tag,
		})
	}
	if len(raw) > 16 {
		body := raw[:len(raw)-16]
		add(body, body, raw[len(raw)-16:], "cs-hmac-sha256-16")
		if len(body) >= 4 {
			size := int(binary.BigEndian.Uint32(body[:4]))
			if size > 0 && size == len(body)-4 {
				add(body[4:], body, raw[len(raw)-16:], "cs-length-prefix-hmac-sha256-16")
			}
		}
	}
	if len(raw) > 32 {
		body := raw[:len(raw)-32]
		add(body, body, raw[len(raw)-32:], "cs-hmac-sha256-32")
		if len(body) >= 4 {
			size := int(binary.BigEndian.Uint32(body[:4]))
			if size > 0 && size == len(body)-4 {
				add(body[4:], body, raw[len(raw)-32:], "cs-length-prefix-hmac-sha256-32")
			}
		}
	}
	add(raw, nil, nil, "cs-raw-ciphertext")
	if len(raw) >= 4 {
		size := int(binary.BigEndian.Uint32(raw[:4]))
		if size > 0 && size == len(raw)-4 {
			add(raw[4:], nil, nil, "cs-length-prefix")
		}
	}
	return out
}

func decryptCSAESBlob(candidate c2DecryptCandidate, blob []byte, aesKey []byte, keyStatus string) (model.C2DecryptedRecord, bool) {
	ivs := [][]byte{
		[]byte("abcdefghijklmnop"),
		make([]byte, aes.BlockSize),
	}
	if len(blob)%aes.BlockSize == 0 && keyStatus == c2DecryptKeyStatusOK {
		for _, iv := range ivs {
			if plaintext, err := decryptAESCBC(blob, aesKey, iv); err == nil {
				return buildDecryptedRecord(candidate, blob, plaintext, "cs-aes-cbc", keyStatus), true
			}
		}
	}
	if len(blob) > aes.BlockSize && (len(blob)-aes.BlockSize)%aes.BlockSize == 0 {
		if plaintext, err := decryptAESCBC(blob[aes.BlockSize:], aesKey, blob[:aes.BlockSize]); err == nil {
			return buildDecryptedRecord(candidate, blob, plaintext, "cs-aes-cbc", keyStatus), true
		}
	}
	if len(blob)%aes.BlockSize != 0 {
		return model.C2DecryptedRecord{}, false
	}
	for _, iv := range ivs {
		if plaintext, err := decryptAESCBC(blob, aesKey, iv); err == nil {
			return buildDecryptedRecord(candidate, blob, plaintext, "cs-aes-cbc", keyStatus), true
		}
	}
	return model.C2DecryptedRecord{}, false
}

func deriveCSKeysFromAESRand(aesRand []byte) ([]byte, []byte) {
	if len(aesRand) == 0 {
		return nil, nil
	}
	sum := sha256.Sum256(aesRand)
	return sum[:16], sum[16:]
}

func isCSMetadataCandidate(candidate c2DecryptCandidate) bool {
	return strings.HasPrefix(candidate.transform, "cs-metadata-")
}

func isCSHTTPFocusedCandidate(candidate c2DecryptCandidate) bool {
	return strings.HasPrefix(candidate.transform, "cs-http-")
}

func countCSMetadataCandidates(candidates []c2DecryptCandidate) int {
	count := 0
	for _, candidate := range candidates {
		if isCSMetadataCandidate(candidate) {
			count++
		}
	}
	return count
}

func buildCSDecryptStatsNotes(stats c2CSDecryptStats) []string {
	notes := []string{}
	if stats.total > 0 {
		notes = append(notes, fmt.Sprintf("CS 候选收敛：总候选 %d，HTTP POST/200 解密候选 %d，metadata 候选跳过 %d。", stats.total, stats.httpFocused, stats.metadataSkipped))
	}
	if stats.hmacVerified > 0 {
		notes = append(notes, fmt.Sprintf("HMAC 校验通过 %d 条；这些记录标记为 verified。", stats.hmacVerified))
	}
	if stats.decryptedWeak > 0 {
		notes = append(notes, fmt.Sprintf("无 HMAC 校验但 AES-CBC 可解 %d 条；这些记录标记为 unverified，需要人工复核。", stats.decryptedWeak))
	}
	if stats.hmacRejected > 0 {
		notes = append(notes, fmt.Sprintf("HMAC 不匹配 %d 次；通常表示 Raw key/HMAC key 不对应、心跳/metadata 混入、或 profile transform 未正确还原。", stats.hmacRejected))
	}
	return notes
}

func buildDecryptedRecord(candidate c2DecryptCandidate, raw []byte, plaintext []byte, algorithm string, keyStatus string) model.C2DecryptedRecord {
	parsed := map[string]any(nil)
	trimmed := bytes.TrimSpace(plaintext)
	if len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') {
		var value any
		if json.Unmarshal(trimmed, &value) == nil {
			if asMap, ok := value.(map[string]any); ok {
				parsed = asMap
			} else {
				parsed = map[string]any{"value": value}
			}
		}
	}
	confidence := 55
	if parsed != nil || utf8.Valid(plaintext) && printableRatio(string(plaintext)) > 0.75 {
		confidence = 72
	}
	if keyStatus == c2DecryptKeyStatusOK {
		confidence = 90
	}
	preview, tags := previewCSPlaintext(candidate, plaintext)
	return model.C2DecryptedRecord{
		PacketID:         candidate.packet.ID,
		StreamID:         candidate.packet.StreamID,
		Time:             candidate.packet.Timestamp,
		Direction:        directionFromCandidate(candidate, raw),
		Algorithm:        algorithm,
		KeyStatus:        keyStatus,
		Confidence:       confidence,
		PlaintextPreview: preview,
		Parsed:           parsed,
		RawLength:        len(raw),
		DecryptedLength:  len(plaintext),
		Tags:             append([]string{candidate.transform}, tags...),
	}
}

func previewCSPlaintext(candidate c2DecryptCandidate, plaintext []byte) (string, []string) {
	if !strings.HasPrefix(candidate.transform, "cs-") {
		return previewC2Plaintext(plaintext), nil
	}
	if preview, tags := previewCSStructuredPayload(plaintext); preview != "" {
		return preview, tags
	}
	return previewC2Plaintext(plaintext), []string{"cs-binary-plaintext"}
}

func previewCSStructuredPayload(raw []byte) (string, []string) {
	if len(raw) == 0 {
		return "", nil
	}
	var parts []string
	tags := []string{"cs-structured-preview"}
	if len(raw) >= 4 {
		value := binary.BigEndian.Uint32(raw[:4])
		if value > 0 && value <= uint32(len(raw)-4) {
			parts = append(parts, fmt.Sprintf("beacon_length=%d", value))
			tags = append(tags, "cs-length-prefix")
		} else {
			parts = append(parts, fmt.Sprintf("beacon_prefix=0x%08x", value))
		}
	}
	textFragments := extractPrintableASCIIFragments(raw, 4)
	if len(textFragments) > 0 {
		tags = append(tags, "cs-ascii-fragments")
		if len(textFragments) > 6 {
			textFragments = textFragments[:6]
		}
		parts = append(parts, "ascii="+strings.Join(textFragments, " | "))
	}
	if len(parts) == 0 {
		return "", nil
	}
	if len(raw) > 0 {
		parts = append(parts, fmt.Sprintf("raw_hex_prefix=%s", hex.EncodeToString(raw[:minInt(len(raw), 48)])))
	}
	return strings.Join(parts, "\n"), tags
}

func extractPrintableASCIIFragments(raw []byte, minLen int) []string {
	out := []string{}
	start := -1
	for i, b := range raw {
		if b >= 0x20 && b <= 0x7e {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 && i-start >= minLen {
			out = append(out, string(raw[start:i]))
		}
		start = -1
	}
	if start >= 0 && len(raw)-start >= minLen {
		out = append(out, string(raw[start:]))
	}
	return out
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func baseDecryptRecord(candidate c2DecryptCandidate, raw []byte, algorithm string) model.C2DecryptedRecord {
	return model.C2DecryptedRecord{
		PacketID:   candidate.packet.ID,
		StreamID:   candidate.packet.StreamID,
		Time:       candidate.packet.Timestamp,
		Direction:  directionFromCandidate(candidate, raw),
		Algorithm:  algorithm,
		KeyStatus:  c2DecryptKeyStatusNA,
		Confidence: 0,
		RawLength:  len(raw),
		Tags:       []string{candidate.transform},
	}
}

func verifyVShellPlaintext(plaintext []byte, vkey string) string {
	if strings.TrimSpace(vkey) == "" {
		return c2DecryptKeyStatusWeak
	}
	text := strings.ToLower(string(plaintext))
	vkey = strings.TrimSpace(vkey)
	hash := md5.Sum([]byte(vkey))
	if strings.Contains(text, "verifykey") || strings.Contains(text, strings.ToLower(vkey)) || strings.Contains(text, hex.EncodeToString(hash[:])) {
		return c2DecryptKeyStatusOK
	}
	return c2DecryptKeyStatusWeak
}

func directionFromCandidate(candidate c2DecryptCandidate, raw []byte) string {
	if candidate.direction != "" {
		return candidate.direction
	}
	return directionFromPacket(candidate.packet, raw)
}

func directionFromPacket(packet model.Packet, raw []byte) string {
	if len(raw) >= 12 {
		if raw[0] >= 0x80 {
			return "server_to_client"
		}
		return "client_to_server"
	}
	return c2DecryptDirectionUnknown
}

func parseFlexibleKey(raw string) []byte {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	cleanedHex := regexp.MustCompile(`(?i)[^0-9a-f]`).ReplaceAllString(raw, "")
	if len(cleanedHex) >= 16 && len(cleanedHex)%2 == 0 {
		if decoded, err := hex.DecodeString(cleanedHex); err == nil {
			return decoded
		}
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if decoded, err := enc.DecodeString(raw); err == nil {
			return decoded
		}
	}
	return []byte(raw)
}

func parseRSAPrivateKey(raw string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(raw)))
	if block == nil {
		return nil, errors.New("missing PEM block")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("PEM is not RSA private key")
	}
	return key, nil
}

func decodeNetBIOSBytes(raw string, upper bool) ([]byte, bool) {
	raw = strings.TrimSpace(raw)
	if len(raw)%2 != 0 || len(raw) < 2 {
		return nil, false
	}
	out := make([]byte, 0, len(raw)/2)
	base := byte('a')
	if upper {
		base = 'A'
	}
	for i := 0; i < len(raw); i += 2 {
		hi := raw[i] - base
		lo := raw[i+1] - base
		if hi > 15 || lo > 15 {
			return nil, false
		}
		out = append(out, hi<<4|lo)
	}
	return out, true
}

func httpBody(raw string) string {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	if idx := strings.Index(raw, "\n\n"); idx >= 0 && idx+2 < len(raw) {
		return raw[idx+2:]
	}
	return ""
}

func httpPayloadValues(raw string) []string {
	out := []string{}
	body := httpBody(raw)
	if body != "" {
		out = append(out, body)
		if values, err := url.ParseQuery(body); err == nil {
			for _, list := range values {
				out = append(out, list...)
			}
		}
	}
	firstLine := strings.SplitN(strings.ReplaceAll(raw, "\r\n", "\n"), "\n", 2)[0]
	fields := strings.Fields(firstLine)
	if len(fields) >= 2 {
		if parsed, err := url.Parse(fields[1]); err == nil {
			for _, list := range parsed.Query() {
				out = append(out, list...)
			}
		}
	}
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "cookie:") || strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "authorization:") {
			out = append(out, strings.TrimSpace(strings.SplitN(line, ":", 2)[1]))
		}
	}
	return out
}

func previewC2Plaintext(raw []byte) string {
	if len(raw) > c2DecryptPreviewMaxBytes {
		raw = raw[:c2DecryptPreviewMaxBytes]
	}
	if utf8.Valid(raw) {
		return string(raw)
	}
	return hex.EncodeToString(raw)
}

func printableRatio(raw string) float64 {
	if raw == "" {
		return 0
	}
	printable := 0
	total := 0
	for _, r := range raw {
		total++
		if r == '\n' || r == '\r' || r == '\t' || unicode.IsPrint(r) {
			printable++
		}
	}
	if total == 0 {
		return 0
	}
	return float64(printable) / float64(total)
}

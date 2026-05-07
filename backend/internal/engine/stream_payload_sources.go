package engine

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gshark/sentinel/backend/internal/model"
)

var (
	suspiciousWebshellURIPattern   = regexp.MustCompile(`(?i)(\.php\b|\.jsp\b|\.jspx\b|\.aspx\b|\.ashx\b|shell|cmd|upload|exec|eval|assert)`)
	suspiciousWebshellValuePattern = regexp.MustCompile(`(?i)(eval\s*\(|assert\s*\(|base64_decode\s*\(|system\s*\(|exec\s*\(|chr\(\d+\)|rebeyond|behinder|godzilla|antsword)`)
	commandExecFunctionPattern     = regexp.MustCompile(`(?i)(system\s*\(|exec\s*\(|shell_exec\s*\(|passthru\s*\(|popen\s*\(|proc_open\s*\(|assert\s*\(|eval\s*\(|base64_decode\s*\(|Runtime\.getRuntime\s*\(|ProcessBuilder\s*\(|getInputStream\s*\(|WScript\.Shell|CreateObject\s*\(|ProcessStartInfo|cmd\.exe|powershell|whoami|ipconfig|ifconfig|net\s+user|uname\s+-a|/bin/sh|/bin/bash)`)
)

const (
	payloadSourceRepeatWindowSeconds        = 30
	payloadSourceStreamBodyFallbackLimit    = 64
	payloadSourceStreamBodyFallbackTimeout  = 2 * time.Second
	payloadSourceStreamBodyFallbackMinScore = 20
)

type payloadSourceHTTPMeta struct {
	method      string
	host        string
	uri         string
	contentType string
	raw         string
}

func (s *Service) ListStreamPayloadSources(limit int) ([]model.StreamPayloadSource, error) {
	if limit <= 0 {
		limit = 500
	}
	if limit > 500 {
		limit = 500
	}
	if s.packetStore == nil || s.packetStore.Count() == 0 {
		return []model.StreamPayloadSource{}, nil
	}

	type pendingPacket struct {
		packet model.Packet
		meta   payloadSourceHTTPMeta
	}

	collected := make([]model.StreamPayloadSource, 0, limit)
	seen := map[string]struct{}{}
	needsStreamBody := make([]pendingPacket, 0)

	err := s.packetStore.Iterate(nil, func(packet model.Packet) error {
		meta, ok := parsePayloadSourceHTTPMeta(packet)
		if !ok {
			return nil
		}
		s.collectPayloadSourcesFromMeta(packet, meta, &collected, seen)
		if !hasHTTPBody(meta.raw) && packet.StreamID >= 0 && shouldFetchPayloadSourceStreamBody(meta) {
			needsStreamBody = append(needsStreamBody, pendingPacket{packet, meta})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	if len(needsStreamBody) > 0 && !payloadSourcesHaveStrongWebshellHint(collected) {
		sort.SliceStable(needsStreamBody, func(i, j int) bool {
			leftRank := payloadSourceStreamBodyFetchRank(needsStreamBody[i].meta)
			rightRank := payloadSourceStreamBodyFetchRank(needsStreamBody[j].meta)
			if leftRank != rightRank {
				return leftRank > rightRank
			}
			return needsStreamBody[i].packet.ID < needsStreamBody[j].packet.ID
		})
		streamBodies := map[int64][]string{}
		for _, pp := range needsStreamBody {
			sid := pp.packet.StreamID
			if _, fetched := streamBodies[sid]; fetched {
				continue
			}
			if len(streamBodies) >= payloadSourceStreamBodyFallbackLimit {
				break
			}
			streamBodies[sid] = s.fetchStreamRequestBodies(sid)
		}
		for _, pp := range needsStreamBody {
			if bodies := streamBodies[pp.packet.StreamID]; len(bodies) > 0 {
				for _, body := range bodies {
					if strings.TrimSpace(body) == "" {
						continue
					}
					enriched := pp.meta
					enriched.raw = body
					s.collectPayloadSourcesFromMeta(pp.packet, enriched, &collected, seen)
				}
				if payloadSourcesHaveStrongWebshellHint(collected) {
					break
				}
			}
		}
	}

	enrichPayloadSourceRepeats(collected)
	out := make([]model.StreamPayloadSource, 0, len(collected))
	for _, source := range collected {
		if shouldKeepPayloadSource(source) {
			out = append(out, source)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		leftRank := payloadSourceRank(out[i])
		rightRank := payloadSourceRank(out[j])
		if leftRank != rightRank {
			return leftRank > rightRank
		}
		if out[i].Confidence != out[j].Confidence {
			return out[i].Confidence > out[j].Confidence
		}
		if out[i].OccurrenceCount != out[j].OccurrenceCount {
			return out[i].OccurrenceCount > out[j].OccurrenceCount
		}
		if out[i].PacketID != out[j].PacketID {
			return out[i].PacketID < out[j].PacketID
		}
		return out[i].ParamName < out[j].ParamName
	})
	if len(out) > limit {
		return out[:limit], nil
	}
	return out, nil
}

func (s *Service) collectPayloadSourcesFromMeta(packet model.Packet, meta payloadSourceHTTPMeta, collected *[]model.StreamPayloadSource, seen map[string]struct{}) {
	inspection := InspectStreamPayload(meta.raw)
	for _, candidate := range inspection.Candidates {
		if strings.TrimSpace(candidate.Value) == "" {
			continue
		}
		source := buildStreamPayloadSource(packet, meta, candidate)
		key := strings.Join([]string{
			fmt.Sprint(packet.ID),
			strings.ToUpper(source.Method),
			source.Host,
			source.URI,
			source.SourceType,
			source.ParamName,
			source.Payload,
		}, "|")
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		*collected = append(*collected, source)
	}
}

func hasHTTPBody(raw string) bool {
	if raw == "" {
		return false
	}
	if !looksLikeHTTPMessage(raw) {
		return true
	}
	return strings.Contains(raw, "\r\n\r\n") || strings.Contains(raw, "\n\n")
}

func shouldFetchPayloadSourceStreamBody(meta payloadSourceHTTPMeta) bool {
	return payloadSourceStreamBodyFetchRank(meta) >= payloadSourceStreamBodyFallbackMinScore
}

func payloadSourcesHaveStrongWebshellHint(sources []model.StreamPayloadSource) bool {
	for _, source := range sources {
		if source.FamilyHint == "antsword_like" || source.FamilyHint == "godzilla_like" || source.FamilyHint == "aes_webshell_like" {
			return true
		}
		if source.SourceRole == "script_or_command" {
			return true
		}
		if streamPayloadSourceHasDecoder(source, "behinder", "antsword", "godzilla") {
			return true
		}
		for _, signal := range source.Signals {
			switch signal {
			case "antsword_like", "godzilla_like", "aes_webshell_like", "command-exec-function", "script-keyword", "script-after-base64":
				return true
			}
		}
	}
	return false
}

func streamPayloadSourceHasDecoder(source model.StreamPayloadSource, decoders ...string) bool {
	for _, hint := range source.DecoderHints {
		for _, decoder := range decoders {
			if strings.EqualFold(strings.TrimSpace(hint), decoder) {
				return true
			}
		}
	}
	if source.DecoderOptionsHint == nil {
		return false
	}
	raw, ok := source.DecoderOptionsHint["decoder"].(string)
	if !ok {
		return false
	}
	for _, decoder := range decoders {
		if strings.EqualFold(strings.TrimSpace(raw), decoder) {
			return true
		}
	}
	return false
}

func payloadSourceStreamBodyFetchRank(meta payloadSourceHTTPMeta) int {
	method := strings.ToUpper(strings.TrimSpace(meta.method))
	switch method {
	case "POST", "PUT", "PATCH":
	default:
		return 0
	}

	score := 10
	if strings.TrimSpace(meta.contentType) != "" {
		score += 15
	}
	uri := strings.ToLower(meta.uri)
	if suspiciousWebshellURIPattern.MatchString(meta.uri) {
		score += 35
	}
	for _, needle := range []string{"upload", "pass", "cmd", "shell", "exec", "eval", "assert"} {
		if strings.Contains(uri, needle) {
			score += 10
		}
	}
	return score
}

func (s *Service) fetchStreamRequestBodies(streamID int64) []string {
	ctx, cancel := context.WithTimeout(context.Background(), payloadSourceStreamBodyFallbackTimeout)
	defer cancel()
	stream := s.HTTPStream(ctx, streamID)
	if len(stream.Chunks) == 0 && stream.Request == "" {
		return nil
	}
	bodies := make([]string, 0, 4)
	for _, chunk := range stream.Chunks {
		if !strings.EqualFold(chunk.Direction, "client") {
			continue
		}
		body := chunk.Body
		if looksLikeHTTPMessage(body) {
			if extracted := extractHTTPMessageBody(body); strings.TrimSpace(extracted) != "" && extracted != body {
				body = extracted
			}
		}
		if strings.TrimSpace(body) != "" {
			bodies = append(bodies, strings.TrimSpace(body))
		}
	}
	if len(bodies) == 0 && strings.TrimSpace(stream.Request) != "" {
		req := stream.Request
		if looksLikeHTTPMessage(req) {
			if extracted := extractHTTPMessageBody(req); strings.TrimSpace(extracted) != "" && extracted != req {
				req = extracted
			}
		}
		if strings.TrimSpace(req) != "" {
			bodies = append(bodies, strings.TrimSpace(req))
		}
	}
	return bodies
}

func parsePayloadSourceHTTPMeta(packet model.Packet) (payloadSourceHTTPMeta, bool) {
	raw := strings.TrimSpace(packet.Payload)
	info := strings.TrimSpace(packet.Info)
	protocol := strings.ToUpper(strings.TrimSpace(packet.Protocol + " " + packet.DisplayProtocol))
	if raw == "" && info == "" {
		return payloadSourceHTTPMeta{}, false
	}
	if !strings.Contains(protocol, "HTTP") && !looksLikeHTTPMessage(raw) && !looksLikeHTTPRequestLine(info) {
		return payloadSourceHTTPMeta{}, false
	}

	meta := payloadSourceHTTPMeta{raw: raw}
	if looksLikeHTTPMessage(raw) {
		lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
		if len(lines) > 0 {
			method, uri := parseHTTPRequestLine(lines[0])
			meta.method = method
			meta.uri = uri
		}
		meta.host = parseHTTPHeaderValue(lines, "host")
		meta.contentType = parseHTTPHeaderValue(lines, "content-type")
	}
	if meta.method == "" || meta.uri == "" {
		method, uri := parseHTTPRequestLine(info)
		if meta.method == "" {
			meta.method = method
		}
		if meta.uri == "" {
			meta.uri = uri
		}
	}
	if meta.method == "" || meta.uri == "" {
		return payloadSourceHTTPMeta{}, false
	}
	if meta.host == "" {
		meta.host = packet.DestIP
		if packet.DestPort > 0 {
			meta.host = fmt.Sprintf("%s:%d", meta.host, packet.DestPort)
		}
	}
	if meta.raw == "" {
		meta.raw = info
	}
	return meta, true
}

func parseHTTPHeaderValue(lines []string, headerName string) string {
	prefix := strings.ToLower(headerName) + ":"
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			return ""
		}
		if strings.HasPrefix(strings.ToLower(trimmed), prefix) {
			return strings.TrimSpace(trimmed[len(prefix):])
		}
	}
	return ""
}

func looksLikeHTTPRequestLine(line string) bool {
	method, uri := parseHTTPRequestLine(line)
	return method != "" && uri != ""
}

func parseHTTPRequestLine(line string) (string, string) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 2 {
		return "", ""
	}
	method := strings.ToUpper(fields[0])
	switch method {
	case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS":
	default:
		return "", ""
	}
	uri := fields[1]
	if parsed, err := url.Parse(uri); err == nil && parsed.RequestURI() != "" {
		uri = parsed.RequestURI()
	}
	return method, uri
}

func buildStreamPayloadSource(packet model.Packet, meta payloadSourceHTTPMeta, candidate model.StreamPayloadCandidate) model.StreamPayloadSource {
	signals := payloadSourceSignals(candidate, meta)
	confidence := candidate.Confidence
	if candidate.FamilyHint != "" {
		confidence += 16
		signals = append(signals, candidate.FamilyHint)
	}
	if candidate.SourceRole != "" {
		confidence += 8
		signals = append(signals, candidate.SourceRole)
	}
	if suspiciousWebshellURIPattern.MatchString(meta.uri) {
		confidence += 6
	}
	if candidate.ParamName != "" && webshellParamPattern.MatchString(candidate.ParamName) {
		confidence += 12
	}
	if suspiciousWebshellValuePattern.MatchString(candidate.Value) {
		confidence += 16
	}
	ruleReasons := make([]string, 0, 4)
	if payloadContainsCommandExecFunction(candidate.Value) {
		confidence += 35
		signals = append(signals, "command-exec-function")
		ruleReasons = append(ruleReasons, "payload 中存在明显命令执行函数或命令关键字")
	}
	if confidence > 100 {
		confidence = 100
	}
	if confidence < 0 {
		confidence = 0
	}
	return model.StreamPayloadSource{
		ID:                 fmt.Sprintf("pkt-%d-%s-%s", packet.ID, candidate.Kind, sanitizePayloadSourceID(candidate.ParamName)),
		Method:             meta.method,
		Host:               meta.host,
		URI:                meta.uri,
		PacketID:           packet.ID,
		StreamID:           packet.StreamID,
		SourceType:         candidate.Kind,
		ParamName:          candidate.ParamName,
		Payload:            candidate.Value,
		Preview:            previewPayload(candidate.Value),
		Confidence:         confidence,
		Signals:            uniquePayloadSourceStrings(signals),
		DecoderHints:       append([]string(nil), candidate.DecoderHints...),
		FamilyHint:         candidate.FamilyHint,
		DecoderOptionsHint: cloneDecoderOptionsHint(candidate.DecoderOptionsHint),
		SourceRole:         candidate.SourceRole,
		ContentType:        meta.contentType,
		OccurrenceCount:    1,
		FirstTime:          packet.Timestamp,
		LastTime:           packet.Timestamp,
		RelatedPackets:     []int64{packet.ID},
		RuleReasons:        uniquePayloadSourceStrings(ruleReasons),
	}
}

func payloadSourceSignals(candidate model.StreamPayloadCandidate, meta payloadSourceHTTPMeta) []string {
	signals := make([]string, 0, 8)
	if suspiciousWebshellURIPattern.MatchString(meta.uri) {
		signals = append(signals, "suspicious-uri")
	}
	if candidate.ParamName != "" && webshellParamPattern.MatchString(candidate.ParamName) {
		signals = append(signals, "suspicious-param")
	}
	if suspiciousWebshellValuePattern.MatchString(candidate.Value) {
		signals = append(signals, "script-keyword")
	}
	if payloadContainsCommandExecFunction(candidate.Value) {
		signals = append(signals, "command-exec-function")
	}
	if candidate.FamilyHint != "" {
		signals = append(signals, candidate.FamilyHint)
	}
	if candidate.SourceRole != "" {
		signals = append(signals, candidate.SourceRole)
	}
	signals = append(signals, candidate.Fingerprints...)
	if candidate.Kind == "query" || candidate.Kind == "form" || candidate.Kind == "multipart" || candidate.Kind == "json" {
		signals = append(signals, "structured-http-field")
	}
	return uniquePayloadSourceStrings(signals)
}

func enrichPayloadSourceRepeats(sources []model.StreamPayloadSource) {
	if len(sources) == 0 {
		return
	}
	groups := map[string][]int{}
	for idx, source := range sources {
		for _, key := range payloadSourceRepeatKeys(source) {
			if key == "" {
				continue
			}
			groups[key] = append(groups[key], idx)
		}
	}
	for _, idxs := range groups {
		if len(idxs) < 3 {
			continue
		}
		for _, idx := range idxs {
			count, first, last, packets := payloadSourceBurstStats(sources, idxs, idx)
			if count < 3 || count <= sources[idx].OccurrenceCount {
				continue
			}
			sources[idx].OccurrenceCount = count
			sources[idx].FirstTime = first
			sources[idx].LastTime = last
			sources[idx].RepeatWindowSeconds = payloadSourceRepeatWindowSeconds
			sources[idx].RelatedPackets = packets
			sources[idx].Signals = uniquePayloadSourceStrings(append(sources[idx].Signals, "repeat-burst"))
			sources[idx].RuleReasons = uniquePayloadSourceStrings(append(sources[idx].RuleReasons, fmt.Sprintf("%d 秒内重复出现 %d 次", payloadSourceRepeatWindowSeconds, count)))
			if count >= 5 {
				sources[idx].Confidence += 30
			} else {
				sources[idx].Confidence += 20
			}
			if sources[idx].Confidence > 100 {
				sources[idx].Confidence = 100
			}
		}
	}
}

func payloadSourceRepeatKeys(source model.StreamPayloadSource) []string {
	parsed, _ := url.Parse(source.URI)
	path := strings.ToLower(strings.TrimSpace(parsed.Path))
	if path == "" {
		path = strings.ToLower(strings.TrimSpace(source.URI))
	}
	endpointKey := strings.Join([]string{
		"endpoint",
		strings.ToUpper(strings.TrimSpace(source.Method)),
		strings.ToLower(strings.TrimSpace(source.Host)),
		path,
		strings.ToLower(strings.TrimSpace(source.ParamName)),
	}, "|")
	hash := sha1.Sum([]byte(source.Payload))
	payloadKey := "payload|" + hex.EncodeToString(hash[:])
	if len(strings.TrimSpace(source.Payload)) < 8 {
		return []string{endpointKey}
	}
	return []string{endpointKey, payloadKey}
}

func payloadSourceBurstStats(sources []model.StreamPayloadSource, idxs []int, center int) (int, string, string, []int64) {
	centerTime, ok := parsePayloadSourceTime(sources[center].FirstTime)
	if !ok {
		packets := make([]int64, 0, len(idxs))
		first := ""
		last := ""
		for _, idx := range idxs {
			packets = append(packets, sources[idx].PacketID)
			if first == "" || sources[idx].FirstTime < first {
				first = sources[idx].FirstTime
			}
			if sources[idx].FirstTime > last {
				last = sources[idx].FirstTime
			}
		}
		sort.Slice(packets, func(i, j int) bool { return packets[i] < packets[j] })
		return len(idxs), first, last, uniquePayloadPacketIDs(packets)
	}
	window := time.Duration(payloadSourceRepeatWindowSeconds) * time.Second
	count := 0
	packets := make([]int64, 0, len(idxs))
	firstTime := centerTime
	lastTime := centerTime
	firstLabel := sources[center].FirstTime
	lastLabel := sources[center].FirstTime
	for _, idx := range idxs {
		ts, ok := parsePayloadSourceTime(sources[idx].FirstTime)
		if !ok {
			continue
		}
		delta := ts.Sub(centerTime)
		if delta < 0 {
			delta = -delta
		}
		if delta > window {
			continue
		}
		count++
		packets = append(packets, sources[idx].PacketID)
		if ts.Before(firstTime) {
			firstTime = ts
			firstLabel = sources[idx].FirstTime
		}
		if ts.After(lastTime) {
			lastTime = ts
			lastLabel = sources[idx].FirstTime
		}
	}
	sort.Slice(packets, func(i, j int) bool { return packets[i] < packets[j] })
	return count, firstLabel, lastLabel, uniquePayloadPacketIDs(packets)
}

func parsePayloadSourceTime(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05.999999",
		"2006-01-02 15:04:05",
		"15:04:05.999999999",
		"15:04:05.999999",
		"15:04:05",
	}
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, raw); err == nil {
			return parsed, true
		}
	}
	return time.Time{}, false
}

func payloadContainsCommandExecFunction(raw string) bool {
	for _, variant := range payloadTextVariants(raw) {
		if commandExecFunctionPattern.MatchString(variant) {
			return true
		}
	}
	return false
}

func payloadTextVariants(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	variants := []string{raw}
	if decoded, err := url.QueryUnescape(raw); err == nil && decoded != raw {
		variants = append(variants, decoded)
		raw = decoded
	}
	cleaned := strings.TrimSpace(raw)
	base64Candidates := []string{cleaned, strings.NewReplacer("-", "+", "_", "/").Replace(cleaned)}
	for _, candidate := range base64Candidates {
		for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			if data, err := encoding.DecodeString(candidate); err == nil && utf8.Valid(data) {
				variants = append(variants, string(data))
			}
		}
	}
	hexCandidate := regexp.MustCompile(`(?i)[^0-9a-f]`).ReplaceAllString(cleaned, "")
	if len(hexCandidate) >= 8 && len(hexCandidate)%2 == 0 {
		if data, err := hex.DecodeString(hexCandidate); err == nil && utf8.Valid(data) {
			variants = append(variants, string(data))
		}
	}
	return uniquePayloadSourceStrings(variants)
}

func shouldKeepPayloadSource(source model.StreamPayloadSource) bool {
	signals := map[string]bool{}
	for _, signal := range source.Signals {
		signals[signal] = true
	}
	if source.FamilyHint != "" || source.SourceRole != "" {
		return true
	}
	if signals["antsword_like"] || signals["godzilla_like"] || signals["aes_webshell_like"] || signals["encrypted_blob"] || signals["script_or_command"] {
		return true
	}
	if signals["command-exec-function"] || signals["repeat-burst"] {
		return true
	}
	if signals["script-keyword"] || signals["script-after-base64"] || signals["base64-aes-block"] || signals["chr-chain"] || signals["hex-block-cipher"] {
		return true
	}
	if source.Confidence >= 45 && (signals["suspicious-param"] || signals["structured-http-field"]) && hasSuspiciousPayloadSourceSignal(source.Signals) {
		return true
	}
	if source.Confidence >= 60 && signals["suspicious-uri"] && hasSuspiciousPayloadSourceSignal(source.Signals) {
		return true
	}
	return false
}

func payloadSourceRank(source model.StreamPayloadSource) int {
	rank := 0
	switch source.FamilyHint {
	case "antsword_like", "godzilla_like":
		rank += 60
	case "aes_webshell_like", "hex_cipher":
		rank += 35
	}
	switch source.SourceRole {
	case "script_or_command":
		rank += 40
	case "encrypted_blob":
		rank += 30
	}
	for _, signal := range source.Signals {
		switch signal {
		case "command-exec-function":
			rank += 35
		case "script-after-base64", "chr-chain":
			rank += 30
		case "godzilla-random-param", "numeric-webshell-param":
			rank += 25
		case "base64-aes-block", "hex-block-cipher":
			rank += 18
		case "repeat-burst":
			rank += 12
		}
	}
	return rank
}

func uniquePayloadPacketIDs(values []int64) []int64 {
	out := make([]int64, 0, len(values))
	seen := map[int64]struct{}{}
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func sanitizePayloadSourceID(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "payload"
	}
	replacer := strings.NewReplacer("/", "-", "\\", "-", " ", "-", ".", "-", "[", "-", "]", "-", ":", "-")
	return replacer.Replace(raw)
}

func uniquePayloadSourceStrings(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	return out
}

func hasSuspiciousPayloadSourceSignal(signals []string) bool {
	for _, signal := range signals {
		switch signal {
		case "suspicious-uri", "suspicious-param", "script-keyword", "script-after-base64", "base64-aes-block", "chr-chain", "hex-block-cipher", "command-exec-function", "repeat-burst", "antsword_like", "godzilla_like", "aes_webshell_like", "encrypted_blob", "script_or_command":
			return true
		}
	}
	return false
}

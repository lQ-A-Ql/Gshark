package engine

import (
	"context"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

var (
	c2VShellArchRE        = regexp.MustCompile(`(?i)\b[wl]64\b`)
	c2DNSNameLikeRE       = regexp.MustCompile(`(?i)(?:query|qry|standard query|response)\s+(?:0x[0-9a-f]+\s+)?(?:A|AAAA|TXT|CNAME|NULL|MX|NS)?\s*([a-z0-9][a-z0-9._-]+\.[a-z]{2,})`)
	c2HTTPHeaderUserAgent = regexp.MustCompile(`(?i)^User-Agent$`)
)

type c2AnalysisBuilder struct {
	result               model.C2SampleAnalysis
	csIndicators         map[string]int
	csChannels           map[string]int
	vshellIndicators     map[string]int
	vshellChannels       map[string]int
	families             map[string]int
	conversations        map[string]int
	csConversations      map[string]int
	vshellConversations  map[string]int
	csRelatedActors      map[string]int
	vshellRelatedActors  map[string]int
	csDeliveryChains     map[string]int
	vshellDeliveryChains map[string]int
	streams              map[string][]model.Packet
	httpObservations     []c2HTTPObservation
	dnsObservations      []c2DNSObservation
	vshellStreamData     map[int64]*c2VShellStreamWork
	emittedCSHTTPPackets map[int64]struct{}
}

type c2HTTPObservation struct {
	packet     model.Packet
	method     string
	path       string
	host       string
	channel    string
	userAgent  string
	evidence   string
	confidence int
	tags       []string
}

type c2DNSObservation struct {
	packet      model.Packet
	qname       string
	maxLabel    int
	queryType   string
	isTXT       bool
	isNull      bool
	isCNAME     bool
	isResponse  bool
	confidence  int
	tags        []string
}

type c2VShellStreamWork struct {
	streamID     int64
	protocol     string
	packets      []model.Packet
	archMarkers  map[string]int
	lengthPrefix int
	shortPackets int
	longPackets  int
	transitions  int
	lastKind     string
	heartbeatAvg string
	heartbeatJit string
	hasWebSocket bool
	wsParams     string
	listenerHints map[string]int
	confidence   int
}

func buildC2SampleAnalysisFromPackets(ctx context.Context, packets []model.Packet) (model.C2SampleAnalysis, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	builder := &c2AnalysisBuilder{
		result:               emptyC2SampleAnalysis(),
		csIndicators:         map[string]int{},
		csChannels:           map[string]int{},
		vshellIndicators:     map[string]int{},
		vshellChannels:       map[string]int{},
		families:             map[string]int{},
		conversations:        map[string]int{},
		csConversations:      map[string]int{},
		vshellConversations:  map[string]int{},
		csRelatedActors:      map[string]int{},
		vshellRelatedActors:  map[string]int{},
		csDeliveryChains:     map[string]int{},
		vshellDeliveryChains: map[string]int{},
		streams:              map[string][]model.Packet{},
		httpObservations:     []c2HTTPObservation{},
		dnsObservations:      []c2DNSObservation{},
		vshellStreamData:     map[int64]*c2VShellStreamWork{},
		emittedCSHTTPPackets: map[int64]struct{}{},
	}

	for _, packet := range packets {
		if err := ctx.Err(); err != nil {
			return model.C2SampleAnalysis{}, err
		}
		if packet.StreamID != 0 {
			key := fmt.Sprintf("%s:%d", strings.ToUpper(packet.Protocol), packet.StreamID)
			builder.streams[key] = append(builder.streams[key], packet)
		}
		builder.inspectPacket(packet)
	}

	builder.inspectStreamPatterns(ctx)
	builder.finish()
	return builder.result, nil
}

func (b *c2AnalysisBuilder) inspectPacket(packet model.Packet) {
	protocol := strings.ToUpper(strings.TrimSpace(c2FirstNonEmpty(packet.DisplayProtocol, packet.Protocol)))
	payloadText := decodeHTTPPayloadText(packet.Payload)
	infoText := strings.TrimSpace(packet.Info)
	joined := strings.TrimSpace(infoText + "\n" + payloadText)

	if isHTTPLikePacket(packet) {
		b.inspectHTTPPacket(packet, payloadText)
	}
	if strings.Contains(protocol, "DNS") || strings.Contains(strings.ToUpper(infoText), " DNS ") || packet.DestPort == 53 || packet.SourcePort == 53 {
		b.inspectDNSPacket(packet, joined)
	}
	if packet.Color.HasSMB || strings.Contains(protocol, "SMB") || strings.Contains(strings.ToUpper(infoText), "SMB") {
		b.addCSCandidate(packet, "smb", "smb-pivot-placeholder", "SMB / named pipe pivot 候选", 42,
			"识别到 SMB 相关包，已作为 Cobalt Strike SMB beacon chaining / 横向 pivot 的占位证据。"+c2FirstNonEmpty(" "+infoText, ""),
			[]string{"smb", "pivot-like", "weak-signal"}, nil)
	}
	if strings.Contains(protocol, "TCP") || packet.SourcePort > 0 || packet.DestPort > 0 {
		b.inspectVShellTCPPacket(packet, payloadText)
	}
}

func (b *c2AnalysisBuilder) inspectHTTPPacket(packet model.Packet, payloadText string) {
	method := httpLoginMethod(packet)
	path := httpRequestPath(packet, payloadText)
	headers := extractHTTPHeaders(payloadText)
	host := strings.TrimSpace(headers["Host"])
	userAgent := strings.TrimSpace(headerValueCI(headers, "User-Agent"))
	headerHints := []string{}
	if userAgent != "" {
		headerHints = append(headerHints, "ua="+truncateC2(userAgent, 80))
	}
	if host != "" {
		headerHints = append(headerHints, "host="+host)
	}
	if method != "" {
		channel := httpChannel(packet)
		obs := c2HTTPObservation{
			packet:     packet,
			method:     strings.ToUpper(method),
			path:       path,
			host:       host,
			channel:    channel,
			userAgent:  userAgent,
			evidence:   strings.Join(headerHints, "; "),
			confidence: 30,
			tags:       []string{"http", "malleable-profile-weak", "needs-correlation"},
		}
		b.httpObservations = append(b.httpObservations, obs)
		if ok, confidence, tags := strongCSHTTPStaticSignal(obs); ok {
			b.emitCSHTTPCandidate(obs, confidence,
				"HTTP/HTTPS Beacon 静态强线索候选：仅因 URI/Header 命中不会直接定性，仍需结合 Host/URI 聚合与周期性复核。 "+obs.evidence,
				tags)
		}
	}

	if path != "" {
		b.inspectVShellWebSocket(packet, method, path, host)
	}
}

func (b *c2AnalysisBuilder) inspectVShellWebSocket(packet model.Packet, method, path, host string) {
	lowerPath := strings.ToLower(path)
	parsed, _ := url.Parse(path)
	query := parsed.Query()
	arch := query.Get("a")
	transport := query.Get("t")
	listenerPort := query.Get("p")
	serverHost := c2FirstNonEmpty(query.Get("h"), host)
	hasVShellParams := c2VShellArchRE.MatchString(arch) && strings.Contains(strings.ToLower(transport), "ws")
	hasWSPath := strings.Contains(lowerPath, "/ws") || strings.Contains(lowerPath, "t=ws_")
	defaultishPort := packet.DestPort == 8084 || packet.SourcePort == 8084 || packet.DestPort == 8088 || packet.SourcePort == 8088
	if !hasVShellParams && !hasWSPath && !defaultishPort {
		return
	}

	confidence := 46
	tags := []string{"websocket", "listener"}
	if hasVShellParams {
		confidence = 82
		tags = append(tags, "arch-param", "ws-param")
	}
	if defaultishPort {
		confidence += 4
		tags = append(tags, "listener-port-observed")
	}
	summary := fmt.Sprintf("%s %s", c2FirstNonEmpty(method, "GET"), path)
	evidence := fmt.Sprintf("a=%s h=%s t=%s p=%s", arch, serverHost, transport, listenerPort)
	b.addVShellCandidate(packet, "websocket", "websocket-handshake", summary, clampConfidence(confidence), evidence,
		tags, []string{"SilverFox-compatible-field"}, "", "", []string{"ws-handshake"})
}

func (b *c2AnalysisBuilder) inspectDNSPacket(packet model.Packet, text string) {
	qname := extractC2DNSName(text)
	if qname == "" {
		qname = truncateC2(strings.TrimSpace(packet.Info), 120)
	}
	if qname == "" {
		return
	}
	maxLabel := maxDNSLabelLength(qname)
	upperText := strings.ToUpper(text)
	
	queryType := "A"
	isTXT := strings.Contains(upperText, " TXT ")
	isNull := strings.Contains(upperText, " NULL ")
	isCNAME := strings.Contains(upperText, " CNAME ")
	if isTXT {
		queryType = "TXT"
	} else if isNull {
		queryType = "NULL"
	} else if isCNAME {
		queryType = "CNAME"
	}
	
	isResponse := strings.Contains(upperText, "RESPONSE") || strings.Contains(upperText, "RESP ")
	
	obs := c2DNSObservation{
		packet:     packet,
		qname:      qname,
		maxLabel:   maxLabel,
		queryType:  queryType,
		isTXT:      isTXT,
		isNull:     isNull,
		isCNAME:    isCNAME,
		isResponse: isResponse,
		confidence: 28,
		tags:       []string{"dns"},
	}
	
	if maxLabel >= 45 || isTXT {
		obs.confidence = 58
		obs.tags = append(obs.tags, "long-label-or-txt")
	}
	
	b.dnsObservations = append(b.dnsObservations, obs)
	
	tags := []string{"dns"}
	confidence := 28
	indicatorType := "dns-presence"
	summary := "DNS C2 channel 候选"
	if maxLabel >= 45 || isTXT {
		confidence = 58
		indicatorType = "dns-beacon-shape"
		summary = "DNS Beacon / tunneling 弱特征候选"
		tags = append(tags, "long-label-or-txt")
	}
	b.addCSCandidate(packet, "dns", indicatorType, summary, confidence,
		fmt.Sprintf("qname=%s max_label=%d", qname, maxLabel), tags, nil)
}

func (b *c2AnalysisBuilder) inspectVShellTCPPacket(packet model.Packet, payloadText string) {
	rawBytes := c2PayloadBytes(packet)
	decoded := strings.TrimSpace(string(rawBytes))
	if decoded == "" {
		decoded = strings.TrimSpace(payloadText)
	}
	portHint := packet.DestPort == 8082 || packet.SourcePort == 8082 || packet.DestPort == 8084 || packet.SourcePort == 8084
	if portHint {
		channel := "tcp"
		if packet.DestPort == 8082 || packet.SourcePort == 8082 {
			channel = "management"
		}
		b.addVShellCandidate(packet, channel, "listener-port", "VShell listener / management port 观察位", 34,
			fmt.Sprintf("src_port=%d dst_port=%d", packet.SourcePort, packet.DestPort), []string{"port-weak-signal"}, nil, "", "", nil)
		if packet.StreamID > 0 {
			sw := b.getOrCreateVShellStream(packet.StreamID, "tcp")
			hint := "listener-port"
			if packet.DestPort == 8082 || packet.SourcePort == 8082 {
				hint = "management-port"
			}
			sw.listenerHints[hint]++
		}
	}

	if c2VShellArchRE.MatchString(decoded) {
		b.addVShellCandidate(packet, "tcp", "arch-marker", "VShell TCP 架构标记候选", 78,
			truncateC2(decoded, 120), []string{"arch-marker", "l64-w64"}, []string{"SilverFox-compatible-field"}, "", "", []string{"tcp-arch-marker"})
		if packet.StreamID > 0 {
			sw := b.getOrCreateVShellStream(packet.StreamID, "tcp")
			marker := c2VShellArchRE.FindString(decoded)
			if marker != "" {
				sw.archMarkers[strings.ToLower(marker)]++
			}
		}
	}

	if ok, declared := hasLengthPrefixShape(rawBytes); ok {
		confidence := 58
		if len(rawBytes) <= 96 {
			confidence = 64
		}
		b.addVShellCandidate(packet, "tcp", "length-prefixed-encrypted-payload", "VShell 4 字节长度前缀 / 加密负载候选", confidence,
			fmt.Sprintf("declared=%d payload_bytes=%d", declared, len(rawBytes)), []string{"length-prefix", "encrypted-payload-shape"}, nil, "", "", []string{"4-byte-length-prefix"})
		if packet.StreamID > 0 {
			sw := b.getOrCreateVShellStream(packet.StreamID, "tcp")
			sw.lengthPrefix++
		}
	}
}

func (b *c2AnalysisBuilder) getOrCreateVShellStream(streamID int64, protocol string) *c2VShellStreamWork {
	sw, ok := b.vshellStreamData[streamID]
	if !ok {
		sw = &c2VShellStreamWork{
			streamID:      streamID,
			protocol:      protocol,
			packets:       []model.Packet{},
			archMarkers:   map[string]int{},
			listenerHints: map[string]int{},
		}
		b.vshellStreamData[streamID] = sw
	}
	return sw
}

func (b *c2AnalysisBuilder) emitCSHTTPCandidate(obs c2HTTPObservation, confidence int, evidence string, tags []string) {
	if obs.packet.ID > 0 {
		if _, ok := b.emittedCSHTTPPackets[obs.packet.ID]; ok {
			return
		}
		b.emittedCSHTTPPackets[obs.packet.ID] = struct{}{}
	}
	summary := fmt.Sprintf("%s %s", obs.method, c2FirstNonEmpty(obs.path, obs.packet.Info))
	b.addCSCandidate(obs.packet, obs.channel, "http-beacon-shape", summary, confidence, strings.TrimSpace(evidence), uniqueStrings(tags), nil)
}

func strongCSHTTPStaticSignal(obs c2HTTPObservation) (bool, int, []string) {
	method := strings.ToUpper(strings.TrimSpace(obs.method))
	path := strings.ToLower(strings.TrimSpace(obs.path))
	if method == "" || path == "" {
		return false, 0, nil
	}
	tags := []string{"http", "malleable-profile-weak"}
	if method == "POST" && (strings.Contains(path, "submit") || strings.Contains(path, "id=")) {
		return true, 48, append(tags, "default-profile-like", "post-result-shape")
	}
	if method == "GET" && strings.Contains(path, "__utm.gif") {
		return true, 44, append(tags, "default-profile-like", "get-tasking-shape")
	}
	return false, 0, nil
}

func (b *c2AnalysisBuilder) promoteCSHTTPObservations() {
	if len(b.httpObservations) == 0 {
		return
	}
	endpoints := map[string][]c2HTTPObservation{}
	for _, obs := range b.httpObservations {
		if obs.method != "GET" && obs.method != "POST" {
			continue
		}
		host := strings.ToLower(c2FirstNonEmpty(obs.host, "(no-host)"))
		path := c2FirstNonEmpty(obs.path, "(no-uri)")
		key := host + "\x00" + path
		endpoints[key] = append(endpoints[key], obs)
	}
	for _, group := range endpoints {
		if len(group) < 4 {
			continue
		}
		methods := map[string]int{}
		times := []float64{}
		for _, obs := range group {
			methods[obs.method]++
			if ts, ok := parseC2ClockSeconds(obs.packet.Timestamp); ok {
				times = append(times, ts)
			}
		}
		sort.Float64s(times)
		intervals := []float64{}
		for i := 1; i < len(times); i++ {
			if delta := times[i] - times[i-1]; delta > 0 {
				intervals = append(intervals, delta)
			}
		}
		avg, jitter := avgAndJitter(intervals)
		hasStableRepeat := len(intervals) >= 3 && avg >= 5 && jitter <= 0.35
		hasHighVolume := len(group) >= 6
		if !hasStableRepeat && !hasHighVolume {
			continue
		}
		confidence := 54
		tags := []string{"http", "endpoint-repeat", "correlated-signal"}
		reason := fmt.Sprintf("Host/URI 重复通信提升为 CS HTTP 候选：samples=%d", len(group))
		if methods["GET"] > 0 && methods["POST"] > 0 {
			confidence += 8
			tags = append(tags, "get-post-tasking-shape")
			reason += fmt.Sprintf(" GET=%d POST=%d", methods["GET"], methods["POST"])
		}
		if hasStableRepeat {
			confidence += 8
			tags = append(tags, "stable-interval")
			reason += fmt.Sprintf(" avg=%.1fs jitter=%.0f%%", avg, jitter*100)
		}
		for _, obs := range group {
			b.emitCSHTTPCandidate(obs, clampConfidence(confidence), reason+" "+obs.evidence, tags)
		}
	}
}

func (b *c2AnalysisBuilder) inspectStreamPatterns(ctx context.Context) {
	for key, packets := range b.streams {
		if err := ctx.Err(); err != nil {
			return
		}
		if len(packets) < 4 {
			continue
		}
		sort.SliceStable(packets, func(i, j int) bool { return packets[i].ID < packets[j].ID })
		protocol := strings.ToUpper(strings.Split(key, ":")[0])
		if strings.Contains(protocol, "TCP") || strings.Contains(protocol, "HTTP") || strings.Contains(protocol, "TLS") {
			b.inspectPeriodicStream(packets)
			b.inspectVShellShortLongStream(packets)
		}
	}
}

func (b *c2AnalysisBuilder) inspectPeriodicStream(packets []model.Packet) {
	times := make([]float64, 0, len(packets))
	for _, packet := range packets {
		if ts, ok := parseC2ClockSeconds(packet.Timestamp); ok {
			times = append(times, ts)
		}
	}
	if len(times) < 4 {
		return
	}
	intervals := make([]float64, 0, len(times)-1)
	for i := 1; i < len(times); i++ {
		delta := times[i] - times[i-1]
		if delta > 0 {
			intervals = append(intervals, delta)
		}
	}
	if len(intervals) < 3 {
		return
	}
	avg, jitter := avgAndJitter(intervals)
	if avg < 3 || jitter > 0.35 {
		return
	}
	packet := packets[0]
	summary := fmt.Sprintf("周期性回连候选 avg=%.1fs jitter=%.0f%%", avg, jitter*100)
	tags := []string{"periodic", "beacon-like"}
	confidence := 62
	if avg >= 8 && avg <= 12 {
		b.result.VShell.BeaconPatterns = append(b.result.VShell.BeaconPatterns, model.C2BeaconPattern{
			Name:       "heartbeat-interval",
			Value:      fmt.Sprintf("%.1fs", avg),
			Confidence: 70,
			Summary:    summary,
		})
		b.addVShellCandidate(packet, "tcp", "heartbeat-interval", "VShell 约 10 秒心跳候选", 70,
			summary, append(tags, "10s-heartbeat"), []string{"SilverFox-compatible-field"}, "ValleyRAT/Winos-compatible", "command-and-control", []string{"periodic-callback"})
		if packet.StreamID > 0 {
			sw := b.getOrCreateVShellStream(packet.StreamID, "tcp")
			sw.heartbeatAvg = fmt.Sprintf("%.1fs", avg)
			sw.heartbeatJit = fmt.Sprintf("%.0f%%", jitter*100)
			sw.confidence = 70
		}
		return
	}
	if avg >= 45 && avg <= 75 {
		tags = append(tags, "silverfox-60s-compatible")
		confidence = 66
	}
	b.addCSCandidate(packet, httpChannel(packet), "beacon-interval", summary, confidence,
		fmt.Sprintf("samples=%d avg=%.2fs jitter=%.2f", len(intervals), avg, jitter), tags, []string{"SilverFox-compatible-field"})
	b.result.CS.BeaconPatterns = append(b.result.CS.BeaconPatterns, model.C2BeaconPattern{
		Name:       "beacon-interval",
		Value:      fmt.Sprintf("%.1fs", avg),
		Confidence: confidence,
		Summary:    summary,
	})
}

func (b *c2AnalysisBuilder) inspectVShellShortLongStream(packets []model.Packet) {
	if len(packets) < 5 {
		return
	}
	shortCount := 0
	longCount := 0
	transitions := 0
	lastKind := ""
	for _, packet := range packets {
		size := c2PayloadSize(packet)
		if size <= 0 {
			size = packet.Length
		}
		kind := ""
		switch {
		case size > 0 && size <= 96:
			shortCount++
			kind = "short"
		case size >= 256:
			longCount++
			kind = "long"
		}
		if kind != "" && lastKind != "" && kind != lastKind {
			transitions++
		}
		if kind != "" {
			lastKind = kind
		}
	}
	if shortCount >= 3 && longCount >= 1 && transitions >= 2 {
		b.addVShellCandidate(packets[0], "tcp", "short-long-alternation", "VShell 短包 / 长包交替候选", 56,
			fmt.Sprintf("short=%d long=%d transitions=%d", shortCount, longCount, transitions),
			[]string{"short-long-alternation", "heartbeat-command-shape"}, []string{"SilverFox-compatible-field"}, "", "", []string{"packet-size-pattern"})
		if packets[0].StreamID > 0 {
			sw := b.getOrCreateVShellStream(packets[0].StreamID, "tcp")
			sw.shortPackets = shortCount
			sw.longPackets = longCount
			sw.transitions = transitions
		}
	}
}

func (b *c2AnalysisBuilder) addCSCandidate(packet model.Packet, channel, indicatorType, summary string, confidence int, evidence string, tags []string, actorHints []string) {
	b.result.CS.Candidates = append(b.result.CS.Candidates, model.C2IndicatorRecord{
		PacketID:              packet.ID,
		StreamID:              packet.StreamID,
		Time:                  packet.Timestamp,
		Family:                "cs",
		Channel:               c2FirstNonEmpty(channel, "unknown"),
		Source:                endpoint(packet.SourceIP, packet.SourcePort),
		Destination:           endpoint(packet.DestIP, packet.DestPort),
		Host:                  c2HostFromPacket(packet),
		URI:                   c2URIFromPacket(packet),
		Method:                httpLoginMethod(packet),
		IndicatorType:         indicatorType,
		IndicatorValue:        c2FirstNonEmpty(c2URIFromPacket(packet), c2HostFromPacket(packet), evidence),
		Confidence:            clampConfidence(confidence),
		Summary:               summary,
		Evidence:              evidence,
		Tags:                  uniqueStrings(tags),
		ActorHints:            uniqueStrings(actorHints),
		TransportTraits:       uniqueStrings([]string{c2FirstNonEmpty(channel, "unknown")}),
		InfrastructureHints:   uniqueStrings(c2InfraHints(packet)),
		AttributionConfidence: 0,
	})
	b.bump("CS", channel, indicatorType, packet, b.csChannels, b.csIndicators, b.csConversations, b.csRelatedActors, b.csDeliveryChains)
}

func (b *c2AnalysisBuilder) addVShellCandidate(packet model.Packet, channel, indicatorType, summary string, confidence int, evidence string, tags []string, actorHints []string, sampleFamily, campaignStage string, transportTraits []string) {
	b.result.VShell.Candidates = append(b.result.VShell.Candidates, model.C2IndicatorRecord{
		PacketID:              packet.ID,
		StreamID:              packet.StreamID,
		Time:                  packet.Timestamp,
		Family:                "vshell",
		Channel:               c2FirstNonEmpty(channel, "unknown"),
		Source:                endpoint(packet.SourceIP, packet.SourcePort),
		Destination:           endpoint(packet.DestIP, packet.DestPort),
		Host:                  c2HostFromPacket(packet),
		URI:                   c2URIFromPacket(packet),
		Method:                httpLoginMethod(packet),
		IndicatorType:         indicatorType,
		IndicatorValue:        c2FirstNonEmpty(c2URIFromPacket(packet), c2HostFromPacket(packet), evidence),
		Confidence:            clampConfidence(confidence),
		Summary:               summary,
		Evidence:              evidence,
		Tags:                  uniqueStrings(tags),
		ActorHints:            uniqueStrings(actorHints),
		SampleFamily:          sampleFamily,
		CampaignStage:         campaignStage,
		TransportTraits:       uniqueStrings(append([]string{c2FirstNonEmpty(channel, "unknown")}, transportTraits...)),
		InfrastructureHints:   uniqueStrings(c2InfraHints(packet)),
		AttributionConfidence: 0,
	})
	b.bump("VShell", channel, indicatorType, packet, b.vshellChannels, b.vshellIndicators, b.vshellConversations, b.vshellRelatedActors, b.vshellDeliveryChains)
}

func (b *c2AnalysisBuilder) bump(family, channel, indicator string, packet model.Packet, channels, indicators map[string]int, conversations map[string]int, relatedActors map[string]int, deliveryChains map[string]int) {
	b.families[family]++
	channels[c2FirstNonEmpty(channel, "unknown")]++
	indicators[c2FirstNonEmpty(indicator, "unknown")]++
	conv := fmt.Sprintf("%s -> %s", endpoint(packet.SourceIP, packet.SourcePort), endpoint(packet.DestIP, packet.DestPort))
	b.conversations[conv]++
	conversations[conv]++
	for _, hint := range c2InfraHints(packet) {
		deliveryChains[hint]++
		if strings.Contains(strings.ToLower(hint), "silverfox") || strings.Contains(strings.ToLower(hint), "hfs") {
			relatedActors["SilverFox-compatible"]++
		}
	}
}

func (b *c2AnalysisBuilder) finish() {
	b.promoteCSHTTPObservations()

	b.result.Families = bucketsFromMap(b.families, 12)
	b.result.Conversations = conversationsFromMap(b.conversations, "", 20)
	b.result.TotalMatchedPackets = countUniqueC2Packets(b.result.CS.Candidates, b.result.VShell.Candidates)

	b.result.CS.CandidateCount = len(b.result.CS.Candidates)
	b.result.CS.MatchedRuleCount = len(b.csIndicators)
	b.result.CS.Channels = bucketsFromMap(b.csChannels, 12)
	b.result.CS.Indicators = bucketsFromMap(b.csIndicators, 16)
	b.result.CS.Conversations = conversationsFromMap(b.csConversations, "CS", 16)
	b.result.CS.RelatedActors = bucketsFromMap(b.csRelatedActors, 8)
	b.result.CS.DeliveryChains = bucketsFromMap(b.csDeliveryChains, 8)
	b.result.CS.HostURIAggregates = buildCSHostURIAggregates(b.result.CS.Candidates, 16)
	b.result.CS.DNSAggregates = buildCSDNSAggregates(b.dnsObservations, 16)

	b.result.VShell.CandidateCount = len(b.result.VShell.Candidates)
	b.result.VShell.MatchedRuleCount = len(b.vshellIndicators)
	b.result.VShell.Channels = bucketsFromMap(b.vshellChannels, 12)
	b.result.VShell.Indicators = bucketsFromMap(b.vshellIndicators, 16)
	b.result.VShell.Conversations = conversationsFromMap(b.vshellConversations, "VShell", 16)
	b.result.VShell.RelatedActors = bucketsFromMap(b.vshellRelatedActors, 8)
	b.result.VShell.DeliveryChains = bucketsFromMap(b.vshellDeliveryChains, 8)
	b.result.VShell.StreamAggregates = buildVShellStreamAggregates(b.vshellStreamData, 16)

	if len(b.result.CS.Candidates) == 0 {
		b.result.CS.Notes = append(b.result.CS.Notes, "未发现 CS 候选；当前规则会抑制一次性普通 HTTP 请求，仅提升强静态线索、重复 Host/URI、DNS 长标签/TXT、SMB pivot 占位与周期性 beacon。")
	} else {
		b.result.CS.Notes = append(b.result.CS.Notes, "CS 结果是候选证据：Malleable C2 可自定义 URI/Header/UA；普通一次性 GET/POST 已默认抑制，HTTP 候选优先来自强静态线索、重复 Host/URI 或周期行为。")
	}
	if len(b.result.VShell.Candidates) == 0 {
		b.result.VShell.Notes = append(b.result.VShell.Notes, "未发现 VShell 候选；当前规则覆盖 WebSocket 参数、l64/w64 架构标记、4 字节长度前缀、短长包交替和约 10 秒心跳。")
	} else {
		b.result.VShell.Notes = append(b.result.VShell.Notes, "VShell 结果是候选证据：端口 8082/8084/8088 只作为中弱信号，WebSocket 参数与 TCP 负载形态权重更高。")
	}
}

type c2EndpointAggregateWork struct {
	host        string
	uri         string
	channel     string
	total       int
	methods     map[string]int
	firstTime   string
	lastTime    string
	times       []float64
	streams     []int64
	packets     []int64
	postPacket  int64
	confidence  int
	indicatorTy []string
}

func buildCSHostURIAggregates(candidates []model.C2IndicatorRecord, limit int) []model.C2HTTPEndpointAggregate {
	work := map[string]*c2EndpointAggregateWork{}
	for _, candidate := range candidates {
		if strings.ToLower(candidate.Family) != "cs" {
			continue
		}
		if strings.TrimSpace(candidate.IndicatorType) != "http-beacon-shape" {
			continue
		}
		channel := strings.ToLower(strings.TrimSpace(candidate.Channel))
		if channel != "http" && channel != "https" {
			continue
		}
		host := strings.TrimSpace(candidate.Host)
		uri := strings.TrimSpace(candidate.URI)
		if host == "" && uri == "" {
			continue
		}
		if host == "" {
			host = "(no-host)"
		}
		if uri == "" {
			uri = "(no-uri)"
		}
		key := strings.ToLower(host) + "\x00" + uri
		item := work[key]
		if item == nil {
			item = &c2EndpointAggregateWork{
				host:    host,
				uri:     uri,
				channel: c2FirstNonEmpty(channel, "http"),
				methods: map[string]int{},
			}
			work[key] = item
		}
		item.total++
		method := strings.ToUpper(strings.TrimSpace(candidate.Method))
		if method == "" {
			method = "UNKNOWN"
		}
		item.methods[method]++
		if candidate.StreamID > 0 {
			item.streams = append(item.streams, candidate.StreamID)
		}
		if candidate.PacketID > 0 {
			item.packets = append(item.packets, candidate.PacketID)
			if method == "POST" && item.postPacket <= 0 {
				item.postPacket = candidate.PacketID
			}
		}
		if candidate.Confidence > item.confidence {
			item.confidence = candidate.Confidence
		}
		if strings.TrimSpace(candidate.IndicatorType) != "" {
			item.indicatorTy = append(item.indicatorTy, candidate.IndicatorType)
		}
		if candidate.Time != "" {
			if item.firstTime == "" || candidate.Time < item.firstTime {
				item.firstTime = candidate.Time
			}
			if item.lastTime == "" || candidate.Time > item.lastTime {
				item.lastTime = candidate.Time
			}
			if seconds, ok := parseC2ClockSeconds(candidate.Time); ok {
				item.times = append(item.times, seconds)
			}
		}
	}

	out := make([]model.C2HTTPEndpointAggregate, 0, len(work))
	for _, item := range work {
		sort.Float64s(item.times)
		intervals := make([]float64, 0, len(item.times)-1)
		for i := 1; i < len(item.times); i++ {
			if delta := item.times[i] - item.times[i-1]; delta > 0 {
				intervals = append(intervals, delta)
			}
		}
		avgInterval := ""
		jitterText := ""
		if len(intervals) > 0 {
			avg, jitter := avgAndJitter(intervals)
			avgInterval = fmt.Sprintf("%.1fs", avg)
			jitterText = fmt.Sprintf("%.0f%%", jitter*100)
		}
		confidence := item.confidence
		if item.methods["GET"] > 0 && item.methods["POST"] > 0 {
			confidence += 10
		}
		if len(intervals) >= 2 && jitterText != "" {
			confidence += 6
		}
		summaryParts := []string{fmt.Sprintf("%d HTTP 候选", item.total)}
		if item.methods["GET"] > 0 {
			summaryParts = append(summaryParts, fmt.Sprintf("GET=%d", item.methods["GET"]))
		}
		if item.methods["POST"] > 0 {
			summaryParts = append(summaryParts, fmt.Sprintf("POST=%d", item.methods["POST"]))
		}
		if avgInterval != "" {
			summaryParts = append(summaryParts, "avg="+avgInterval, "jitter="+jitterText)
		}
		representativePacket := item.postPacket
		if representativePacket <= 0 && len(item.packets) > 0 {
			representativePacket = item.packets[0]
		}
		out = append(out, model.C2HTTPEndpointAggregate{
			Host:                item.host,
			URI:                 item.uri,
			Channel:             item.channel,
			Total:               item.total,
			GetCount:            item.methods["GET"],
			PostCount:           item.methods["POST"],
			Methods:             bucketsFromMap(item.methods, 8),
			FirstTime:           item.firstTime,
			LastTime:            item.lastTime,
			AvgInterval:         avgInterval,
			Jitter:              jitterText,
			Streams:             limitInt64List(uniqueInt64s(item.streams), 12),
			Packets:             limitInt64List(uniqueInt64s(item.packets), 24),
			RepresentativePacket: representativePacket,
			Confidence:          clampConfidence(confidence),
			Summary:             strings.Join(summaryParts, " · "),
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Total == out[j].Total {
			if out[i].Host == out[j].Host {
				return out[i].URI < out[j].URI
			}
			return out[i].Host < out[j].Host
		}
		return out[i].Total > out[j].Total
	})
	if limit > 0 && len(out) > limit {
		return out[:limit]
	}
	return out
}

type c2DNSAggregateWork struct {
	qname       string
	total       int
	maxLabel    int
	queryTypes  map[string]int
	txtCount    int
	nullCount   int
	cnameCount  int
	requestCount int
	responseCount int
	firstTime   string
	lastTime    string
	times       []float64
	packets     []int64
	confidence  int
}

func buildCSDNSAggregates(observations []c2DNSObservation, limit int) []model.C2DNSAggregate {
	work := map[string]*c2DNSAggregateWork{}
	for _, obs := range observations {
		qname := strings.ToLower(strings.TrimSpace(obs.qname))
		if qname == "" {
			continue
		}
		item := work[qname]
		if item == nil {
			item = &c2DNSAggregateWork{
				qname:      qname,
				queryTypes: map[string]int{},
			}
			work[qname] = item
		}
		item.total++
		if obs.maxLabel > item.maxLabel {
			item.maxLabel = obs.maxLabel
		}
		item.queryTypes[obs.queryType]++
		if obs.isTXT {
			item.txtCount++
		}
		if obs.isNull {
			item.nullCount++
		}
		if obs.isCNAME {
			item.cnameCount++
		}
		if obs.isResponse {
			item.responseCount++
		} else {
			item.requestCount++
		}
		if obs.packet.ID > 0 {
			item.packets = append(item.packets, obs.packet.ID)
		}
		if obs.confidence > item.confidence {
			item.confidence = obs.confidence
		}
		if obs.packet.Timestamp != "" {
			if item.firstTime == "" || obs.packet.Timestamp < item.firstTime {
				item.firstTime = obs.packet.Timestamp
			}
			if item.lastTime == "" || obs.packet.Timestamp > item.lastTime {
				item.lastTime = obs.packet.Timestamp
			}
			if seconds, ok := parseC2ClockSeconds(obs.packet.Timestamp); ok {
				item.times = append(item.times, seconds)
			}
		}
	}

	out := make([]model.C2DNSAggregate, 0, len(work))
	for _, item := range work {
		sort.Float64s(item.times)
		intervals := make([]float64, 0, len(item.times)-1)
		for i := 1; i < len(item.times); i++ {
			if delta := item.times[i] - item.times[i-1]; delta > 0 {
				intervals = append(intervals, delta)
			}
		}
		avgInterval := ""
		jitterText := ""
		if len(intervals) > 0 {
			avg, jitter := avgAndJitter(intervals)
			avgInterval = fmt.Sprintf("%.1fs", avg)
			jitterText = fmt.Sprintf("%.0f%%", jitter*100)
		}
		confidence := item.confidence
		if item.txtCount > 0 || item.nullCount > 0 {
			confidence += 8
		}
		if item.maxLabel >= 45 {
			confidence += 6
		}
		if len(intervals) >= 2 && jitterText != "" {
			confidence += 4
		}
		summaryParts := []string{fmt.Sprintf("%d DNS 查询", item.total)}
		if item.txtCount > 0 {
			summaryParts = append(summaryParts, fmt.Sprintf("TXT=%d", item.txtCount))
		}
		if item.nullCount > 0 {
			summaryParts = append(summaryParts, fmt.Sprintf("NULL=%d", item.nullCount))
		}
		if item.maxLabel >= 45 {
			summaryParts = append(summaryParts, fmt.Sprintf("max_label=%d", item.maxLabel))
		}
		if avgInterval != "" {
			summaryParts = append(summaryParts, "avg="+avgInterval, "jitter="+jitterText)
		}
		reqRespRatio := ""
		if item.requestCount > 0 && item.responseCount > 0 {
			reqRespRatio = fmt.Sprintf("req=%d resp=%d", item.requestCount, item.responseCount)
		} else if item.requestCount > 0 {
			reqRespRatio = fmt.Sprintf("req=%d", item.requestCount)
		} else if item.responseCount > 0 {
			reqRespRatio = fmt.Sprintf("resp=%d", item.responseCount)
		}
		if reqRespRatio != "" {
			summaryParts = append(summaryParts, reqRespRatio)
		}
		out = append(out, model.C2DNSAggregate{
			QName:          item.qname,
			Total:          item.total,
			MaxLabelLength: item.maxLabel,
			QueryTypes:     bucketsFromMap(item.queryTypes, 8),
			TxtCount:       item.txtCount,
			NullCount:      item.nullCount,
			CnameCount:     item.cnameCount,
			RequestCount:   item.requestCount,
			ResponseCount:  item.responseCount,
			FirstTime:      item.firstTime,
			LastTime:       item.lastTime,
			AvgInterval:    avgInterval,
			Jitter:         jitterText,
			Packets:        limitInt64List(uniqueInt64s(item.packets), 24),
			Confidence:     clampConfidence(confidence),
			Summary:        strings.Join(summaryParts, " · "),
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Total == out[j].Total {
			return out[i].QName < out[j].QName
		}
		return out[i].Total > out[j].Total
	})
	if limit > 0 && len(out) > limit {
		return out[:limit]
	}
	return out
}

func buildVShellStreamAggregates(streamData map[int64]*c2VShellStreamWork, limit int) []model.C2StreamAggregate {
	out := make([]model.C2StreamAggregate, 0, len(streamData))
	for _, sw := range streamData {
		if sw.streamID <= 0 {
			continue
		}
		totalPackets := len(sw.packets)
		if totalPackets < 3 {
			continue
		}
		times := make([]float64, 0, totalPackets)
		packetIDs := make([]int64, 0, totalPackets)
		firstTime := ""
		lastTime := ""
		for _, p := range sw.packets {
			if p.ID > 0 {
				packetIDs = append(packetIDs, p.ID)
			}
			if p.Timestamp != "" {
				if firstTime == "" || p.Timestamp < firstTime {
					firstTime = p.Timestamp
				}
				if lastTime == "" || p.Timestamp > lastTime {
					lastTime = p.Timestamp
				}
				if seconds, ok := parseC2ClockSeconds(p.Timestamp); ok {
					times = append(times, seconds)
				}
			}
		}
		confidence := sw.confidence
		if sw.lengthPrefix > 0 {
			confidence += 6
		}
		if sw.shortPackets >= 3 && sw.longPackets >= 1 && sw.transitions >= 2 {
			confidence += 8
		}
		if sw.heartbeatAvg != "" {
			confidence += 6
		}
		if len(sw.archMarkers) > 0 {
			confidence += 4
		}
		summaryParts := []string{fmt.Sprintf("%d 包", totalPackets)}
		if len(sw.archMarkers) > 0 {
			for marker, count := range sw.archMarkers {
				summaryParts = append(summaryParts, fmt.Sprintf("%s=%d", marker, count))
			}
		}
		if sw.lengthPrefix > 0 {
			summaryParts = append(summaryParts, fmt.Sprintf("length-prefix=%d", sw.lengthPrefix))
		}
		if sw.shortPackets > 0 && sw.longPackets > 0 {
			summaryParts = append(summaryParts, fmt.Sprintf("short=%d long=%d", sw.shortPackets, sw.longPackets))
		}
		if sw.heartbeatAvg != "" {
			summaryParts = append(summaryParts, "heartbeat="+sw.heartbeatAvg)
		}
		if sw.hasWebSocket {
			summaryParts = append(summaryParts, "websocket")
		}
		out = append(out, model.C2StreamAggregate{
			StreamID:        sw.streamID,
			Protocol:        sw.protocol,
			TotalPackets:    totalPackets,
			ArchMarkers:     bucketsFromMap(sw.archMarkers, 4),
			LengthPrefix:    sw.lengthPrefix,
			ShortPackets:    sw.shortPackets,
			LongPackets:     sw.longPackets,
			Transitions:     sw.transitions,
			HeartbeatAvg:    sw.heartbeatAvg,
			HeartbeatJitter: sw.heartbeatJit,
			HasWebSocket:    sw.hasWebSocket,
			WSParams:        sw.wsParams,
			ListenerHints:   bucketsFromMap(sw.listenerHints, 4),
			FirstTime:       firstTime,
			LastTime:        lastTime,
			Packets:         limitInt64List(uniqueInt64s(packetIDs), 24),
			Confidence:      clampConfidence(confidence),
			Summary:         strings.Join(summaryParts, " · "),
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Confidence == out[j].Confidence {
			return out[i].StreamID < out[j].StreamID
		}
		return out[i].Confidence > out[j].Confidence
	})
	if limit > 0 && len(out) > limit {
		return out[:limit]
	}
	return out
}

func c2FirstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func headerValueCI(headers map[string]string, name string) string {
	for key, value := range headers {
		if c2HTTPHeaderUserAgent.MatchString(key) && strings.EqualFold(name, "User-Agent") {
			return value
		}
		if strings.EqualFold(key, name) {
			return value
		}
	}
	return ""
}

func httpChannel(packet model.Packet) string {
	if packet.SourcePort == 443 || packet.DestPort == 443 || strings.Contains(strings.ToUpper(packet.Protocol), "TLS") {
		return "https"
	}
	if isHTTPLikePacket(packet) {
		return "http"
	}
	return strings.ToLower(c2FirstNonEmpty(packet.Protocol, "tcp"))
}

func endpoint(ip string, port int) string {
	if strings.TrimSpace(ip) == "" {
		if port > 0 {
			return fmt.Sprintf(":%d", port)
		}
		return ""
	}
	if port > 0 {
		return fmt.Sprintf("%s:%d", ip, port)
	}
	return ip
}

func c2HostFromPacket(packet model.Packet) string {
	payloadText := decodeHTTPPayloadText(packet.Payload)
	headers := extractHTTPHeaders(payloadText)
	return strings.TrimSpace(headers["Host"])
}

func c2URIFromPacket(packet model.Packet) string {
	return httpRequestPath(packet, decodeHTTPPayloadText(packet.Payload))
}

func c2InfraHints(packet model.Packet) []string {
	hints := []string{}
	for _, port := range []int{packet.SourcePort, packet.DestPort} {
		switch port {
		case 443:
			hints = append(hints, "https-c2-compatible")
		case 8082:
			hints = append(hints, "vshell-management-surface")
		case 8084, 8088:
			hints = append(hints, "vshell-listener-port")
		case 18856, 9899:
			hints = append(hints, "silverfox-case-port-weak")
		}
	}
	if strings.Contains(strings.ToLower(packet.Info), "hfs") || strings.Contains(strings.ToLower(packet.Payload), "hfs") {
		hints = append(hints, "hfs-delivery")
	}
	return hints
}

func c2PayloadBytes(packet model.Packet) []byte {
	if decoded := decodeLooseHex(strings.TrimSpace(c2FirstNonEmpty(packet.Payload, packet.RawHex, packet.UDPPayloadHex))); len(decoded) > 0 {
		return decoded
	}
	text := c2FirstNonEmpty(packet.Payload, packet.RawHex, packet.UDPPayloadHex)
	return []byte(text)
}

func c2PayloadSize(packet model.Packet) int {
	if bytes := c2PayloadBytes(packet); len(bytes) > 0 {
		return len(bytes)
	}
	return packet.Length
}

func hasLengthPrefixShape(payload []byte) (bool, int) {
	if len(payload) < 8 {
		return false, 0
	}
	be := int(payload[0])<<24 | int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	le := int(payload[3])<<24 | int(payload[2])<<16 | int(payload[1])<<8 | int(payload[0])
	for _, declared := range []int{be, le} {
		if declared <= 0 {
			continue
		}
		remaining := len(payload) - 4
		if declared == remaining || math.Abs(float64(declared-remaining)) <= 4 {
			return true, declared
		}
	}
	return false, 0
}

func extractC2DNSName(text string) string {
	matches := c2DNSNameLikeRE.FindStringSubmatch(text)
	if len(matches) >= 2 {
		return strings.Trim(strings.ToLower(matches[1]), ".")
	}
	fields := strings.Fields(text)
	for _, field := range fields {
		clean := strings.Trim(strings.ToLower(field), ".,;:()[]{}<>\"'")
		if strings.Count(clean, ".") >= 1 && len(clean) >= 6 {
			return clean
		}
	}
	return ""
}

func maxDNSLabelLength(qname string) int {
	maxLen := 0
	for _, label := range strings.Split(strings.Trim(qname, "."), ".") {
		if len(label) > maxLen {
			maxLen = len(label)
		}
	}
	return maxLen
}

func parseC2ClockSeconds(value string) (float64, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	if sec, err := strconv.ParseFloat(value, 64); err == nil {
		return sec, true
	}
	parts := strings.Split(value, ":")
	if len(parts) < 3 {
		return 0, false
	}
	hour, errH := strconv.Atoi(parts[0])
	minute, errM := strconv.Atoi(parts[1])
	second, errS := strconv.ParseFloat(parts[2], 64)
	if errH != nil || errM != nil || errS != nil {
		return 0, false
	}
	return float64(hour*3600+minute*60) + second, true
}

func avgAndJitter(values []float64) (float64, float64) {
	if len(values) == 0 {
		return 0, 1
	}
	total := 0.0
	for _, value := range values {
		total += value
	}
	avg := total / float64(len(values))
	if avg <= 0 {
		return avg, 1
	}
	deviation := 0.0
	for _, value := range values {
		deviation += math.Abs(value - avg)
	}
	return avg, deviation / float64(len(values)) / avg
}

func bucketsFromMap(input map[string]int, limit int) []model.TrafficBucket {
	items := make([]model.TrafficBucket, 0, len(input))
	for label, count := range input {
		if strings.TrimSpace(label) == "" || count <= 0 {
			continue
		}
		items = append(items, model.TrafficBucket{Label: label, Count: count})
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Count == items[j].Count {
			return items[i].Label < items[j].Label
		}
		return items[i].Count > items[j].Count
	})
	if limit > 0 && len(items) > limit {
		return items[:limit]
	}
	return items
}

func conversationsFromMap(input map[string]int, protocol string, limit int) []model.AnalysisConversation {
	buckets := bucketsFromMap(input, limit)
	out := make([]model.AnalysisConversation, 0, len(buckets))
	for _, bucket := range buckets {
		out = append(out, model.AnalysisConversation{Label: bucket.Label, Protocol: protocol, Count: bucket.Count})
	}
	return out
}

func countUniqueC2Packets(groups ...[]model.C2IndicatorRecord) int {
	seen := map[int64]struct{}{}
	for _, group := range groups {
		for _, item := range group {
			if item.PacketID > 0 {
				seen[item.PacketID] = struct{}{}
			}
		}
	}
	return len(seen)
}

func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func uniqueInt64s(values []int64) []int64 {
	seen := map[int64]struct{}{}
	out := []int64{}
	for _, value := range values {
		if value <= 0 {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func limitInt64List(values []int64, limit int) []int64 {
	if limit > 0 && len(values) > limit {
		return values[:limit]
	}
	return values
}

func truncateC2(value string, limit int) string {
	value = strings.TrimSpace(value)
	if limit <= 0 || len(value) <= limit {
		return value
	}
	return value[:limit-1] + "…"
}

func clampConfidence(value int) int {
	if value < 0 {
		return 0
	}
	if value > 100 {
		return 100
	}
	return value
}

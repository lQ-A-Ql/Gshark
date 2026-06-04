package engine

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

// DNS tunneling detection thresholds for threat hunting.
const (
	dnsSubdomainLenThreshold = 50  // subdomain label length > 50 is suspicious
	dnsEntropyThreshold      = 3.5 // Shannon entropy above this is suspicious
	dnsHighFreqThreshold     = 10  // >10 queries to same base domain triggers frequency hit
	dnsBase64MinLen          = 12  // minimum label length to check for base64
	dnsHexMinLen             = 16  // minimum label length to check for hex encoding
)

// Brute force detection thresholds.
const (
	bruteForceIPThreshold       = 10 // same IP > N auth failures triggers brute force hit
	bruteForceTargetIPThreshold = 3  // > N distinct source IPs hitting same target with auth failures
)

// Data exfiltration detection thresholds.
const (
	exfilLargePayloadThreshold = 10 * 1024 * 1024 // 10 MB — packet length for large HTTP POST/PUT
	exfilDNSQueryLenThreshold  = 100              // DNS query name length > 100 chars is suspicious
)

// Known exfiltration / file-sharing service domains.
var exfilServiceDomains = []string{
	"mega.nz",
	"mega.co.nz",
	"pastebin.com",
	"paste.ee",
	"dropbox.com",
	"sendspace.com",
	"transfer.sh",
	"file.io",
	"anonfiles.com",
	"bayfiles.com",
	"catbox.moe",
	"litterbox.catbox.moe",
	"gofile.io",
	"tmpfiles.org",
	"0x0.st",
}

var (
	streamFlagRuleName = detectLegacyRuleName(func() []model.ThreatHit {
		return HuntThreats([]model.Packet{{ID: 1, Info: "flag{demo}"}}, []string{"flag{"})
	}, "Flag Match")
	streamFlagBase64RuleName = detectLegacyRuleName(func() []model.ThreatHit {
		return HuntThreats([]model.Packet{{ID: 1, Info: base64.StdEncoding.EncodeToString([]byte("flag{"))}}, []string{"flag{"})
	}, "Flag Base64")
	streamFlagHexRuleName = detectLegacyRuleName(func() []model.ThreatHit {
		return HuntThreats([]model.Packet{{ID: 1, Info: hex.EncodeToString([]byte("flag{"))}}, []string{"flag{"})
	}, "Flag Hex")
	streamAnomalyRuleName     = detectLegacyRuleName(func() []model.ThreatHit { return findAnomaly404403(make404Packets(), 1) }, "Burst 403/404")
	streamAnomalyPreview      = detectLegacyPreview(func() []model.ThreatHit { return findAnomaly404403(make404Packets(), 1) }, "Repeated 403/404 responses in a short window")
	streamNonStandardRuleName = detectLegacyRuleName(func() []model.ThreatHit {
		return DetectNonStandardPortFlows([]model.Packet{{ID: 1, Info: "HTTP GET /test", Protocol: "HTTP", DestPort: 9999, DestIP: "10.0.0.8"}})
	}, "HTTP on Non-standard Port")
	dnsTunnelLongSubRule     = "DNS 隧道：异常长子域名"
	dnsTunnelEncodedSubRule  = "DNS 隧道：编码子域名"
	dnsTunnelHighEntropyRule = "DNS 隧道：高熵子域名"
	dnsTunnelHighFreqRule    = "DNS 隧道：高频查询"
	bruteForceIPRule         = "暴力破解：单 IP 高频认证失败"
	bruteForceCredentialRule = "暴力破解：凭据填充"
	bruteForceAnomalyRule    = "暴力破解：401/403 异常激增"

	exfilLargeHTTPRule = "数据外泄：大文件 HTTP 传输"
	exfilServiceRule   = "数据外泄：已知外泄服务域名"
	exfilDNSQueryRule  = "数据外泄：长 DNS 查询"
)

// dnsDomainStats tracks per-domain DNS query statistics during threat hunting.
type dnsDomainStats struct {
	queryCount  int
	subdomains  map[string]struct{}
	totalSubLen int
	maxSubLen   int
	maxEntropy  float64
	encodedHits int
	firstPacket int64
}

type threatHunter struct {
	prefixes      []string
	encoded       []string
	hexEncoded    []string
	hits          []model.ThreatHit
	nextID        int64
	statusCounter map[string]int
	dnsStats      map[string]*dnsDomainStats // keyed by base domain

	// Brute force detection state.
	// authFailByIP: source IP -> count of 401/403 responses.
	authFailByIP map[string]int
	// authFailByTarget: "destIP:destPort" -> set of source IPs with auth failures.
	authFailByTarget map[string]map[string]struct{}
	// authFailTotal: total 401/403 count across all IPs (for anomaly burst detection).
	authFailTotal int
}

func newThreatHunter(prefixes []string, startID int64) *threatHunter {
	normalized := make([]string, 0, len(prefixes))
	encoded := make([]string, 0, len(prefixes))
	hexEncoded := make([]string, 0, len(prefixes))
	seen := map[string]struct{}{}
	for _, prefix := range prefixes {
		value := strings.TrimSpace(prefix)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		normalized = append(normalized, value)
		encoded = append(encoded, base64.StdEncoding.EncodeToString([]byte(value)))
		hexEncoded = append(hexEncoded, hex.EncodeToString([]byte(value)))
	}
	if startID <= 0 {
		startID = 1
	}
	return &threatHunter{
		prefixes:         normalized,
		encoded:          encoded,
		hexEncoded:       hexEncoded,
		nextID:           startID,
		statusCounter:    map[string]int{},
		dnsStats:         map[string]*dnsDomainStats{},
		authFailByIP:     map[string]int{},
		authFailByTarget: map[string]map[string]struct{}{},
	}
}

func (h *threatHunter) Observe(packet model.Packet) {
	text := packet.Info + "\n" + packet.Payload
	lowerText := strings.ToLower(text)

	for idx, prefix := range h.prefixes {
		if strings.Contains(lowerText, strings.ToLower(prefix)) {
			h.append(model.ThreatHit{
				PacketID: packet.ID,
				Category: "CTF",
				Rule:     streamFlagRuleName,
				Level:    "high",
				Preview:  previewText(text),
				Match:    prefix,
			})
		}
		if idx < len(h.encoded) && strings.Contains(text, h.encoded[idx]) {
			h.append(model.ThreatHit{
				PacketID: packet.ID,
				Category: "CTF",
				Rule:     streamFlagBase64RuleName,
				Level:    "medium",
				Preview:  previewText(text),
				Match:    h.encoded[idx],
			})
		}
		if idx < len(h.hexEncoded) && strings.Contains(lowerText, strings.ToLower(h.hexEncoded[idx])) {
			h.append(model.ThreatHit{
				PacketID: packet.ID,
				Category: "CTF",
				Rule:     streamFlagHexRuleName,
				Level:    "medium",
				Preview:  previewText(text),
				Match:    h.hexEncoded[idx],
			})
		}
	}

	info := strings.ToLower(packet.Info)
	if strings.Contains(info, " 404") || strings.Contains(info, " 403") {
		h.statusCounter[packet.SourceIP]++
	}

	// Brute force detection: track 401/403 auth failures.
	if strings.Contains(info, " 401") || strings.Contains(info, " 403") {
		h.authFailByIP[packet.SourceIP]++
		h.authFailTotal++
		targetKey := packet.DestIP + ":" + fmt.Sprint(packet.DestPort)
		if h.authFailByTarget[targetKey] == nil {
			h.authFailByTarget[targetKey] = make(map[string]struct{})
		}
		h.authFailByTarget[targetKey][packet.SourceIP] = struct{}{}
	}

	if strings.Contains(info, "http") && packet.DestPort != 80 && packet.DestPort != 8080 && packet.DestPort != 443 {
		h.append(model.ThreatHit{
			PacketID: packet.ID,
			Category: "Anomaly",
			Rule:     streamNonStandardRuleName,
			Level:    "medium",
			Preview:  previewText(packet.Info),
			Match:    packet.DestIP,
		})
	}

	// DNS tunneling detection.
	h.observeDNSTunnel(packet)

	// Data exfiltration detection.
	h.observeDataExfiltration(packet)
}

// isBase64Like returns true if a string looks like base64-encoded data.
func isBase64Like(s string) bool {
	if len(s) < dnsBase64MinLen {
		return false
	}
	b64Chars := 0
	for _, c := range s {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' {
			b64Chars++
		}
	}
	ratio := float64(b64Chars) / float64(len(s))
	if ratio < 0.85 {
		return false
	}
	hasUpper, hasDigit := false, false
	for _, c := range s {
		if c >= 'A' && c <= 'Z' {
			hasUpper = true
		}
		if c >= '0' && c <= '9' {
			hasDigit = true
		}
	}
	return hasUpper && hasDigit
}

// isHexLike returns true if a string looks like hex-encoded data.
func isHexLike(s string) bool {
	if len(s) < dnsHexMinLen {
		return false
	}
	hexChars := 0
	for _, c := range s {
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			hexChars++
		}
	}
	return float64(hexChars)/float64(len(s)) > 0.90
}

// observeDNSTunnel checks a single DNS packet for tunneling indicators and
// accumulates per-domain statistics for frequency-based detection.
func (h *threatHunter) observeDNSTunnel(packet model.Packet) {
	if !strings.Contains(strings.ToUpper(packet.Protocol), "DNS") && packet.DestPort != 53 && packet.SourcePort != 53 {
		return
	}
	qname := extractDNSQueryName(packet.Info)
	if qname == "" {
		return
	}
	base := baseDomain(qname)
	if base == "" {
		return
	}
	subdomain := extractSubdomain(qname, base)

	// Also extract the original-case subdomain from the raw Info for encoding detection.
	// extractDNSQueryName lowercases, which destroys the mixed-case signal for base64.
	origQname := extractOriginalCaseQueryName(packet.Info)
	origSub := extractSubdomain(origQname, base)

	// Accumulate per-domain stats for frequency detection.
	stats := h.dnsStats[base]
	if stats == nil {
		stats = &dnsDomainStats{
			subdomains:  make(map[string]struct{}),
			firstPacket: packet.ID,
		}
		h.dnsStats[base] = stats
	}
	stats.queryCount++
	if subdomain != "" {
		stats.subdomains[subdomain] = struct{}{}
		stats.totalSubLen += len(subdomain)
		if len(subdomain) > stats.maxSubLen {
			stats.maxSubLen = len(subdomain)
		}
	}

	// DGA detection applies to the full queried domain, not just subdomains.
	h.observeDGA(packet, qname)

	// Per-packet subdomain analysis.
	if subdomain == "" {
		return
	}

	// Rule 1: Long subdomain detection.
	for _, label := range strings.Split(subdomain, ".") {
		if len(label) > dnsSubdomainLenThreshold {
			h.append(model.ThreatHit{
				PacketID: packet.ID,
				Category: "dns-tunneling",
				Rule:     dnsTunnelLongSubRule,
				Level:    "high",
				Preview:  previewText(fmt.Sprintf("子域名标签长度 %d > %d: %s", len(label), dnsSubdomainLenThreshold, qname)),
				Match:    qname,
			})
			break
		}
	}

	// Use original-case subdomain for encoding detection.
	encSub := origSub
	if encSub == "" {
		encSub = subdomain
	}

	// Rule 2: Base64-encoded subdomain detection.
	if isBase64Like(encSub) {
		h.append(model.ThreatHit{
			PacketID: packet.ID,
			Category: "dns-tunneling",
			Rule:     dnsTunnelEncodedSubRule,
			Level:    "medium",
			Preview:  previewText(fmt.Sprintf("疑似 Base64 编码子域名: %s", origQname)),
			Match:    origQname,
		})
		if stats != nil {
			stats.encodedHits++
		}
	}

	// Rule 3: Hex-encoded subdomain detection.
	if isHexLike(encSub) {
		h.append(model.ThreatHit{
			PacketID: packet.ID,
			Category: "dns-tunneling",
			Rule:     dnsTunnelEncodedSubRule,
			Level:    "medium",
			Preview:  previewText(fmt.Sprintf("疑似 Hex 编码子域名: %s", origQname)),
			Match:    origQname,
		})
		if stats != nil {
			stats.encodedHits++
		}
	}

	// Rule 4: High-entropy subdomain detection.
	entropy := shannonEntropy(subdomain)
	if stats != nil && entropy > stats.maxEntropy {
		stats.maxEntropy = entropy
	}
	if entropy > dnsEntropyThreshold && len(subdomain) > 20 {
		h.append(model.ThreatHit{
			PacketID: packet.ID,
			Category: "dns-tunneling",
			Rule:     dnsTunnelHighEntropyRule,
			Level:    "medium",
			Preview:  previewText(fmt.Sprintf("子域名熵值 %.2f > %.1f: %s", entropy, dnsEntropyThreshold, qname)),
			Match:    qname,
		})
	}
}

// extractOriginalCaseQueryName extracts the query domain name without lowercasing.
// This preserves the original case for encoding pattern detection.
func extractOriginalCaseQueryName(info string) string {
	matches := dnsQueryNameRE.FindStringSubmatch(info)
	if len(matches) < 2 {
		return ""
	}
	name := strings.TrimSuffix(strings.TrimSpace(matches[1]), ".")
	if name == "" || !strings.Contains(name, ".") {
		return ""
	}
	return name
}

// observeDGA checks a DNS query domain for DGA (Domain Generation Algorithm) characteristics.
// It uses multi-signal analysis: Shannon entropy, domain length, consonant ratio, and digit ratio.
func (h *threatHunter) observeDGA(packet model.Packet, domain string) {
	reasons := isSuspiciousDomain(domain)
	if len(reasons) == 0 {
		return
	}

	level := "medium"
	if len(reasons) >= 3 {
		level = "high"
	}

	h.append(model.ThreatHit{
		PacketID: packet.ID,
		Category: "DGA",
		Rule:     dgaRuleName,
		Level:    level,
		Preview:  previewText(domain + " (" + strings.Join(reasons, ", ") + ")"),
		Match:    domain,
	})
}

// observeDataExfiltration checks a single packet for data exfiltration indicators:
//  1. Large HTTP POST/PUT transfers (packet length > 10 MB)
//  2. Known exfiltration service domain in destination
//  3. DNS exfiltration via long query names (> 100 chars)
func (h *threatHunter) observeDataExfiltration(packet model.Packet) {
	info := strings.ToLower(packet.Info)
	lowerDestIP := strings.ToLower(packet.DestIP)

	// Rule 1: Large HTTP POST/PUT — packet length exceeds threshold and method is POST or PUT.
	if packet.Length >= exfilLargePayloadThreshold {
		if strings.Contains(info, "post") || strings.Contains(info, "put") {
			h.append(model.ThreatHit{
				PacketID: packet.ID,
				Category: "data-exfiltration",
				Rule:     exfilLargeHTTPRule,
				Level:    "high",
				Preview:  previewText(fmt.Sprintf("大文件 HTTP 传输: %d 字节, %s", packet.Length, packet.Info)),
				Match:    packet.DestIP,
			})
		}
	}

	// Rule 2: Known exfiltration service domain match.
	// Check against DestIP (which may contain a hostname) and Info fields.
	for _, domain := range exfilServiceDomains {
		if strings.Contains(lowerDestIP, domain) || strings.Contains(info, domain) {
			h.append(model.ThreatHit{
				PacketID: packet.ID,
				Category: "data-exfiltration",
				Rule:     exfilServiceRule,
				Level:    "high",
				Preview:  previewText(fmt.Sprintf("匹配已知外泄服务 %s: %s", domain, packet.Info)),
				Match:    domain,
			})
			break // one hit per packet is enough
		}
	}

	// Rule 3: DNS exfiltration — long DNS query name (> 100 chars).
	if isDNSPacket(packet) {
		qname := extractDNSQueryName(packet.Info)
		if len(qname) > exfilDNSQueryLenThreshold {
			h.append(model.ThreatHit{
				PacketID: packet.ID,
				Category: "data-exfiltration",
				Rule:     exfilDNSQueryRule,
				Level:    "high",
				Preview:  previewText(fmt.Sprintf("长 DNS 查询（%d 字符）: %s", len(qname), qname)),
				Match:    qname,
			})
		}
	}
}

// isDNSPacket returns true if the packet is a DNS packet.
func isDNSPacket(packet model.Packet) bool {
	return strings.Contains(strings.ToUpper(packet.Protocol), "DNS") || packet.DestPort == 53 || packet.SourcePort == 53
}

func (h *threatHunter) Results() []model.ThreatHit {
	ips := make([]string, 0, len(h.statusCounter))
	for ip, count := range h.statusCounter {
		if count >= 8 {
			ips = append(ips, ip)
		}
	}
	sort.Strings(ips)
	for _, ip := range ips {
		h.append(model.ThreatHit{
			PacketID: 0,
			Category: "Anomaly",
			Rule:     streamAnomalyRuleName,
			Level:    "medium",
			Preview:  streamAnomalyPreview,
			Match:    ip,
		})
	}

	// DNS tunneling: frequency-based detection aggregated across all observed packets.
	domains := make([]string, 0, len(h.dnsStats))
	for domain := range h.dnsStats {
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	for _, domain := range domains {
		stats := h.dnsStats[domain]
		if stats.queryCount < dnsHighFreqThreshold {
			continue
		}
		uniqueSubs := len(stats.subdomains)
		var avgSubLen float64
		if uniqueSubs > 0 {
			avgSubLen = float64(stats.totalSubLen) / float64(uniqueSubs)
		}
		h.append(model.ThreatHit{
			PacketID: stats.firstPacket,
			Category: "dns-tunneling",
			Rule:     dnsTunnelHighFreqRule,
			Level:    "high",
			Preview: fmt.Sprintf(
				"域名 %s 在 %d 次查询中有 %d 个唯一子域名，平均子域名长度 %.1f",
				domain, stats.queryCount, uniqueSubs, avgSubLen),
			Match: domain,
		})
	}

	// Brute force detection: Rule 1 — same IP high-frequency auth failures.
	bfIPs := make([]string, 0, len(h.authFailByIP))
	for ip, count := range h.authFailByIP {
		if count >= bruteForceIPThreshold {
			bfIPs = append(bfIPs, ip)
		}
	}
	sort.Strings(bfIPs)
	for _, ip := range bfIPs {
		h.append(model.ThreatHit{
			PacketID: 0,
			Category: "brute-force",
			Rule:     bruteForceIPRule,
			Level:    "high",
			Preview:  fmt.Sprintf("IP %s 短时间内出现 %d 次 401/403 认证失败", ip, h.authFailByIP[ip]),
			Match:    ip,
		})
	}

	// Brute force detection: Rule 2 — credential stuffing (multiple IPs hitting same target).
	targetKeys := make([]string, 0, len(h.authFailByTarget))
	for key := range h.authFailByTarget {
		targetKeys = append(targetKeys, key)
	}
	sort.Strings(targetKeys)
	for _, key := range targetKeys {
		srcIPs := h.authFailByTarget[key]
		if len(srcIPs) >= bruteForceTargetIPThreshold {
			h.append(model.ThreatHit{
				PacketID: 0,
				Category: "brute-force",
				Rule:     bruteForceCredentialRule,
				Level:    "high",
				Preview:  fmt.Sprintf("%d 个不同源 IP 尝试访问 %s，疑似凭据填充攻击", len(srcIPs), key),
				Match:    key,
			})
		}
	}

	// Brute force detection: Rule 3 — 401/403 anomaly burst.
	if h.authFailTotal >= bruteForceIPThreshold*2 {
		h.append(model.ThreatHit{
			PacketID: 0,
			Category: "brute-force",
			Rule:     bruteForceAnomalyRule,
			Level:    "high",
			Preview:  fmt.Sprintf("短时间内出现 %d 次 401/403 响应，认证异常激增", h.authFailTotal),
			Match:    fmt.Sprintf("total=%d", h.authFailTotal),
		})
	}

	out := make([]model.ThreatHit, len(h.hits))
	copy(out, h.hits)
	return out
}

func (h *threatHunter) append(hit model.ThreatHit) {
	hit.ID = h.nextID
	h.nextID++
	h.hits = append(h.hits, hit)
}

func detectLegacyRuleName(fn func() []model.ThreatHit, fallback string) string {
	hits := fn()
	if len(hits) == 0 || strings.TrimSpace(hits[0].Rule) == "" {
		return fallback
	}
	return hits[0].Rule
}

func detectLegacyPreview(fn func() []model.ThreatHit, fallback string) string {
	hits := fn()
	if len(hits) == 0 || strings.TrimSpace(hits[0].Preview) == "" {
		return fallback
	}
	return hits[0].Preview
}

func make404Packets() []model.Packet {
	packets := make([]model.Packet, 0, 8)
	for i := 0; i < 8; i++ {
		packets = append(packets, model.Packet{
			ID:       int64(i + 1),
			Info:     "HTTP 404 Not Found",
			SourceIP: "192.0.2.10",
			Protocol: "HTTP",
			DestPort: 80,
		})
	}
	return packets
}

// DetectDNSTunneling performs DNS tunneling detection on a slice of packets.
// It identifies high-frequency subdomain queries, long subdomains,
// Base64/Hex-encoded subdomains, and high-entropy subdomains.
func DetectDNSTunneling(packets []model.Packet) []model.ThreatHit {
	h := newThreatHunter(nil, 1)
	for _, pkt := range packets {
		h.observeDNSTunnel(pkt)
	}
	return h.Results()
}

// DetectDataExfiltration performs data exfiltration detection on a slice of packets.
// It identifies large HTTP POST/PUT transfers, known exfiltration service domains,
// and DNS-based exfiltration via long query names.
func DetectDataExfiltration(packets []model.Packet) []model.ThreatHit {
	h := newThreatHunter(nil, 1)
	for _, pkt := range packets {
		h.observeDataExfiltration(pkt)
	}
	return h.Results()
}

// DetectBruteForce performs brute force detection on a slice of packets.
// It identifies single-IP high-frequency auth failures, credential stuffing
// (multiple IPs targeting same host), and 401/403 anomaly bursts.
func DetectBruteForce(packets []model.Packet) []model.ThreatHit {
	h := newThreatHunter(nil, 1)
	for _, pkt := range packets {
		h.observeBruteForce(pkt)
	}
	return h.Results()
}

// observeBruteForce checks a single packet for brute force indicators.
func (h *threatHunter) observeBruteForce(packet model.Packet) {
	info := strings.ToLower(packet.Info)
	if strings.Contains(info, " 401") || strings.Contains(info, " 403") {
		h.authFailByIP[packet.SourceIP]++
		h.authFailTotal++
		targetKey := packet.DestIP + ":" + fmt.Sprint(packet.DestPort)
		if h.authFailByTarget[targetKey] == nil {
			h.authFailByTarget[targetKey] = make(map[string]struct{})
		}
		h.authFailByTarget[targetKey][packet.SourceIP] = struct{}{}
	}
}

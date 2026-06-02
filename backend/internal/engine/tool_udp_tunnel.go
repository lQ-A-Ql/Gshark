package engine

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

var dnsQueryNameRE = regexp.MustCompile(`(?i)(?:Standard query|query)\s+(?:0x[0-9a-fA-F]+\s+)?(?:[A-Z]+\s+)?(\S+)`)

func (s *Service) UDPTunnelAnalysis(ctx context.Context) (model.UDPTunnelAnalysis, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if s.CurrentCapturePath() == "" {
		return model.UDPTunnelAnalysis{}, fmt.Errorf("当前未加载抓包，请先导入 pcapng 文件")
	}
	if s.packetStore == nil {
		return model.UDPTunnelAnalysis{}, fmt.Errorf("当前抓包尚未建立本地数据包索引")
	}
	packets, err := s.packetStore.All(nil)
	if err != nil {
		return model.UDPTunnelAnalysis{}, err
	}
	return buildUDPTunnelAnalysis(ctx, packets)
}

type dnsQueryGroup struct {
	baseDomain  string
	queryCount  int
	subdomains  map[string]struct{}
	totalSubLen int
	maxPayload  int
	firstPacket int64
}

type udpSessionKey struct {
	src  string
	dst  string
	port int
}

type udpSessionGroup struct {
	key         udpSessionKey
	packetCount int
	bytesTotal  int
	payloads    []int
	firstPacket int64
	firstTime   string
	lastTime    string
}

func buildUDPTunnelAnalysis(ctx context.Context, packets []model.Packet) (model.UDPTunnelAnalysis, error) {
	result := model.UDPTunnelAnalysis{
		DNSTunnelHits: []model.DNSTunnelCandidate{},
		UDPTunnelHits: []model.UDPTunnelCandidate{},
		Notes:         []string{},
	}

	dnsGroups := make(map[string]*dnsQueryGroup)
	udpSessions := make(map[udpSessionKey]*udpSessionGroup)

	for _, packet := range packets {
		if err := ctx.Err(); err != nil {
			return model.UDPTunnelAnalysis{}, err
		}

		proto := strings.ToUpper(packet.Protocol)

		// Collect DNS queries
		if strings.Contains(proto, "DNS") {
			qname := extractDNSQueryName(packet.Info)
			if qname == "" {
				continue
			}
			base := baseDomain(qname)
			if base == "" {
				continue
			}
			group := dnsGroups[base]
			if group == nil {
				group = &dnsQueryGroup{
					baseDomain:  base,
					subdomains:  make(map[string]struct{}),
					firstPacket: packet.ID,
				}
				dnsGroups[base] = group
			}
			group.queryCount++
			subdomain := extractSubdomain(qname, base)
			if subdomain != "" {
				group.subdomains[subdomain] = struct{}{}
				group.totalSubLen += len(subdomain)
			}
			if packet.Length > group.maxPayload {
				group.maxPayload = packet.Length
			}
			continue
		}

		// Collect UDP sessions
		if proto == "UDP" || packet.UDPPayloadHex != "" {
			if packet.SourceIP == "" || packet.DestIP == "" {
				continue
			}
			key := udpSessionKey{src: packet.SourceIP, dst: packet.DestIP, port: packet.DestPort}
			session := udpSessions[key]
			if session == nil {
				session = &udpSessionGroup{
					key:         key,
					firstPacket: packet.ID,
					firstTime:   packet.Timestamp,
				}
				udpSessions[key] = session
			}
			session.packetCount++
			session.bytesTotal += packet.Length
			session.payloads = append(session.payloads, packet.Length)
			session.lastTime = packet.Timestamp
		}
	}

	// Analyze DNS groups for tunneling
	for _, group := range dnsGroups {
		if group.queryCount <= 50 {
			continue
		}
		uniqueSubs := len(group.subdomains)
		var avgSubLen float64
		if uniqueSubs > 0 {
			avgSubLen = float64(group.totalSubLen) / float64(uniqueSubs)
		}

		// Calculate entropy across all subdomain characters
		allSubChars := ""
		for sub := range group.subdomains {
			allSubChars += sub
		}
		entropy := shannonEntropy(allSubChars)

		flagged := entropy > 3.5 || avgSubLen > 20 || group.maxPayload > 200
		if !flagged {
			continue
		}

		confidence := 40
		if entropy > 4.0 {
			confidence = 80
		} else if entropy > 3.5 {
			confidence = 60
		}

		evidence := fmt.Sprintf("base=%s queries=%d unique_subs=%d entropy=%.2f avg_sub_len=%.1f max_payload=%d",
			group.baseDomain, group.queryCount, uniqueSubs, entropy, avgSubLen, group.maxPayload)

		result.DNSTunnelHits = append(result.DNSTunnelHits, model.DNSTunnelCandidate{
			BaseDomain:       group.baseDomain,
			QueryCount:       group.queryCount,
			UniqueSubdomains: uniqueSubs,
			AvgSubdomainLen:  avgSubLen,
			MaxPayloadSize:   group.maxPayload,
			EntropyScore:     entropy,
			Confidence:       confidence,
			FirstPacketID:    group.firstPacket,
			Evidence:         evidence,
		})
	}

	// Analyze UDP sessions for tunneling
	for _, session := range udpSessions {
		if session.packetCount <= 100 {
			continue
		}
		avg := float64(session.bytesTotal) / float64(session.packetCount)
		if avg <= 50 {
			continue
		}
		stddev := calcStdDev(session.payloads, avg)
		if avg == 0 {
			continue
		}
		uniformity := stddev / avg
		if uniformity >= 0.2 {
			continue
		}

		confidence := 50
		if session.packetCount > 500 && uniformity < 0.1 {
			confidence = 90
		} else if session.packetCount > 200 && uniformity < 0.15 {
			confidence = 70
		}

		duration := estimateDurationSec(session.firstTime, session.lastTime)

		result.UDPTunnelHits = append(result.UDPTunnelHits, model.UDPTunnelCandidate{
			Source:        session.key.src,
			Destination:   session.key.dst,
			Port:          session.key.port,
			PacketCount:   session.packetCount,
			BytesTotal:    session.bytesTotal,
			AvgPayloadLen: avg,
			StdDevLen:     stddev,
			DurationSec:   duration,
			Confidence:    confidence,
			FirstPacketID: session.firstPacket,
			Protocol:      "UDP",
		})
	}

	// Sort by confidence descending
	sort.SliceStable(result.DNSTunnelHits, func(i, j int) bool {
		return result.DNSTunnelHits[i].Confidence > result.DNSTunnelHits[j].Confidence
	})
	sort.SliceStable(result.UDPTunnelHits, func(i, j int) bool {
		return result.UDPTunnelHits[i].Confidence > result.UDPTunnelHits[j].Confidence
	})

	result.TotalSuspicious = len(result.DNSTunnelHits) + len(result.UDPTunnelHits)
	result.Notes = buildUDPTunnelNotes(result)
	return result, nil
}

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}
	length := float64(len([]rune(s)))
	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

func extractDNSQueryName(info string) string {
	matches := dnsQueryNameRE.FindStringSubmatch(info)
	if len(matches) < 2 {
		return ""
	}
	name := strings.TrimSuffix(strings.TrimSpace(matches[1]), ".")
	if name == "" || !strings.Contains(name, ".") {
		return ""
	}
	return strings.ToLower(name)
}

func baseDomain(fqdn string) string {
	parts := strings.Split(fqdn, ".")
	if len(parts) < 2 {
		return ""
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

func extractSubdomain(fqdn, base string) string {
	if !strings.HasSuffix(fqdn, base) {
		return ""
	}
	sub := strings.TrimSuffix(fqdn, "."+base)
	if sub == fqdn || sub == "" {
		return ""
	}
	return sub
}

func calcStdDev(values []int, mean float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sumSq := 0.0
	for _, v := range values {
		diff := float64(v) - mean
		sumSq += diff * diff
	}
	return math.Sqrt(sumSq / float64(len(values)))
}

func estimateDurationSec(first, last string) float64 {
	// Timestamps are typically formatted as relative seconds or absolute times.
	// Attempt a simple numeric parse for relative timestamps (e.g. "1.234567").
	if first == "" || last == "" || first == last {
		return 0
	}
	var t1, t2 float64
	if _, err := fmt.Sscanf(first, "%f", &t1); err != nil {
		return 0
	}
	if _, err := fmt.Sscanf(last, "%f", &t2); err != nil {
		return 0
	}
	d := t2 - t1
	if d < 0 {
		d = -d
	}
	return d
}

func buildUDPTunnelNotes(result model.UDPTunnelAnalysis) []string {
	notes := make([]string, 0, 4)
	if result.TotalSuspicious == 0 {
		return []string{"当前抓包中未识别到明显的 UDP 隧道行为。"}
	}
	if len(result.DNSTunnelHits) > 0 {
		notes = append(notes, fmt.Sprintf("发现 %d 个疑似 DNS 隧道域名，建议检查子域名编码模式和流量频率。", len(result.DNSTunnelHits)))
	}
	if len(result.UDPTunnelHits) > 0 {
		notes = append(notes, fmt.Sprintf("发现 %d 个疑似 UDP 隧道会话，载荷长度均匀度异常。", len(result.UDPTunnelHits)))
	}
	return notes
}

package engine

import (
	"encoding/base64"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

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
)

type threatHunter struct {
	prefixes      []string
	encoded       []string
	hexEncoded    []string
	hits          []model.ThreatHit
	nextID        int64
	statusCounter map[string]int
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
		prefixes:      normalized,
		encoded:       encoded,
		hexEncoded:    hexEncoded,
		nextID:        startID,
		statusCounter: map[string]int{},
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

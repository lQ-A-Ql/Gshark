package engine

import (
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

// IOCIndex holds IOC entries indexed for O(1) lookup by type and value.
type IOCIndex struct {
	ipSet         map[string][]model.IOCEntry
	domainSet     map[string][]model.IOCEntry
	hashMD5Set    map[string][]model.IOCEntry
	hashSHA1Set   map[string][]model.IOCEntry
	hashSHA256Set map[string][]model.IOCEntry
	urlSet        map[string][]model.IOCEntry
	allEntries    []model.IOCEntry
	feeds         map[string]model.IOCFeed
}

// NewIOCIndex creates an empty IOCIndex.
func NewIOCIndex() *IOCIndex {
	return &IOCIndex{
		ipSet:         make(map[string][]model.IOCEntry),
		domainSet:     make(map[string][]model.IOCEntry),
		hashMD5Set:    make(map[string][]model.IOCEntry),
		hashSHA1Set:   make(map[string][]model.IOCEntry),
		hashSHA256Set: make(map[string][]model.IOCEntry),
		urlSet:        make(map[string][]model.IOCEntry),
		feeds:         make(map[string]model.IOCFeed),
	}
}

// AddFeed registers a feed in the index.
func (idx *IOCIndex) AddFeed(feed model.IOCFeed) {
	idx.feeds[feed.ID] = feed
}

// AddEntries indexes a slice of IOC entries for fast lookup.
func (idx *IOCIndex) AddEntries(entries []model.IOCEntry) {
	for _, entry := range entries {
		idx.addEntry(entry)
	}
}

func (idx *IOCIndex) addEntry(entry model.IOCEntry) {
	value := strings.TrimSpace(entry.Value)
	if value == "" {
		return
	}
	idx.allEntries = append(idx.allEntries, entry)

	switch entry.Type {
	case model.IOCTypeIP:
		if ip := normalizeIP(value); ip != "" {
			idx.ipSet[ip] = append(idx.ipSet[ip], entry)
		}
	case model.IOCTypeDomain:
		domain := strings.ToLower(strings.TrimSpace(value))
		domain = strings.TrimSuffix(domain, ".")
		if domain != "" {
			idx.domainSet[domain] = append(idx.domainSet[domain], entry)
		}
	case model.IOCTypeHashMD5:
		if h := normalizeHash(value, 32); h != "" {
			idx.hashMD5Set[h] = append(idx.hashMD5Set[h], entry)
		}
	case model.IOCTypeHashSHA1:
		if h := normalizeHash(value, 40); h != "" {
			idx.hashSHA1Set[h] = append(idx.hashSHA1Set[h], entry)
		}
	case model.IOCTypeHashSHA256:
		if h := normalizeHash(value, 64); h != "" {
			idx.hashSHA256Set[h] = append(idx.hashSHA256Set[h], entry)
		}
	case model.IOCTypeURL:
		if u := normalizeURL(value); u != "" {
			idx.urlSet[u] = append(idx.urlSet[u], entry)
		}
	}
}

// EntryCount returns the total number of indexed entries.
func (idx *IOCIndex) EntryCount() int {
	return len(idx.allEntries)
}

// FeedCount returns the number of registered feeds.
func (idx *IOCIndex) FeedCount() int {
	return len(idx.feeds)
}

// Clear removes all entries and feeds from the index.
func (idx *IOCIndex) Clear() {
	idx.ipSet = make(map[string][]model.IOCEntry)
	idx.domainSet = make(map[string][]model.IOCEntry)
	idx.hashMD5Set = make(map[string][]model.IOCEntry)
	idx.hashSHA1Set = make(map[string][]model.IOCEntry)
	idx.hashSHA256Set = make(map[string][]model.IOCEntry)
	idx.urlSet = make(map[string][]model.IOCEntry)
	idx.allEntries = nil
	idx.feeds = make(map[string]model.IOCFeed)
}

// MatchPackets scans packets against the IOC index and returns all matches.
func MatchPackets(packets []model.Packet, idx *IOCIndex) []model.IOCMatchResult {
	if idx == nil || len(packets) == 0 {
		return nil
	}
	var results []model.IOCMatchResult
	for _, pkt := range packets {
		results = append(results, matchPacket(pkt, idx)...)
	}
	return results
}

// MatchPacketsSummary scans packets and returns a summary with aggregated counts.
func MatchPacketsSummary(packets []model.Packet, idx *IOCIndex) model.IOCMatchSummary {
	matches := MatchPackets(packets, idx)
	summary := model.IOCMatchSummary{
		TotalPackets: len(packets),
		ByType:       make(map[string]int),
		BySeverity:   make(map[string]int),
		ByFeed:       make(map[string]int),
		Matches:      matches,
	}
	summary.TotalMatches = len(matches)

	matchedPackets := make(map[int64]struct{})
	for _, m := range matches {
		matchedPackets[m.PacketID] = struct{}{}
		summary.ByType[m.IOCType]++
		if m.Severity != "" {
			summary.BySeverity[m.Severity]++
		}
		if m.FeedID != "" {
			summary.ByFeed[m.FeedID]++
		}
	}
	summary.MatchedPackets = len(matchedPackets)
	return summary
}

// MatchPacketsAsThreatHits converts IOC matches into ThreatHit entries for integration
// with the existing threat hunting pipeline.
func MatchPacketsAsThreatHits(packets []model.Packet, idx *IOCIndex) []model.ThreatHit {
	if idx == nil {
		return nil
	}
	matches := MatchPackets(packets, idx)
	hits := make([]model.ThreatHit, 0, len(matches))
	var seq int64 = 1
	for _, m := range matches {
		level := iocSeverityToLevel(m.Severity)
		rule := "IOC Match: " + m.IOCType
		if m.FeedName != "" {
			rule = "IOC Match [" + m.FeedName + "]: " + m.IOCType
		}
		hits = append(hits, model.ThreatHit{
			ID:       seq,
			PacketID: m.PacketID,
			Category: "IOC",
			Rule:     rule,
			Level:    level,
			Preview:  iocMatchPreview(m),
			Match:    m.IOCValue,
		})
		seq++
	}
	return hits
}

func matchPacket(pkt model.Packet, idx *IOCIndex) []model.IOCMatchResult {
	var results []model.IOCMatchResult

	// 1. IP matching: SourceIP and DestIP.
	for _, ip := range []string{pkt.SourceIP, pkt.DestIP} {
		normalized := normalizeIP(ip)
		if normalized == "" {
			continue
		}
		if entries, ok := idx.ipSet[normalized]; ok {
			for _, entry := range entries {
				matchField := "source_ip"
				if ip == pkt.DestIP {
					matchField = "dest_ip"
				}
				results = append(results, iocMatchFromEntry(pkt.ID, entry, matchField, ip, idx))
			}
		}
	}

	// Gather text fields for domain/hash/URL matching.
	text := strings.ToLower(pkt.Info + "\n" + pkt.Payload)

	// 2. Domain matching: check Info and Payload for domain occurrences.
	if len(idx.domainSet) > 0 {
		for domain, entries := range idx.domainSet {
			if strings.Contains(text, domain) {
				for _, entry := range entries {
					results = append(results, iocMatchFromEntry(pkt.ID, entry, "info/payload", domain, idx))
				}
			}
		}
	}

	// 3. Hash matching: extract hex strings of known lengths from packet text.
	if len(idx.hashMD5Set) > 0 || len(idx.hashSHA1Set) > 0 || len(idx.hashSHA256Set) > 0 {
		results = append(results, matchHashes(pkt, text, idx)...)
	}

	// 4. URL matching: check for URL substrings in Info and Payload.
	if len(idx.urlSet) > 0 {
		for iocURL, entries := range idx.urlSet {
			if strings.Contains(text, iocURL) {
				for _, entry := range entries {
					results = append(results, iocMatchFromEntry(pkt.ID, entry, "info/payload", iocURL, idx))
				}
			}
		}
	}

	return results
}

// hex32RE matches 32-char hex strings (MD5).
var hex32RE = regexp.MustCompile(`(?i)\b[0-9a-f]{32}\b`)

// hex40RE matches 40-char hex strings (SHA1).
var hex40RE = regexp.MustCompile(`(?i)\b[0-9a-f]{40}\b`)

// hex64RE matches 64-char hex strings (SHA256).
var hex64RE = regexp.MustCompile(`(?i)\b[0-9a-f]{64}\b`)

func matchHashes(pkt model.Packet, text string, idx *IOCIndex) []model.IOCMatchResult {
	var results []model.IOCMatchResult
	lowerText := strings.ToLower(text)

	// MD5 (32 hex chars).
	if len(idx.hashMD5Set) > 0 {
		for _, match := range hex32RE.FindAllString(lowerText, -1) {
			if entries, ok := idx.hashMD5Set[match]; ok {
				for _, entry := range entries {
					results = append(results, iocMatchFromEntry(pkt.ID, entry, "payload_hash", match, idx))
				}
			}
		}
	}

	// SHA1 (40 hex chars).
	if len(idx.hashSHA1Set) > 0 {
		for _, match := range hex40RE.FindAllString(lowerText, -1) {
			if entries, ok := idx.hashSHA1Set[match]; ok {
				for _, entry := range entries {
					results = append(results, iocMatchFromEntry(pkt.ID, entry, "payload_hash", match, idx))
				}
			}
		}
	}

	// SHA256 (64 hex chars).
	if len(idx.hashSHA256Set) > 0 {
		for _, match := range hex64RE.FindAllString(lowerText, -1) {
			if entries, ok := idx.hashSHA256Set[match]; ok {
				for _, entry := range entries {
					results = append(results, iocMatchFromEntry(pkt.ID, entry, "payload_hash", match, idx))
				}
			}
		}
	}

	return results
}

func iocMatchFromEntry(packetID int64, entry model.IOCEntry, matchField, matchValue string, idx *IOCIndex) model.IOCMatchResult {
	result := model.IOCMatchResult{
		PacketID:    packetID,
		IOCType:     entry.Type,
		IOCValue:    entry.Value,
		MatchField:  matchField,
		MatchValue:  matchValue,
		FeedID:      entry.FeedID,
		Severity:    entry.Severity,
		Confidence:  entry.Confidence,
		Tags:        entry.Tags,
		Description: entry.Description,
	}
	if feed, ok := idx.feeds[entry.FeedID]; ok {
		result.FeedName = feed.Name
	}
	if result.Severity == "" {
		result.Severity = "medium"
	}
	return result
}

func iocSeverityToLevel(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return "medium"
	}
}

func iocMatchPreview(m model.IOCMatchResult) string {
	var b strings.Builder
	b.WriteString("IOC 命中: ")
	b.WriteString(m.IOCValue)
	if m.FeedName != "" {
		b.WriteString(" (来源: ")
		b.WriteString(m.FeedName)
		b.WriteString(")")
	}
	if m.Description != "" {
		b.WriteString(" — ")
		b.WriteString(m.Description)
	}
	s := b.String()
	if len(s) > 120 {
		return s[:120]
	}
	return s
}

// normalizeIP parses an IP string and returns its normalized form.
func normalizeIP(s string) string {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return ""
	}
	return ip.String()
}

// normalizeHash lowercases and validates hex string of expected length.
func normalizeHash(s string, expectedLen int) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if len(s) != expectedLen {
		return ""
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return ""
		}
	}
	return s
}

// normalizeURL extracts the scheme+host+path for substring matching.
func normalizeURL(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	// Try full URL parse.
	u, err := url.Parse(s)
	if err == nil && u.Host != "" {
		// Return lowercase scheme+host+path for matching.
		return strings.ToLower(u.Scheme + "://" + u.Host + u.Path)
	}
	// Fallback: just lowercase it.
	return strings.ToLower(s)
}

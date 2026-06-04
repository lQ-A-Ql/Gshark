package engine

import (
	"strings"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

// ─── IOC Index Tests ─────────────────────────────────────────────────────────

func TestIOCIndex_AddEntries_IP(t *testing.T) {
	idx := NewIOCIndex()
	idx.AddEntries([]model.IOCEntry{
		{ID: "1", FeedID: "f1", Type: model.IOCTypeIP, Value: "192.168.1.100", Severity: "high"},
		{ID: "2", FeedID: "f1", Type: model.IOCTypeIP, Value: "10.0.0.1", Severity: "medium"},
	})
	if idx.EntryCount() != 2 {
		t.Fatalf("expected 2 entries, got %d", idx.EntryCount())
	}
	if _, ok := idx.ipSet["192.168.1.100"]; !ok {
		t.Fatal("expected IP 192.168.1.100 in index")
	}
}

func TestIOCIndex_AddEntries_Domain(t *testing.T) {
	idx := NewIOCIndex()
	idx.AddEntries([]model.IOCEntry{
		{ID: "1", FeedID: "f1", Type: model.IOCTypeDomain, Value: "evil.com", Severity: "high"},
		{ID: "2", FeedID: "f1", Type: model.IOCTypeDomain, Value: "malware.net.", Severity: "medium"},
	})
	if idx.EntryCount() != 2 {
		t.Fatalf("expected 2 entries, got %d", idx.EntryCount())
	}
	if _, ok := idx.domainSet["evil.com"]; !ok {
		t.Fatal("expected domain evil.com in index")
	}
	if _, ok := idx.domainSet["malware.net"]; !ok {
		t.Fatal("expected domain malware.net in index (trailing dot stripped)")
	}
}

func TestIOCIndex_AddEntries_Hash(t *testing.T) {
	idx := NewIOCIndex()
	md5 := "d41d8cd98f00b204e9800998ecf8427e"
	sha1 := "da39a3ee5e6b4b0d3255bfef95601890afd80709"
	sha256 := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	idx.AddEntries([]model.IOCEntry{
		{ID: "1", FeedID: "f1", Type: model.IOCTypeHashMD5, Value: md5},
		{ID: "2", FeedID: "f1", Type: model.IOCTypeHashSHA1, Value: sha1},
		{ID: "3", FeedID: "f1", Type: model.IOCTypeHashSHA256, Value: sha256},
	})
	if idx.EntryCount() != 3 {
		t.Fatalf("expected 3 entries, got %d", idx.EntryCount())
	}
	if _, ok := idx.hashMD5Set[md5]; !ok {
		t.Fatal("expected MD5 hash in index")
	}
	if _, ok := idx.hashSHA1Set[sha1]; !ok {
		t.Fatal("expected SHA1 hash in index")
	}
	if _, ok := idx.hashSHA256Set[sha256]; !ok {
		t.Fatal("expected SHA256 hash in index")
	}
}

func TestIOCIndex_AddEntries_URL(t *testing.T) {
	idx := NewIOCIndex()
	idx.AddEntries([]model.IOCEntry{
		{ID: "1", FeedID: "f1", Type: model.IOCTypeURL, Value: "http://evil.com/malware.exe"},
	})
	if idx.EntryCount() != 1 {
		t.Fatalf("expected 1 entry, got %d", idx.EntryCount())
	}
	if _, ok := idx.urlSet["http://evil.com/malware.exe"]; !ok {
		t.Fatal("expected URL in index")
	}
}

func TestIOCIndex_Clear(t *testing.T) {
	idx := NewIOCIndex()
	idx.AddFeed(model.IOCFeed{ID: "f1", Name: "test"})
	idx.AddEntries([]model.IOCEntry{
		{ID: "1", FeedID: "f1", Type: model.IOCTypeIP, Value: "1.2.3.4"},
	})
	idx.Clear()
	if idx.EntryCount() != 0 {
		t.Fatalf("expected 0 entries after clear, got %d", idx.EntryCount())
	}
	if idx.FeedCount() != 0 {
		t.Fatalf("expected 0 feeds after clear, got %d", idx.FeedCount())
	}
}

// ─── MatchPackets Tests ──────────────────────────────────────────────────────

func TestMatchPackets_IP(t *testing.T) {
	idx := NewIOCIndex()
	idx.AddFeed(model.IOCFeed{ID: "f1", Name: "TestFeed"})
	idx.AddEntries([]model.IOCEntry{
		{ID: "1", FeedID: "f1", Type: model.IOCTypeIP, Value: "192.168.1.100", Severity: "high", Description: "Known C2"},
	})

	packets := []model.Packet{
		{ID: 1, SourceIP: "192.168.1.100", DestIP: "10.0.0.1", Info: "TCP SYN"},
		{ID: 2, SourceIP: "10.0.0.2", DestIP: "192.168.1.100", Info: "TCP ACK"},
		{ID: 3, SourceIP: "10.0.0.2", DestIP: "10.0.0.3", Info: "TCP SYN"}, // no match
	}

	matches := MatchPackets(packets, idx)
	if len(matches) != 2 {
		t.Fatalf("expected 2 matches, got %d", len(matches))
	}
	if matches[0].PacketID != 1 || matches[0].MatchField != "source_ip" {
		t.Errorf("match 0: expected packet 1 source_ip, got packet %d field %s", matches[0].PacketID, matches[0].MatchField)
	}
	if matches[1].PacketID != 2 || matches[1].MatchField != "dest_ip" {
		t.Errorf("match 1: expected packet 2 dest_ip, got packet %d field %s", matches[1].PacketID, matches[1].MatchField)
	}
	if matches[0].FeedName != "TestFeed" {
		t.Errorf("expected FeedName 'TestFeed', got %q", matches[0].FeedName)
	}
}

func TestMatchPackets_Domain(t *testing.T) {
	idx := NewIOCIndex()
	idx.AddEntries([]model.IOCEntry{
		{ID: "1", FeedID: "f1", Type: model.IOCTypeDomain, Value: "evil.com", Severity: "high"},
	})

	packets := []model.Packet{
		{ID: 1, Info: "HTTP GET /index.html", Payload: "Host: evil.com", DestIP: "1.2.3.4"},
		{ID: 2, Info: "DNS query good.com", DestIP: "8.8.8.8"}, // no match
	}

	matches := MatchPackets(packets, idx)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].PacketID != 1 {
		t.Errorf("expected packet 1, got %d", matches[0].PacketID)
	}
}

func TestMatchPackets_Hash(t *testing.T) {
	idx := NewIOCIndex()
	md5 := "d41d8cd98f00b204e9800998ecf8427e"
	idx.AddEntries([]model.IOCEntry{
		{ID: "1", FeedID: "f1", Type: model.IOCTypeHashMD5, Value: md5, Severity: "critical"},
	})

	packets := []model.Packet{
		{ID: 1, Info: "File download", Payload: "hash=" + md5, DestIP: "1.2.3.4"},
		{ID: 2, Info: "Normal traffic", Payload: "some data", DestIP: "1.2.3.4"}, // no match
	}

	matches := MatchPackets(packets, idx)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].IOCType != model.IOCTypeHashMD5 {
		t.Errorf("expected hash_md5, got %s", matches[0].IOCType)
	}
}

func TestMatchPackets_URL(t *testing.T) {
	idx := NewIOCIndex()
	idx.AddEntries([]model.IOCEntry{
		{ID: "1", FeedID: "f1", Type: model.IOCTypeURL, Value: "http://evil.com/payload.bin", Severity: "high"},
	})

	packets := []model.Packet{
		{ID: 1, Info: "GET http://evil.com/payload.bin HTTP/1.1", DestIP: "1.2.3.4"},
		{ID: 2, Info: "GET http://good.com/index.html HTTP/1.1", DestIP: "1.2.3.4"}, // no match
	}

	matches := MatchPackets(packets, idx)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
}

func TestMatchPackets_NoMatch(t *testing.T) {
	idx := NewIOCIndex()
	idx.AddEntries([]model.IOCEntry{
		{ID: "1", FeedID: "f1", Type: model.IOCTypeIP, Value: "1.2.3.4"},
	})

	packets := []model.Packet{
		{ID: 1, SourceIP: "10.0.0.1", DestIP: "10.0.0.2", Info: "TCP"},
	}

	matches := MatchPackets(packets, idx)
	if len(matches) != 0 {
		t.Fatalf("expected 0 matches, got %d", len(matches))
	}
}

func TestMatchPackets_NilIndex(t *testing.T) {
	packets := []model.Packet{{ID: 1, SourceIP: "1.2.3.4"}}
	matches := MatchPackets(packets, nil)
	if len(matches) != 0 {
		t.Fatalf("expected 0 matches with nil index, got %d", len(matches))
	}
}

func TestMatchPackets_EmptyPackets(t *testing.T) {
	idx := NewIOCIndex()
	idx.AddEntries([]model.IOCEntry{
		{ID: "1", FeedID: "f1", Type: model.IOCTypeIP, Value: "1.2.3.4"},
	})
	matches := MatchPackets(nil, idx)
	if len(matches) != 0 {
		t.Fatalf("expected 0 matches with nil packets, got %d", len(matches))
	}
}

// ─── MatchPacketsSummary Tests ───────────────────────────────────────────────

func TestMatchPacketsSummary(t *testing.T) {
	idx := NewIOCIndex()
	idx.AddFeed(model.IOCFeed{ID: "f1", Name: "Feed1"})
	idx.AddEntries([]model.IOCEntry{
		{ID: "1", FeedID: "f1", Type: model.IOCTypeIP, Value: "1.2.3.4", Severity: "high"},
		{ID: "2", FeedID: "f1", Type: model.IOCTypeDomain, Value: "evil.com", Severity: "medium"},
	})

	packets := []model.Packet{
		{ID: 1, SourceIP: "1.2.3.4", Info: "TCP", DestIP: "10.0.0.1"},
		{ID: 2, Info: "DNS evil.com", DestIP: "8.8.8.8"},
		{ID: 3, SourceIP: "10.0.0.2", Info: "TCP", DestIP: "10.0.0.3"}, // no match
	}

	summary := MatchPacketsSummary(packets, idx)
	if summary.TotalPackets != 3 {
		t.Errorf("expected 3 total packets, got %d", summary.TotalPackets)
	}
	if summary.MatchedPackets != 2 {
		t.Errorf("expected 2 matched packets, got %d", summary.MatchedPackets)
	}
	if summary.TotalMatches != 2 {
		t.Errorf("expected 2 total matches, got %d", summary.TotalMatches)
	}
	if summary.ByType[model.IOCTypeIP] != 1 {
		t.Errorf("expected 1 IP match, got %d", summary.ByType[model.IOCTypeIP])
	}
	if summary.ByType[model.IOCTypeDomain] != 1 {
		t.Errorf("expected 1 domain match, got %d", summary.ByType[model.IOCTypeDomain])
	}
}

// ─── MatchPacketsAsThreatHits Tests ──────────────────────────────────────────

func TestMatchPacketsAsThreatHits(t *testing.T) {
	idx := NewIOCIndex()
	idx.AddFeed(model.IOCFeed{ID: "f1", Name: "ThreatIntel"})
	idx.AddEntries([]model.IOCEntry{
		{ID: "1", FeedID: "f1", Type: model.IOCTypeIP, Value: "1.2.3.4", Severity: "critical"},
	})

	packets := []model.Packet{
		{ID: 1, SourceIP: "1.2.3.4", DestIP: "10.0.0.1", Info: "TCP"},
	}

	hits := MatchPacketsAsThreatHits(packets, idx)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit, got %d", len(hits))
	}
	if hits[0].Category != "IOC" {
		t.Errorf("expected category 'IOC', got %q", hits[0].Category)
	}
	if hits[0].Level != "critical" {
		t.Errorf("expected level 'critical', got %q", hits[0].Level)
	}
	if !strings.Contains(hits[0].Rule, "ThreatIntel") {
		t.Errorf("expected rule to contain 'ThreatIntel', got %q", hits[0].Rule)
	}
	if !strings.Contains(hits[0].Rule, "ip") {
		t.Errorf("expected rule to contain 'ip', got %q", hits[0].Rule)
	}
}

func TestMatchPacketsAsThreatHits_NilIndex(t *testing.T) {
	hits := MatchPacketsAsThreatHits([]model.Packet{{ID: 1}}, nil)
	if hits != nil {
		t.Fatalf("expected nil hits with nil index, got %v", hits)
	}
}

// ─── Import Tests ────────────────────────────────────────────────────────────

func TestImportJSON(t *testing.T) {
	input := `[
		{"type": "ip", "value": "1.2.3.4", "severity": "high", "description": "C2 server"},
		{"type": "domain", "value": "evil.com", "confidence": 90},
		{"type": "hash_md5", "value": "d41d8cd98f00b204e9800998ecf8427e"},
		{"type": "url", "value": "http://malware.net/payload"}
	]`

	entries, err := ImportJSON(strings.NewReader(input), "test-feed")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 4 {
		t.Fatalf("expected 4 entries, got %d", len(entries))
	}
	if entries[0].Type != model.IOCTypeIP || entries[0].Value != "1.2.3.4" {
		t.Errorf("entry 0: expected ip/1.2.3.4, got %s/%s", entries[0].Type, entries[0].Value)
	}
	if entries[1].Type != model.IOCTypeDomain || entries[1].Value != "evil.com" {
		t.Errorf("entry 1: expected domain/evil.com, got %s/%s", entries[1].Type, entries[1].Value)
	}
	if entries[1].Confidence != 90 {
		t.Errorf("entry 1: expected confidence 90, got %d", entries[1].Confidence)
	}
	if entries[0].Severity != "high" {
		t.Errorf("entry 0: expected severity 'high', got %q", entries[0].Severity)
	}
}

func TestImportJSON_EmptyArray(t *testing.T) {
	entries, err := ImportJSON(strings.NewReader(`[]`), "test-feed")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(entries))
	}
}

func TestImportJSON_InvalidJSON(t *testing.T) {
	_, err := ImportJSON(strings.NewReader(`{not json}`), "test-feed")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestImportCSV(t *testing.T) {
	input := `type,value,severity,confidence,tags,description,source
ip,1.2.3.4,high,95,c2;apt,Command and Control server,threat-intel
domain,evil.com,medium,80,,Malware domain,
hash_md5,d41d8cd98f00b204e9800998ecf8427e,critical,,,Empty file hash,virustotal
`

	entries, err := ImportCSV(strings.NewReader(input), "csv-feed")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	if entries[0].Type != model.IOCTypeIP || entries[0].Value != "1.2.3.4" {
		t.Errorf("entry 0: expected ip/1.2.3.4, got %s/%s", entries[0].Type, entries[0].Value)
	}
	if entries[0].Severity != "high" {
		t.Errorf("entry 0: expected severity 'high', got %q", entries[0].Severity)
	}
	if entries[0].Confidence != 95 {
		t.Errorf("entry 0: expected confidence 95, got %d", entries[0].Confidence)
	}
	if len(entries[0].Tags) != 2 || entries[0].Tags[0] != "c2" || entries[0].Tags[1] != "apt" {
		t.Errorf("entry 0: expected tags [c2 apt], got %v", entries[0].Tags)
	}
	if entries[2].Severity != "critical" {
		t.Errorf("entry 2: expected severity 'critical', got %q", entries[2].Severity)
	}
}

func TestImportCSV_NoHeader(t *testing.T) {
	input := `ip,1.2.3.4,high
domain,evil.com,low
`
	entries, err := ImportCSV(strings.NewReader(input), "csv-feed")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
}

func TestImportCSV_EmptyInput(t *testing.T) {
	entries, err := ImportCSV(strings.NewReader(""), "csv-feed")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(entries))
	}
}

func TestImportSTIX(t *testing.T) {
	input := `{
		"type": "bundle",
		"objects": [
			{
				"type": "indicator",
				"id": "indicator--1",
				"name": "Evil IP",
				"pattern": "[ipv4-addr:value = '1.2.3.4']",
				"labels": ["malicious"],
				"confidence": 85,
				"valid_from": "2024-01-01T00:00:00Z"
			},
			{
				"type": "indicator",
				"id": "indicator--2",
				"name": "Evil Domain",
				"pattern": "[domain-name:value = 'evil.com']",
				"labels": ["suspicious"]
			},
			{
				"type": "indicator",
				"id": "indicator--3",
				"name": "Malware Hash",
				"pattern": "[file:hashes.'SHA-256' = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']"
			},
			{
				"type": "indicator",
				"id": "indicator--4",
				"name": "Malware URL",
				"pattern": "[url:value = 'http://evil.com/payload']"
			},
			{
				"type": "malware",
				"id": "malware--1",
				"name": "Should be skipped"
			}
		]
	}`

	entries, err := ImportSTIX(strings.NewReader(input), "stix-feed")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 4 {
		t.Fatalf("expected 4 entries, got %d", len(entries))
	}

	// Check IP entry.
	if entries[0].Type != model.IOCTypeIP || entries[0].Value != "1.2.3.4" {
		t.Errorf("entry 0: expected ip/1.2.3.4, got %s/%s", entries[0].Type, entries[0].Value)
	}
	if entries[0].Severity != "high" {
		t.Errorf("entry 0: expected severity 'high' (from 'malicious' label), got %q", entries[0].Severity)
	}
	if entries[0].Confidence != 85 {
		t.Errorf("entry 0: expected confidence 85, got %d", entries[0].Confidence)
	}

	// Check domain entry.
	if entries[1].Type != model.IOCTypeDomain || entries[1].Value != "evil.com" {
		t.Errorf("entry 1: expected domain/evil.com, got %s/%s", entries[1].Type, entries[1].Value)
	}
	if entries[1].Severity != "medium" {
		t.Errorf("entry 1: expected severity 'medium' (from 'suspicious' label), got %q", entries[1].Severity)
	}

	// Check SHA256 entry.
	if entries[2].Type != model.IOCTypeHashSHA256 {
		t.Errorf("entry 2: expected hash_sha256, got %s", entries[2].Type)
	}

	// Check URL entry.
	if entries[3].Type != model.IOCTypeURL || entries[3].Value != "http://evil.com/payload" {
		t.Errorf("entry 3: expected url/http://evil.com/payload, got %s/%s", entries[3].Type, entries[3].Value)
	}
}

func TestImportSTIX_InvalidJSON(t *testing.T) {
	_, err := ImportSTIX(strings.NewReader(`{not json}`), "stix-feed")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestImportIOCData_UnsupportedFormat(t *testing.T) {
	_, err := ImportIOCData(strings.NewReader(""), "xml", "feed")
	if err == nil {
		t.Fatal("expected error for unsupported format")
	}
}

func TestImportIOCData_RoutesToCorrectParser(t *testing.T) {
	// JSON format.
	jsonInput := `[{"type":"ip","value":"1.2.3.4"}]`
	entries, err := ImportIOCData(strings.NewReader(jsonInput), "json", "f1")
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("json: expected 1 entry, got %d", len(entries))
	}

	// CSV format.
	csvInput := "type,value\nip,5.6.7.8\n"
	entries, err = ImportIOCData(strings.NewReader(csvInput), "csv", "f2")
	if err != nil {
		t.Fatalf("csv: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("csv: expected 1 entry, got %d", len(entries))
	}
}

// ─── IOCCache Tests ─────────────────────────────────────────────────────────

func TestIOCCache_Reload(t *testing.T) {
	cache := NewIOCCache()
	feeds := []model.IOCFeed{
		{ID: "f1", Name: "Feed1"},
		{ID: "f2", Name: "Feed2"},
	}
	entries := []model.IOCEntry{
		{ID: "1", FeedID: "f1", Type: model.IOCTypeIP, Value: "1.2.3.4"},
		{ID: "2", FeedID: "f2", Type: model.IOCTypeDomain, Value: "evil.com"},
	}
	cache.Reload(feeds, entries)

	stats := cache.Stats()
	if stats.FeedCount != 2 {
		t.Errorf("expected 2 feeds, got %d", stats.FeedCount)
	}
	if stats.EntryCount != 2 {
		t.Errorf("expected 2 entries, got %d", stats.EntryCount)
	}
	if stats.IPCount != 1 {
		t.Errorf("expected 1 IP, got %d", stats.IPCount)
	}
	if stats.DomainCount != 1 {
		t.Errorf("expected 1 domain, got %d", stats.DomainCount)
	}
}

func TestIOCCache_RemoveFeed(t *testing.T) {
	cache := NewIOCCache()
	cache.Reload(
		[]model.IOCFeed{
			{ID: "f1", Name: "Feed1"},
			{ID: "f2", Name: "Feed2"},
		},
		[]model.IOCEntry{
			{ID: "1", FeedID: "f1", Type: model.IOCTypeIP, Value: "1.2.3.4"},
			{ID: "2", FeedID: "f2", Type: model.IOCTypeDomain, Value: "evil.com"},
		},
	)

	cache.RemoveFeed("f1")
	stats := cache.Stats()
	if stats.FeedCount != 1 {
		t.Errorf("expected 1 feed after remove, got %d", stats.FeedCount)
	}
	if stats.EntryCount != 1 {
		t.Errorf("expected 1 entry after remove, got %d", stats.EntryCount)
	}
	if stats.IPCount != 0 {
		t.Errorf("expected 0 IPs after remove, got %d", stats.IPCount)
	}
}

// ─── Helper Function Tests ──────────────────────────────────────────────────

func TestNormalizeIP(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"192.168.1.1", "192.168.1.1"},
		{"  10.0.0.1  ", "10.0.0.1"},
		{"::1", "::1"},
		{"invalid", ""},
		{"", ""},
		{"999.999.999.999", ""},
	}
	for _, tt := range tests {
		got := normalizeIP(tt.input)
		if got != tt.want {
			t.Errorf("normalizeIP(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestNormalizeHash(t *testing.T) {
	tests := []struct {
		input string
		len   int
		want  string
	}{
		{"d41d8cd98f00b204e9800998ecf8427e", 32, "d41d8cd98f00b204e9800998ecf8427e"},
		{"D41D8CD98F00B204E9800998ECF8427E", 32, "d41d8cd98f00b204e9800998ecf8427e"},
		{"d41d8cd98f00b204e9800998ecf8427", 32, ""},    // too short
		{"d41d8cd98f00b204e9800998ecf8427e00", 32, ""}, // too long
		{"g41d8cd98f00b204e9800998ecf8427e", 32, ""},   // invalid hex
		{"", 32, ""},
	}
	for _, tt := range tests {
		got := normalizeHash(tt.input, tt.len)
		if got != tt.want {
			t.Errorf("normalizeHash(%q, %d) = %q, want %q", tt.input, tt.len, got, tt.want)
		}
	}
}

func TestNormalizeURL(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"http://evil.com/path", "http://evil.com/path"},
		{"HTTP://EVIL.COM/Path", "http://evil.com/path"},
		{"  http://example.com  ", "http://example.com"},
		{"", ""},
	}
	for _, tt := range tests {
		got := normalizeURL(tt.input)
		if got != tt.want {
			t.Errorf("normalizeURL(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestNormalizeIOCType(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"ip", model.IOCTypeIP},
		{"ipv4", model.IOCTypeIP},
		{"domain", model.IOCTypeDomain},
		{"domain-name", model.IOCTypeDomain},
		{"md5", model.IOCTypeHashMD5},
		{"hash_md5", model.IOCTypeHashMD5},
		{"sha256", model.IOCTypeHashSHA256},
		{"url", model.IOCTypeURL},
		{"unknown", ""},
	}
	for _, tt := range tests {
		got := normalizeIOCType(tt.input)
		if got != tt.want {
			t.Errorf("normalizeIOCType(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSeverityFromLabels(t *testing.T) {
	tests := []struct {
		labels []string
		want   string
	}{
		{[]string{"malicious"}, "high"},
		{[]string{"critical"}, "critical"},
		{[]string{"suspicious"}, "medium"},
		{[]string{"low"}, "low"},
		{[]string{"unknown"}, "medium"},
		{nil, "medium"},
	}
	for _, tt := range tests {
		got := severityFromLabels(tt.labels)
		if got != tt.want {
			t.Errorf("severityFromLabels(%v) = %q, want %q", tt.labels, got, tt.want)
		}
	}
}

// ─── Integration: Full Pipeline ─────────────────────────────────────────────

func TestIOCFullPipeline(t *testing.T) {
	// 1. Import IOC data from JSON.
	jsonInput := `[
		{"type": "ip", "value": "192.168.1.100", "severity": "critical", "description": "Known C2"},
		{"type": "domain", "value": "malware.net", "severity": "high"},
		{"type": "hash_md5", "value": "d41d8cd98f00b204e9800998ecf8427e", "severity": "high"}
	]`
	entries, err := ImportJSON(strings.NewReader(jsonInput), "threat-feed")
	if err != nil {
		t.Fatalf("import error: %v", err)
	}

	// 2. Build IOC index.
	cache := NewIOCCache()
	cache.Reload([]model.IOCFeed{
		{ID: "threat-feed", Name: "Threat Intel Feed"},
	}, entries)

	// 3. Match packets.
	packets := []model.Packet{
		{ID: 1, SourceIP: "192.168.1.100", DestIP: "10.0.0.1", Info: "TCP SYN"},
		{ID: 2, Info: "DNS query malware.net", DestIP: "8.8.8.8"},
		{ID: 3, Info: "Download", Payload: "file hash: d41d8cd98f00b204e9800998ecf8427e", DestIP: "10.0.0.1"},
		{ID: 4, SourceIP: "10.0.0.2", DestIP: "10.0.0.3", Info: "Normal traffic"}, // no match
	}

	// 4. Get summary.
	summary := MatchPacketsSummary(packets, cache.Index())
	if summary.TotalPackets != 4 {
		t.Errorf("expected 4 total packets, got %d", summary.TotalPackets)
	}
	if summary.MatchedPackets != 3 {
		t.Errorf("expected 3 matched packets, got %d", summary.MatchedPackets)
	}

	// 5. Convert to ThreatHits for integration.
	hits := MatchPacketsAsThreatHits(packets, cache.Index())
	if len(hits) != 3 {
		t.Fatalf("expected 3 hits, got %d", len(hits))
	}
	for _, hit := range hits {
		if hit.Category != "IOC" {
			t.Errorf("expected category 'IOC', got %q", hit.Category)
		}
	}

	// 6. Verify cache stats.
	stats := cache.Stats()
	if stats.FeedCount != 1 {
		t.Errorf("expected 1 feed, got %d", stats.FeedCount)
	}
	if stats.EntryCount != 3 {
		t.Errorf("expected 3 entries, got %d", stats.EntryCount)
	}
}

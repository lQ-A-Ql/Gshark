package engine

import (
	"strings"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

// makeDNSPacket creates a DNS packet with the given query info.
// The Info field follows tshark's "Standard query ... A <domain>" format.
func makeDNSPacket(id int64, domain, queryType string) model.Packet {
	return model.Packet{
		ID:       id,
		Info:     "Standard query " + queryType + " " + domain,
		Protocol: "DNS",
		SourceIP: "192.168.1.10",
		DestIP:   "8.8.8.8",
		DestPort: 53,
	}
}

func TestDetectDNSTunneling_LongSubdomain(t *testing.T) {
	// Generate a subdomain label > 50 characters.
	longLabel := strings.Repeat("a", 60)
	domain := longLabel + ".example.com"

	packets := []model.Packet{
		makeDNSPacket(1, domain, "A"),
	}

	hits := DetectDNSTunneling(packets)
	found := false
	for _, h := range hits {
		if h.Rule == dnsTunnelLongSubRule {
			found = true
			if h.Category != "dns-tunneling" {
				t.Errorf("expected category 'dns-tunneling', got %q", h.Category)
			}
			if h.Level != "high" {
				t.Errorf("expected level 'high', got %q", h.Level)
			}
			break
		}
	}
	if !found {
		t.Error("expected DNS tunnel long subdomain hit for 60-char label")
	}
}

func TestDetectDNSTunneling_LongSubdomainInNestedLabel(t *testing.T) {
	// A deeply nested subdomain where one label is long.
	longLabel := strings.Repeat("x", 55)
	domain := "prefix." + longLabel + ".data.example.com"

	packets := []model.Packet{
		makeDNSPacket(1, domain, "TXT"),
	}

	hits := DetectDNSTunneling(packets)
	found := false
	for _, h := range hits {
		if h.Rule == dnsTunnelLongSubRule {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected DNS tunnel hit for nested long subdomain label")
	}
}

func TestDetectDNSTunneling_Base64EncodedSubdomain(t *testing.T) {
	// A subdomain that looks like base64: mixed case, digits, long enough.
	// "Hello World 123" base64 = "SGVsbG8gV29ybGQgMTIz" (20 chars, mixed case+digit)
	domain := "SGVsbG8gV29ybGQgMTIz.example.com"

	packets := []model.Packet{
		makeDNSPacket(1, domain, "A"),
	}

	hits := DetectDNSTunneling(packets)
	found := false
	for _, h := range hits {
		if h.Rule == dnsTunnelEncodedSubRule && strings.Contains(h.Preview, "Base64") {
			found = true
			if h.Category != "dns-tunneling" {
				t.Errorf("expected category 'dns-tunneling', got %q", h.Category)
			}
			break
		}
	}
	if !found {
		t.Error("expected DNS tunnel base64 encoded subdomain hit")
	}
}

func TestDetectDNSTunneling_HexEncodedSubdomain(t *testing.T) {
	// A subdomain that looks like hex: all hex chars, long enough.
	domain := "48656c6c6f576f726c64313233.example.com"

	packets := []model.Packet{
		makeDNSPacket(1, domain, "A"),
	}

	hits := DetectDNSTunneling(packets)
	found := false
	for _, h := range hits {
		if h.Rule == dnsTunnelEncodedSubRule && strings.Contains(h.Preview, "Hex") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected DNS tunnel hex encoded subdomain hit")
	}
}

func TestDetectDNSTunneling_HighEntropySubdomain(t *testing.T) {
	// A long random-looking subdomain with high entropy (> 3.5) and length > 20.
	// "aB3dEf7hIjKlMnOpQrStUvWx" has mixed chars => high entropy.
	domain := "aB3dEf7hIjKlMnOpQrStUvWxYz.example.com"

	packets := []model.Packet{
		makeDNSPacket(1, domain, "A"),
	}

	hits := DetectDNSTunneling(packets)
	found := false
	for _, h := range hits {
		if h.Rule == dnsTunnelHighEntropyRule {
			found = true
			if h.Category != "dns-tunneling" {
				t.Errorf("expected category 'dns-tunneling', got %q", h.Category)
			}
			break
		}
	}
	if !found {
		t.Error("expected DNS tunnel high entropy hit for random-looking subdomain")
	}
}

func TestDetectDNSTunneling_HighFrequencyQueries(t *testing.T) {
	// Generate > 10 queries to the same base domain with unique subdomains.
	packets := make([]model.Packet, 0, 15)
	for i := 0; i < 15; i++ {
		sub := strings.Repeat("x", 8) + string(rune('A'+i))
		domain := sub + ".tunnel.example.com"
		packets = append(packets, makeDNSPacket(int64(i+1), domain, "A"))
	}

	hits := DetectDNSTunneling(packets)
	found := false
	for _, h := range hits {
		if h.Rule == dnsTunnelHighFreqRule {
			found = true
			if h.Category != "dns-tunneling" {
				t.Errorf("expected category 'dns-tunneling', got %q", h.Category)
			}
			if h.Level != "high" {
				t.Errorf("expected level 'high', got %q", h.Level)
			}
			// baseDomain returns the last two labels: "example.com"
			if !strings.Contains(h.Match, "example.com") {
				t.Errorf("expected match to contain base domain, got %q", h.Match)
			}
			break
		}
	}
	if !found {
		t.Error("expected DNS tunnel high frequency hit for 15 queries to same base domain")
	}
}

func TestDetectDNSTunneling_NoFalsePositiveOnNormalDNS(t *testing.T) {
	// Normal DNS queries should not trigger any hits.
	packets := []model.Packet{
		makeDNSPacket(1, "www.example.com", "A"),
		makeDNSPacket(2, "mail.example.com", "MX"),
		makeDNSPacket(3, "api.example.com", "A"),
	}

	hits := DetectDNSTunneling(packets)
	if len(hits) != 0 {
		t.Errorf("expected 0 hits on normal DNS traffic, got %d: %+v", len(hits), hits)
	}
}

func TestDetectDNSTunneling_NoFalsePositiveOnShortSubdomains(t *testing.T) {
	// Short subdomains with normal entropy should not trigger.
	packets := []model.Packet{
		makeDNSPacket(1, "a.example.com", "A"),
		makeDNSPacket(2, "bb.example.com", "A"),
		makeDNSPacket(3, "cc.example.com", "A"),
	}

	hits := DetectDNSTunneling(packets)
	if len(hits) != 0 {
		t.Errorf("expected 0 hits on short subdomains, got %d: %+v", len(hits), hits)
	}
}

func TestDetectDNSTunneling_ThreatHunterIntegration(t *testing.T) {
	// Test that DNS tunneling works through the threatHunter Observe/Results path.
	h := newThreatHunter(nil, 1)

	// Feed some DNS packets with suspicious patterns.
	longLabel := strings.Repeat("z", 60)
	h.Observe(makeDNSPacket(1, longLabel+".evil.com", "TXT"))

	// Feed many unique subdomain queries to the same base domain.
	for i := 0; i < 12; i++ {
		sub := strings.Repeat("q", 10) + string(rune('a'+i))
		h.Observe(makeDNSPacket(int64(i+100), sub+".covert.example.net", "A"))
	}

	results := h.Results()

	// Should have at least one long-subdomain hit and one high-freq hit.
	hasLongSub := false
	hasHighFreq := false
	for _, hit := range results {
		if hit.Rule == dnsTunnelLongSubRule {
			hasLongSub = true
		}
		if hit.Rule == dnsTunnelHighFreqRule {
			hasHighFreq = true
		}
	}
	if !hasLongSub {
		t.Error("expected long subdomain hit from threatHunter integration")
	}
	if !hasHighFreq {
		t.Error("expected high frequency hit from threatHunter integration")
	}
}

func TestDetectDNSTunneling_TXTQueryTypes(t *testing.T) {
	// TXT queries with encoded subdomains are a common DNS tunnel pattern.
	domain := "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAA.example.com"

	packets := []model.Packet{
		makeDNSPacket(1, domain, "TXT"),
	}

	hits := DetectDNSTunneling(packets)
	if len(hits) == 0 {
		t.Error("expected at least one DNS tunnel hit for suspicious TXT query")
	}
}

func TestDetectDNSTunneling_MixedNormalAndSuspicious(t *testing.T) {
	// Mix of normal and suspicious packets. Only suspicious ones should trigger.
	packets := []model.Packet{
		makeDNSPacket(1, "www.google.com", "A"),
		makeDNSPacket(2, "mail.google.com", "MX"),
	}
	// Add 12 suspicious high-frequency queries.
	for i := 0; i < 12; i++ {
		sub := strings.Repeat("r", 10) + string(rune('A'+i))
		packets = append(packets, makeDNSPacket(int64(i+10), sub+".dataexfil.com", "A"))
	}

	hits := DetectDNSTunneling(packets)

	// Normal domains should not appear in hits.
	for _, h := range hits {
		if strings.Contains(h.Match, "google.com") {
			t.Errorf("normal domain google.com should not be in hits: %+v", h)
		}
	}

	// Should have high-freq hit for dataexfil.com.
	found := false
	for _, h := range hits {
		if h.Rule == dnsTunnelHighFreqRule && strings.Contains(h.Match, "dataexfil.com") {
			found = true
		}
	}
	if !found {
		t.Error("expected high frequency hit for dataexfil.com")
	}
}

func TestIsBase64Like(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"SGVsbG8gV29ybGQ", true},          // "Hello World" base64 (mixed case + digit-like)
		{"abcdefghijklmnop", false},        // all lowercase, no digits
		{"ABCDEFGHIJKLMNOP", false},        // all uppercase, no digits
		{"abc", false},                     // too short
		{"YWJjZGVmZzEyMzQ1Ng", true},       // mixed with digits
		{"hello world!", false},            // not base64 chars
		{"QUJDREVGR0hJSktMTU5PUA", true},   // 22 chars, all upper + has digit-like
		{"MTIzNDU2Nzg5MDEyMzQ1Njc4", true}, // digits-heavy base64
		{"QUJDREVGR0g", false},             // 11 chars, too short (< 12)
		{"dGhpcyBpcyBhIHRlc3Q", true},      // lowercase base64 with digit-like positions
	}
	for _, tt := range tests {
		got := isBase64Like(tt.input)
		if got != tt.want {
			t.Errorf("isBase64Like(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestIsHexLike(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"48656c6c6f576f726c64", true},       // "Hello World" hex
		{"abcdef0123456789", true},           // all hex chars
		{"ABCDEF0123456789", true},           // uppercase hex
		{"ghijklmnop", false},                // non-hex chars
		{"abc", false},                       // too short
		{"48656c6c6f576f726c64XXXXX", false}, // 20 hex / 25 total = 80% < 90%
		{"deadbeefcafebabe", true},           // classic hex pattern
		{"48656c6c6f576f726c64ZZ", true},     // 20/22 = 90.9% > 90% threshold
	}
	for _, tt := range tests {
		got := isHexLike(tt.input)
		if got != tt.want {
			t.Errorf("isHexLike(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestShannonEntropy_ReuseFromUDPTunnel(t *testing.T) {
	// Verify that the shannonEntropy function from tool_udp_tunnel.go is accessible.
	// Low entropy string.
	low := shannonEntropy("aaaaaaaaaa")
	if low > 1.0 {
		t.Errorf("expected low entropy for repeated chars, got %.2f", low)
	}

	// High entropy string.
	high := shannonEntropy("aB3dEf7hIjKlMnOpQrSt")
	if high < 3.0 {
		t.Errorf("expected high entropy for mixed chars, got %.2f", high)
	}

	// Empty string.
	zero := shannonEntropy("")
	if zero != 0 {
		t.Errorf("expected 0 entropy for empty string, got %.2f", zero)
	}
}

func TestExtractDNSQueryName_ReuseFromUDPTunnel(t *testing.T) {
	// Verify that extractDNSQueryName from tool_udp_tunnel.go works with our formats.
	tests := []struct {
		info string
		want string
	}{
		{"Standard query A example.com", "example.com"},
		{"Standard query TXT tunnel.evil.com", "tunnel.evil.com"},
		{"Standard query 0x1234 A test.org", "test.org"},
		{"", ""},
		{"HTTP GET /index.html", ""},
	}
	for _, tt := range tests {
		got := extractDNSQueryName(tt.info)
		if got != tt.want {
			t.Errorf("extractDNSQueryName(%q) = %q, want %q", tt.info, got, tt.want)
		}
	}
}

func TestBaseDomain_ReuseFromUDPTunnel(t *testing.T) {
	tests := []struct {
		fqdn string
		want string
	}{
		{"www.example.com", "example.com"},
		{"sub.domain.example.com", "example.com"},
		{"example.com", "example.com"},
		{"localhost", ""},
	}
	for _, tt := range tests {
		got := baseDomain(tt.fqdn)
		if got != tt.want {
			t.Errorf("baseDomain(%q) = %q, want %q", tt.fqdn, got, tt.want)
		}
	}
}

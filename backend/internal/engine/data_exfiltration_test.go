package engine

import (
	"strings"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestDetectDataExfiltration_LargeHTTPPost(t *testing.T) {
	packets := []model.Packet{
		{
			ID:       1,
			Info:     "POST /upload HTTP/1.1",
			Protocol: "HTTP",
			Length:   15 * 1024 * 1024, // 15 MB
			DestIP:   "10.0.0.1",
			DestPort: 443,
		},
	}

	hits := DetectDataExfiltration(packets)
	found := false
	for _, h := range hits {
		if h.Rule == exfilLargeHTTPRule {
			found = true
			if h.Category != "data-exfiltration" {
				t.Errorf("expected category 'data-exfiltration', got %q", h.Category)
			}
			if h.Level != "high" {
				t.Errorf("expected level 'high', got %q", h.Level)
			}
			break
		}
	}
	if !found {
		t.Error("expected large HTTP POST hit for 15 MB packet")
	}
}

func TestDetectDataExfiltration_LargeHTTPPut(t *testing.T) {
	packets := []model.Packet{
		{
			ID:       1,
			Info:     "PUT /api/data HTTP/1.1",
			Protocol: "HTTP",
			Length:   11 * 1024 * 1024, // 11 MB
			DestIP:   "10.0.0.2",
			DestPort: 443,
		},
	}

	hits := DetectDataExfiltration(packets)
	found := false
	for _, h := range hits {
		if h.Rule == exfilLargeHTTPRule {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected large HTTP PUT hit for 11 MB packet")
	}
}

func TestDetectDataExfiltration_SmallHTTPPostNoHit(t *testing.T) {
	// A small POST should not trigger the large payload rule.
	packets := []model.Packet{
		{
			ID:       1,
			Info:     "POST /api/login HTTP/1.1",
			Protocol: "HTTP",
			Length:   1024, // 1 KB
			DestIP:   "10.0.0.1",
			DestPort: 443,
		},
	}

	hits := DetectDataExfiltration(packets)
	for _, h := range hits {
		if h.Rule == exfilLargeHTTPRule {
			t.Error("small HTTP POST should not trigger large payload rule")
		}
	}
}

func TestDetectDataExfiltration_LargeGETNoHit(t *testing.T) {
	// A large GET (e.g., downloading) should not trigger the exfil rule.
	packets := []model.Packet{
		{
			ID:       1,
			Info:     "GET /download/big.iso HTTP/1.1",
			Protocol: "HTTP",
			Length:   15 * 1024 * 1024,
			DestIP:   "10.0.0.1",
			DestPort: 443,
		},
	}

	hits := DetectDataExfiltration(packets)
	for _, h := range hits {
		if h.Rule == exfilLargeHTTPRule {
			t.Error("large GET should not trigger large payload exfil rule")
		}
	}
}

func TestDetectDataExfiltration_KnownExfilServiceMega(t *testing.T) {
	packets := []model.Packet{
		{
			ID:       1,
			Info:     "POST /upload HTTP/1.1",
			Protocol: "HTTP",
			Length:   5 * 1024 * 1024,
			DestIP:   "mega.nz",
			DestPort: 443,
		},
	}

	hits := DetectDataExfiltration(packets)
	found := false
	for _, h := range hits {
		if h.Rule == exfilServiceRule && h.Match == "mega.nz" {
			found = true
			if h.Category != "data-exfiltration" {
				t.Errorf("expected category 'data-exfiltration', got %q", h.Category)
			}
			break
		}
	}
	if !found {
		t.Error("expected exfil service hit for mega.nz")
	}
}

func TestDetectDataExfiltration_KnownExfilServicePastebin(t *testing.T) {
	packets := []model.Packet{
		{
			ID:       1,
			Info:     "POST /api/api_post.php HTTP/1.1",
			Protocol: "HTTP",
			DestIP:   "pastebin.com",
			DestPort: 443,
		},
	}

	hits := DetectDataExfiltration(packets)
	found := false
	for _, h := range hits {
		if h.Rule == exfilServiceRule && h.Match == "pastebin.com" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected exfil service hit for pastebin.com")
	}
}

func TestDetectDataExfiltration_KnownExfilServiceDropbox(t *testing.T) {
	packets := []model.Packet{
		{
			ID:       1,
			Info:     "POST /upload HTTP/1.1",
			Protocol: "HTTP",
			DestIP:   "content.dropbox.com",
			DestPort: 443,
		},
	}

	hits := DetectDataExfiltration(packets)
	found := false
	for _, h := range hits {
		if h.Rule == exfilServiceRule && h.Match == "dropbox.com" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected exfil service hit for dropbox.com")
	}
}

func TestDetectDataExfiltration_KnownExfilServiceInInfo(t *testing.T) {
	// Domain appears in Info field (e.g., Host header).
	packets := []model.Packet{
		{
			ID:       1,
			Info:     "POST /upload HTTP/1.1 Host: sendspace.com",
			Protocol: "HTTP",
			DestIP:   "1.2.3.4",
			DestPort: 443,
		},
	}

	hits := DetectDataExfiltration(packets)
	found := false
	for _, h := range hits {
		if h.Rule == exfilServiceRule && h.Match == "sendspace.com" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected exfil service hit for sendspace.com in Info field")
	}
}

func TestDetectDataExfiltration_NormalDestNoHit(t *testing.T) {
	packets := []model.Packet{
		{
			ID:       1,
			Info:     "GET /index.html HTTP/1.1",
			Protocol: "HTTP",
			DestIP:   "example.com",
			DestPort: 443,
		},
	}

	hits := DetectDataExfiltration(packets)
	for _, h := range hits {
		if h.Rule == exfilServiceRule {
			t.Errorf("normal domain should not trigger exfil service rule: %+v", h)
		}
	}
}

func TestDetectDataExfiltration_LongDNSQuery(t *testing.T) {
	// Generate a DNS query name > 100 characters.
	longSub := strings.Repeat("a", 120)
	domain := longSub + ".evil.com"

	packets := []model.Packet{
		makeDNSPacket(1, domain, "A"),
	}

	hits := DetectDataExfiltration(packets)
	found := false
	for _, h := range hits {
		if h.Rule == exfilDNSQueryRule {
			found = true
			if h.Category != "data-exfiltration" {
				t.Errorf("expected category 'data-exfiltration', got %q", h.Category)
			}
			if h.Level != "high" {
				t.Errorf("expected level 'high', got %q", h.Level)
			}
			break
		}
	}
	if !found {
		t.Error("expected DNS exfil hit for 120-char query name")
	}
}

func TestDetectDataExfiltration_NormalDNSQueryNoHit(t *testing.T) {
	packets := []model.Packet{
		makeDNSPacket(1, "www.example.com", "A"),
		makeDNSPacket(2, "mail.google.com", "MX"),
	}

	hits := DetectDataExfiltration(packets)
	for _, h := range hits {
		if h.Rule == exfilDNSQueryRule {
			t.Errorf("normal DNS query should not trigger exfil rule: %+v", h)
		}
	}
}

func TestDetectDataExfiltration_MultipleRulesOnSamePacket(t *testing.T) {
	// A large POST to a known exfil service should trigger both rules.
	packets := []model.Packet{
		{
			ID:       1,
			Info:     "POST /upload HTTP/1.1",
			Protocol: "HTTP",
			Length:   12 * 1024 * 1024,
			DestIP:   "mega.nz",
			DestPort: 443,
		},
	}

	hits := DetectDataExfiltration(packets)
	hasLargeHTTP := false
	hasService := false
	for _, h := range hits {
		if h.Rule == exfilLargeHTTPRule {
			hasLargeHTTP = true
		}
		if h.Rule == exfilServiceRule {
			hasService = true
		}
	}
	if !hasLargeHTTP {
		t.Error("expected large HTTP hit for 12 MB POST to mega.nz")
	}
	if !hasService {
		t.Error("expected exfil service hit for mega.nz")
	}
}

func TestDetectDataExfiltration_ThreatHunterIntegration(t *testing.T) {
	// Test through the full threatHunter Observe/Results path.
	h := newThreatHunter(nil, 1)

	// Large POST to known exfil service.
	h.Observe(model.Packet{
		ID:       1,
		Info:     "POST /upload HTTP/1.1",
		Protocol: "HTTP",
		Length:   15 * 1024 * 1024,
		DestIP:   "dropbox.com",
		DestPort: 443,
	})

	// Long DNS query.
	longSub := strings.Repeat("x", 110)
	h.Observe(makeDNSPacket(2, longSub+".exfil.evil.com", "A"))

	// Known exfil service with small payload.
	h.Observe(model.Packet{
		ID:       3,
		Info:     "POST /api_post.php HTTP/1.1",
		Protocol: "HTTP",
		DestIP:   "pastebin.com",
		DestPort: 443,
	})

	results := h.Results()

	hasLargeHTTP := false
	hasService := false
	hasDNSExfil := false
	for _, hit := range results {
		if hit.Category != "data-exfiltration" {
			continue
		}
		switch hit.Rule {
		case exfilLargeHTTPRule:
			hasLargeHTTP = true
		case exfilServiceRule:
			hasService = true
		case exfilDNSQueryRule:
			hasDNSExfil = true
		}
	}
	if !hasLargeHTTP {
		t.Error("expected large HTTP hit from integration test")
	}
	if !hasService {
		t.Error("expected exfil service hit from integration test")
	}
	if !hasDNSExfil {
		t.Error("expected DNS exfil hit from integration test")
	}
}

func TestDetectDataExfiltration_NoFalsePositiveOnNormalTraffic(t *testing.T) {
	packets := []model.Packet{
		{ID: 1, Info: "GET /index.html HTTP/1.1", Protocol: "HTTP", Length: 2048, DestIP: "example.com", DestPort: 443},
		{ID: 2, Info: "POST /api/login HTTP/1.1", Protocol: "HTTP", Length: 512, DestIP: "example.com", DestPort: 443},
		makeDNSPacket(3, "www.google.com", "A"),
		makeDNSPacket(4, "cdn.jsdelivr.net", "A"),
	}

	hits := DetectDataExfiltration(packets)
	if len(hits) != 0 {
		t.Errorf("expected 0 hits on normal traffic, got %d: %+v", len(hits), hits)
	}
}

func TestExfilServiceDomains_AllKnown(t *testing.T) {
	// Verify all expected domains are in the list.
	expected := []string{
		"mega.nz", "mega.co.nz", "pastebin.com", "paste.ee",
		"dropbox.com", "sendspace.com", "transfer.sh", "file.io",
		"anonfiles.com", "bayfiles.com", "catbox.moe", "litterbox.catbox.moe",
		"gofile.io", "tmpfiles.org", "0x0.st",
	}

	domainSet := make(map[string]struct{}, len(exfilServiceDomains))
	for _, d := range exfilServiceDomains {
		domainSet[d] = struct{}{}
	}

	for _, d := range expected {
		if _, ok := domainSet[d]; !ok {
			t.Errorf("expected domain %q in exfilServiceDomains", d)
		}
	}
}

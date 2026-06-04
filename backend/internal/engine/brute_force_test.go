package engine

import (
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func makeAuthFailPacket(id int64, srcIP, destIP string, destPort int, statusCode int) model.Packet {
	codeText := map[int]string{
		401: "401 Unauthorized",
		403: "403 Forbidden",
	}
	return model.Packet{
		ID:       id,
		Info:     "HTTP/1.1 " + codeText[statusCode],
		Protocol: "HTTP",
		SourceIP: srcIP,
		DestIP:   destIP,
		DestPort: destPort,
	}
}

func TestDetectBruteForce_SingleIPThreshold(t *testing.T) {
	// Same IP sends 12 auth failures to the same target — should trigger.
	packets := make([]model.Packet, 0, 12)
	for i := int64(1); i <= 12; i++ {
		packets = append(packets, makeAuthFailPacket(i, "192.168.1.100", "10.0.0.1", 80, 401))
	}
	hits := DetectBruteForce(packets)
	found := false
	for _, h := range hits {
		if h.Rule == bruteForceIPRule {
			found = true
			if h.Category != "brute-force" {
				t.Errorf("expected category 'brute-force', got %q", h.Category)
			}
			if h.Level != "high" {
				t.Errorf("expected level 'high', got %q", h.Level)
			}
			if h.Match != "192.168.1.100" {
				t.Errorf("expected match '192.168.1.100', got %q", h.Match)
			}
			break
		}
	}
	if !found {
		t.Error("expected brute force single-IP hit for 12x 401 from same IP")
	}
}

func TestDetectBruteForce_SingleIPBelowThreshold(t *testing.T) {
	// Only 5 auth failures — below threshold, should NOT trigger.
	packets := make([]model.Packet, 0, 5)
	for i := int64(1); i <= 5; i++ {
		packets = append(packets, makeAuthFailPacket(i, "192.168.1.100", "10.0.0.1", 80, 401))
	}
	hits := DetectBruteForce(packets)
	for _, h := range hits {
		if h.Category == "brute-force" {
			t.Errorf("expected no brute-force hit for only 5 failures, got %+v", h)
		}
	}
}

func TestDetectBruteForce_CredentialStuffing(t *testing.T) {
	// 4 different source IPs hitting the same target with 401 — credential stuffing.
	packets := []model.Packet{
		makeAuthFailPacket(1, "10.0.0.1", "192.168.1.10", 80, 401),
		makeAuthFailPacket(2, "10.0.0.2", "192.168.1.10", 80, 401),
		makeAuthFailPacket(3, "10.0.0.3", "192.168.1.10", 80, 401),
		makeAuthFailPacket(4, "10.0.0.4", "192.168.1.10", 80, 401),
	}
	hits := DetectBruteForce(packets)
	found := false
	for _, h := range hits {
		if h.Rule == bruteForceCredentialRule {
			found = true
			if h.Category != "brute-force" {
				t.Errorf("expected category 'brute-force', got %q", h.Category)
			}
			if h.Level != "high" {
				t.Errorf("expected level 'high', got %q", h.Level)
			}
			break
		}
	}
	if !found {
		t.Error("expected credential stuffing hit for 4 different IPs targeting same host")
	}
}

func TestDetectBruteForce_CredentialStuffingBelowThreshold(t *testing.T) {
	// Only 2 different source IPs — below threshold.
	packets := []model.Packet{
		makeAuthFailPacket(1, "10.0.0.1", "192.168.1.10", 80, 401),
		makeAuthFailPacket(2, "10.0.0.2", "192.168.1.10", 80, 401),
	}
	hits := DetectBruteForce(packets)
	for _, h := range hits {
		if h.Rule == bruteForceCredentialRule {
			t.Errorf("expected no credential stuffing hit for only 2 IPs, got %+v", h)
		}
	}
}

func TestDetectBruteForce_401403AnomalyBurst(t *testing.T) {
	// 25 total auth failures from mixed IPs — should trigger anomaly burst.
	packets := make([]model.Packet, 0, 25)
	for i := int64(1); i <= 25; i++ {
		srcIP := "10.0.0." + string(rune('1'+(i%5)))
		packets = append(packets, makeAuthFailPacket(i, srcIP, "192.168.1.10", 80, 401))
	}
	hits := DetectBruteForce(packets)
	found := false
	for _, h := range hits {
		if h.Rule == bruteForceAnomalyRule {
			found = true
			if h.Category != "brute-force" {
				t.Errorf("expected category 'brute-force', got %q", h.Category)
			}
			break
		}
	}
	if !found {
		t.Error("expected 401/403 anomaly burst hit for 25 total auth failures")
	}
}

func TestDetectBruteForce_403Included(t *testing.T) {
	// Mix of 401 and 403 from same IP.
	packets := make([]model.Packet, 0, 12)
	for i := int64(1); i <= 6; i++ {
		packets = append(packets, makeAuthFailPacket(i, "192.168.1.50", "10.0.0.1", 80, 401))
	}
	for i := int64(7); i <= 12; i++ {
		packets = append(packets, makeAuthFailPacket(i, "192.168.1.50", "10.0.0.1", 80, 403))
	}
	hits := DetectBruteForce(packets)
	found := false
	for _, h := range hits {
		if h.Rule == bruteForceIPRule {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected brute force hit when 401+403 combined count exceeds threshold")
	}
}

func TestDetectBruteForce_NoFalsePositiveOnNormal(t *testing.T) {
	// Normal HTTP traffic with no 401/403 — should produce no brute force hits.
	packets := []model.Packet{
		makePacket(1, "GET /api/data", "normal response", "HTTP", "192.168.1.1", 80),
		makePacket(2, "HTTP/1.1 200 OK", "OK", "HTTP", "10.0.0.1", 80),
		makePacket(3, "DNS query", "A www.example.com", "DNS", "192.168.1.1", 53),
	}
	hits := DetectBruteForce(packets)
	if len(hits) != 0 {
		t.Errorf("expected 0 brute force hits on normal traffic, got %d: %+v", len(hits), hits)
	}
}

func TestDetectBruteForce_MixedWithOtherTraffic(t *testing.T) {
	// Auth failures mixed with normal traffic.
	packets := make([]model.Packet, 0, 15)
	// Normal packets.
	packets = append(packets, makePacket(1, "GET /index.html", "OK", "HTTP", "192.168.1.1", 80))
	packets = append(packets, makePacket(2, "HTTP/1.1 200 OK", "body", "HTTP", "10.0.0.1", 80))
	// 12 auth failures from same IP.
	for i := int64(3); i <= 14; i++ {
		packets = append(packets, makeAuthFailPacket(i, "10.10.10.10", "192.168.1.50", 80, 401))
	}
	packets = append(packets, makePacket(15, "GET /favicon.ico", "OK", "HTTP", "192.168.1.1", 80))

	hits := DetectBruteForce(packets)
	foundIPRule := false
	for _, h := range hits {
		if h.Rule == bruteForceIPRule && h.Match == "10.10.10.10" {
			foundIPRule = true
			break
		}
	}
	if !foundIPRule {
		t.Error("expected brute force IP rule hit for 10.10.10.10 in mixed traffic")
	}
}

func TestHuntThreats_BruteForceIntegration(t *testing.T) {
	// Verify brute force hits appear in HuntThreats output.
	packets := make([]model.Packet, 0, 12)
	for i := int64(1); i <= 12; i++ {
		packets = append(packets, makeAuthFailPacket(i, "192.168.1.200", "10.0.0.1", 80, 401))
	}
	hits := HuntThreats(packets, nil)
	found := false
	for _, h := range hits {
		if h.Category == "brute-force" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected brute-force category hit in HuntThreats output")
	}
}

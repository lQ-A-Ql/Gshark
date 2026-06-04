package engine

import (
	"math"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestShannonEntropy_KnownValues(t *testing.T) {
	// Uniform distribution of 4 chars → entropy = 2.0
	if e := shannonEntropy("abcd"); math.Abs(e-2.0) > 0.01 {
		t.Errorf("expected entropy ~2.0 for 'abcd', got %.4f", e)
	}
	// Single char → entropy = 0
	if e := shannonEntropy("aaaa"); math.Abs(e) > 0.001 {
		t.Errorf("expected entropy 0 for 'aaaa', got %.4f", e)
	}
	// Empty string → entropy = 0
	if e := shannonEntropy(""); e != 0 {
		t.Errorf("expected entropy 0 for empty string, got %.4f", e)
	}
	// High entropy string (many unique chars)
	if e := shannonEntropy("abcdefghij"); e < 3.0 {
		t.Errorf("expected entropy > 3.0 for 'abcdefghij', got %.4f", e)
	}
}

func TestConsonantRatio(t *testing.T) {
	tests := []struct {
		domain string
		want   float64
	}{
		{"example", 0.5714}, // x,m,p,l = 4 consonants, e,a,e = 3 vowels → 4/7
		{"bcdfgh", 1.0},     // all consonants
		{"aeiou", 0.0},      // all vowels
		{"test123", 0.75},   // t,s,t = 3 consonants, e = 1 vowel → 0.75 (digits ignored)
		{"", 0.0},
	}
	for _, tt := range tests {
		got := consonantRatio(tt.domain)
		if math.Abs(got-tt.want) > 0.05 {
			t.Errorf("consonantRatio(%q) = %.4f, want ~%.4f", tt.domain, got, tt.want)
		}
	}
}

func TestDigitRatio(t *testing.T) {
	tests := []struct {
		domain string
		want   float64
	}{
		{"abc123", 0.5},    // 3 digits, 3 letters
		{"abcdef", 0.0},    // no digits
		{"123456", 1.0},    // all digits
		{"test1.com", 0.1}, // 1 digit out of 10 chars (including dot, but dot is skipped)... actually 1/8
		{"", 0.0},
	}
	for _, tt := range tests {
		got := digitRatio(tt.domain)
		if math.Abs(got-tt.want) > 0.05 {
			t.Errorf("digitRatio(%q) = %.4f, want ~%.4f", tt.domain, got, tt.want)
		}
	}
}

func TestIsSuspiciousDomain_DGA(t *testing.T) {
	// DGA-like domain: high entropy + high consonant ratio (2 signals)
	dgaDomain := "xkqjzmvbwtpnrfdghlc.com" // consonant-heavy, high entropy
	reasons := isSuspiciousDomain(dgaDomain)
	if len(reasons) < 2 {
		t.Errorf("expected DGA domain %q to be suspicious (>=2 reasons), got %d: %v", dgaDomain, len(reasons), reasons)
	}

	// Normal domain should not be suspicious
	normalDomain := "google.com"
	reasons = isSuspiciousDomain(normalDomain)
	if len(reasons) != 0 {
		t.Errorf("expected normal domain %q to not be suspicious, got %d reasons: %v", normalDomain, len(reasons), reasons)
	}

	// Short domain should not be suspicious
	shortDomain := "ab.com"
	reasons = isSuspiciousDomain(shortDomain)
	if len(reasons) != 0 {
		t.Errorf("expected short domain %q to not be suspicious, got %d reasons: %v", shortDomain, len(reasons), reasons)
	}
}

func TestIsSuspiciousDomain_DigitHeavy(t *testing.T) {
	// Domain with high digit ratio + high entropy
	domain := "a1b2c3d4e5f6g7h8i9j0.com"
	reasons := isSuspiciousDomain(domain)
	if len(reasons) < 2 {
		t.Errorf("expected digit-heavy domain %q to be suspicious, got %d reasons: %v", domain, len(reasons), reasons)
	}
}

func TestDetectDGADomains_FindsDGAPackets(t *testing.T) {
	packets := []model.Packet{
		{ID: 1, Info: "Standard query A xkqjzmvbwtpnrfdghlcxkqjzmvbwtpnrfdghlc.com", Protocol: "DNS"},
		{ID: 2, Info: "Standard query A google.com", Protocol: "DNS"},
		{ID: 3, Info: "HTTP GET /index.html", Protocol: "HTTP"},
	}
	hits := detectDGADomains(packets)
	if len(hits) == 0 {
		t.Fatal("expected at least one DGA hit for suspicious domain")
	}
	found := false
	for _, h := range hits {
		if h.Category == "DGA" && h.Rule == "DGA Domain" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected DGA hit with category 'DGA' and rule 'DGA Domain'")
	}
}

func TestDetectDGADomains_IgnoresNormalDomains(t *testing.T) {
	packets := []model.Packet{
		{ID: 1, Info: "Standard query A www.google.com", Protocol: "DNS"},
		{ID: 2, Info: "Standard query A github.com", Protocol: "DNS"},
		{ID: 3, Info: "Standard query A stackoverflow.com", Protocol: "DNS"},
	}
	hits := detectDGADomains(packets)
	if len(hits) != 0 {
		t.Errorf("expected 0 DGA hits for normal domains, got %d: %+v", len(hits), hits)
	}
}

func TestDetectDGADomains_NoDNSSkipped(t *testing.T) {
	packets := []model.Packet{
		{ID: 1, Info: "HTTP GET /api/data", Protocol: "HTTP"},
		{ID: 2, Info: "TCP data payload", Protocol: "TCP"},
	}
	hits := detectDGADomains(packets)
	if len(hits) != 0 {
		t.Errorf("expected 0 DGA hits for non-DNS packets, got %d", len(hits))
	}
}

func TestDetectDGADomains_DeduplicatesSameDomain(t *testing.T) {
	packets := []model.Packet{
		{ID: 1, Info: "Standard query A xkqjzmvbwtpnrfdghlcxkqjzmvbwtpnrfdghlc.com", Protocol: "DNS"},
		{ID: 2, Info: "Standard query A xkqjzmvbwtpnrfdghlcxkqjzmvbwtpnrfdghlc.com", Protocol: "DNS"},
		{ID: 3, Info: "Standard query A xkqjzmvbwtpnrfdghlcxkqjzmvbwtpnrfdghlc.com", Protocol: "DNS"},
	}
	hits := detectDGADomains(packets)
	if len(hits) != 1 {
		t.Errorf("expected 1 DGA hit (deduplicated), got %d", len(hits))
	}
}

func TestDetectDGADomains_HighSeverity(t *testing.T) {
	// Domain that triggers 3+ signals → high severity
	// Long (>30), consonant-heavy (>0.8), high entropy, digit-heavy (>0.3)
	domain := "xkqjzmvbwtpnrfdghlckjzmp12345.com" // 36 chars, mostly consonants, digits, high entropy
	packets := []model.Packet{
		{ID: 1, Info: "Standard query A " + domain, Protocol: "DNS"},
	}
	hits := detectDGADomains(packets)
	if len(hits) == 0 {
		t.Fatal("expected at least one DGA hit")
	}
	if hits[0].Level != "high" {
		t.Errorf("expected high severity for 3+ signal domain, got %q", hits[0].Level)
	}
}

func TestDetectDGADomains_Exported(t *testing.T) {
	packets := []model.Packet{
		{ID: 1, Info: "Standard query A xkqjzmvbwtpnrfdghlcxkqjzmvbwtpnrfdghlc.com", Protocol: "DNS"},
	}
	hits := DetectDGADomains(packets)
	if len(hits) == 0 {
		t.Error("expected exported DetectDGADomains to return hits")
	}
}

func TestHuntThreats_IncludesDGA(t *testing.T) {
	packets := []model.Packet{
		{ID: 1, Info: "Standard query A xkqjzmvbwtpnrfdghlcxkqjzmvbwtpnrfdghlc.com", Protocol: "DNS"},
	}
	hits := HuntThreats(packets, nil)
	found := false
	for _, h := range hits {
		if h.Category == "DGA" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected HuntThreats to include DGA detection for suspicious DNS packets")
	}
}

func TestThreatHunter_ObserveDGA(t *testing.T) {
	hunter := newThreatHunter(nil, 1)
	hunter.Observe(model.Packet{
		ID:       1,
		Info:     "Standard query A xkqjzmvbwtpnrfdghlcxkqjzmvbwtpnrfdghlc.com",
		Protocol: "DNS",
		DestPort: 53,
	})
	results := hunter.Results()
	found := false
	for _, h := range results {
		if h.Category == "DGA" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected threatHunter to detect DGA domain in DNS packet")
	}
}

func TestThreatHunter_ObserveDGA_NormalDomainIgnored(t *testing.T) {
	hunter := newThreatHunter(nil, 1)
	hunter.Observe(model.Packet{
		ID:       1,
		Info:     "Standard query A www.google.com",
		Protocol: "DNS",
		DestPort: 53,
	})
	results := hunter.Results()
	for _, h := range results {
		if h.Category == "DGA" {
			t.Errorf("expected no DGA hit for normal domain, got %+v", h)
		}
	}
}

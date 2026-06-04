package engine

import (
	"strings"
	"unicode"

	"github.com/gshark/sentinel/backend/internal/model"
)

// DGA detection thresholds.
// Conservative thresholds to minimize false positives on legitimate domains.
// A domain must trigger at least 2 signals to be flagged.
const (
	dgaEntropyThreshold    = 4.0 // Shannon entropy — real DGA domains typically exceed 4.0
	dgaLengthThreshold     = 30  // Total domain length — legit long domains (e.g. CDNs) can reach 25-30
	dgaConsonantThreshold  = 0.8 // Consonant-only ratio — DGA strings are often consonant-heavy
	dgaDigitRatioThreshold = 0.3 // Digit ratio — DGA domains often embed random numbers
)

// dgaRuleName is the rule name for DGA domain detection.
var dgaRuleName = detectLegacyRuleName(func() []model.ThreatHit {
	// Use a clearly DGA-like domain that triggers detection with conservative thresholds.
	return detectDGADomains([]model.Packet{{ID: 1, Info: "A xkqjzmvbwtpnrfdghlcbtpnrfdghlckjzmp.com", Protocol: "DNS"}})
}, "DGA Domain")

// consonantRatio returns the ratio of consonants (non-vowel, non-digit, non-separator) in a domain.
func consonantRatio(domain string) float64 {
	vowels := map[rune]bool{'a': true, 'e': true, 'i': true, 'o': true, 'u': true, 'y': true}
	total := 0
	consonants := 0
	for _, c := range strings.ToLower(domain) {
		if c == '.' || c == '-' {
			continue
		}
		if unicode.IsDigit(c) {
			continue
		}
		if !unicode.IsLetter(c) {
			continue
		}
		total++
		if !vowels[c] {
			consonants++
		}
	}
	if total == 0 {
		return 0
	}
	return float64(consonants) / float64(total)
}

// digitRatio returns the ratio of digits in a domain.
func digitRatio(domain string) float64 {
	total := 0
	digits := 0
	for _, c := range domain {
		if c == '.' || c == '-' {
			continue
		}
		total++
		if unicode.IsDigit(c) {
			digits++
		}
	}
	if total == 0 {
		return 0
	}
	return float64(digits) / float64(total)
}

// isSuspiciousDomain performs multi-signal DGA analysis on a domain.
// Returns a list of triggered rule descriptions; empty if domain looks benign.
// Requires at least 2 signals to fire to reduce false positives.
func isSuspiciousDomain(domain string) []string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" || !strings.Contains(domain, ".") {
		return nil
	}

	// Skip very short domains.
	if len(domain) < 4 {
		return nil
	}

	var reasons []string

	// 1. Shannon entropy check (reuse from tool_udp_tunnel.go).
	if shannonEntropy(domain) > dgaEntropyThreshold {
		reasons = append(reasons, "high entropy")
	}

	// 2. Length check.
	if len(domain) > dgaLengthThreshold {
		reasons = append(reasons, "long domain")
	}

	// 3. Consonant ratio check.
	if consonantRatio(domain) > dgaConsonantThreshold {
		reasons = append(reasons, "high consonant ratio")
	}

	// 4. Digit ratio check.
	if digitRatio(domain) > dgaDigitRatioThreshold {
		reasons = append(reasons, "high digit ratio")
	}

	// A domain is suspicious if at least 2 signals fire.
	// Single signal alone may produce false positives.
	if len(reasons) < 2 {
		return nil
	}
	return reasons
}

// detectDGADomains analyzes packets for DGA domain patterns.
// It examines DNS query packets and flags domains that exhibit multiple
// DGA characteristics: high entropy, excessive length, high consonant ratio,
// and high digit ratio.
func detectDGADomains(packets []model.Packet) []model.ThreatHit {
	var hits []model.ThreatHit
	var seq int64 = 1
	seen := map[string]bool{}

	for _, pkt := range packets {
		domain := extractDNSQueryName(pkt.Info)
		if domain == "" || seen[domain] {
			continue
		}

		reasons := isSuspiciousDomain(domain)
		if len(reasons) == 0 {
			continue
		}
		seen[domain] = true

		level := "medium"
		if len(reasons) >= 3 {
			level = "high"
		}

		hits = append(hits, model.ThreatHit{
			ID:       seq,
			PacketID: pkt.ID,
			Category: "DGA",
			Rule:     "DGA Domain",
			Level:    level,
			Preview:  previewText(domain + " (" + strings.Join(reasons, ", ") + ")"),
			Match:    domain,
		})
		seq++
	}
	return hits
}

// DetectDGADomains is the exported entry point for DGA domain detection.
// It analyzes DNS query packets and returns ThreatHits for domains that
// exhibit multiple DGA characteristics.
func DetectDGADomains(packets []model.Packet) []model.ThreatHit {
	return detectDGADomains(packets)
}

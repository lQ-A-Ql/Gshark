package engine

import (
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

// MalleableProfile describes a known C2 malleable profile with its characteristic
// URI patterns, header transforms, and encoding modes.
type MalleableProfile struct {
	Name        string   // e.g. "cs-default", "cs-zeus"
	Family      string   // "cs" or "vshell"
	URIPatterns []string // normalized lowercase URI substrings to match against path
	// HeaderPresence lists HTTP header names whose presence alone is a signal.
	HeaderPresence []string
	// HeaderValues maps header name (lowercase) to expected value substring.
	// Empty value means presence is sufficient.
	HeaderValues map[string]string
	// EncodingModes lists encoding identifiers (e.g. "mask", "base64", "netbios").
	EncodingModes []string
	// UserAgent is the default User-Agent substring, if any.
	UserAgent string
	// ContentType is the default Content-Type for POST, if any.
	ContentType string
	// Confidence when the profile matches.
	Confidence int
}

// malleableCandidateScore tracks per-profile scoring during matching.
type malleableCandidateScore struct {
	profile      *MalleableProfile
	uriHits      int
	headerHits   int
	uaHit        bool
	ctHit        bool
	encodingHits int
	matchedOn    []string
}

// knownMalleableProfiles is the database of known C2 malleable profiles.
// These represent out-of-the-box or widely-used Cobalt Strike and other C2 profiles.
var knownMalleableProfiles = []MalleableProfile{
	// ── Cobalt Strike default profiles ──────────────────────────────────
	{
		Name:   "cs-default",
		Family: "cs",
		URIPatterns: []string{
			"/jquery-3.3.1.min.js",
			"/submit.php",
			"/__utm.gif",
			"/pixel.gif",
			"/en-us/default.aspx",
			"/IE9CompatViewList.xml",
		},
		HeaderPresence: []string{"Accept", "Accept-Language", "Accept-Encoding", "Referer"},
		HeaderValues:   map[string]string{"x-requested-with": "XMLHttpRequest"},
		EncodingModes:  []string{"mask"},
		UserAgent:      "Mozilla/5.0 (Windows NT",
		ContentType:    "application/octet-stream",
		Confidence:     85,
	},
	{
		Name:   "cs-zeus",
		Family: "cs",
		URIPatterns: []string{
			"/image/",
			"/wp-content/themes/",
			"/uploads/",
		},
		HeaderPresence: []string{"Accept", "Accept-Language", "Referer"},
		HeaderValues:   map[string]string{"x-forwarded-for": ""},
		EncodingModes:  []string{"mask", "base64"},
		UserAgent:      "Mozilla/5.0 (Windows NT 6.1",
		ContentType:    "application/x-www-form-urlencoded",
		Confidence:     78,
	},
	{
		Name:   "cs-cobaltstrike-online",
		Family: "cs",
		URIPatterns: []string{
			"/jquery-3.3.2.min.js",
			"/submit.php",
			"/login.php",
		},
		HeaderPresence: []string{"Accept", "Accept-Encoding"},
		HeaderValues:   map[string]string{"x-requested-with": "XMLHttpRequest"},
		EncodingModes:  []string{"mask"},
		UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
		ContentType:    "application/octet-stream",
		Confidence:     82,
	},
	{
		Name:   "cs-uri-watermark-4",
		Family: "cs",
		URIPatterns: []string{
			"/jquery-3.3.1.min.js",
			"/submit.php",
			"/__utm.gif",
		},
		HeaderPresence: []string{"Accept", "Accept-Language", "Accept-Encoding"},
		HeaderValues:   map[string]string{"x-requested-with": "XMLHttpRequest"},
		EncodingModes:  []string{"mask"},
		UserAgent:      "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0)",
		ContentType:    "application/octet-stream",
		Confidence:     80,
	},
	// ── Cobalt Strike popular community profiles ────────────────────────
	{
		Name:   "cs-pandora",
		Family: "cs",
		URIPatterns: []string{
			"/api/v1/content",
			"/api/v1/token",
		},
		HeaderPresence: []string{"Content-Type", "Accept"},
		HeaderValues:   map[string]string{"x-csrf-token": ""},
		EncodingModes:  []string{"mask", "base64"},
		UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
		ContentType:    "application/json",
		Confidence:     70,
	},
	{
		Name:   "cs-gitlab-api",
		Family: "cs",
		URIPatterns: []string{
			"/api/v4/session",
			"/api/v4/metadata",
		},
		HeaderPresence: []string{"Accept", "Cookie"},
		HeaderValues:   map[string]string{"x-forwarded-for": ""},
		EncodingModes:  []string{"mask"},
		UserAgent:      "Mozilla/5.0 (Windows NT 10.0",
		ContentType:    "application/x-www-form-urlencoded",
		Confidence:     68,
	},
	// ── VShell default profiles ─────────────────────────────────────────
	{
		Name:   "vshell-default-ws",
		Family: "vshell",
		URIPatterns: []string{
			"/?a=l64&h=",
			"/?a=w64&h=",
			"/ws",
		},
		HeaderPresence: []string{"Upgrade", "Connection"},
		HeaderValues: map[string]string{
			"upgrade":    "websocket",
			"connection": "upgrade",
		},
		EncodingModes: []string{"base64"},
		Confidence:    88,
	},
}

// MatchMalleableProfile checks a set of HTTP observations against the known
// malleable C2 profile database. It returns the best-matching profile (if any)
// along with a confidence score and the list of matched signals.
//
// The matching logic requires:
//   - At least one URI pattern match (the primary signal)
//   - Plus at least one additional corroborating signal (header, UA, encoding)
//
// This avoids false positives from incidental URI substring matches.
func MatchMalleableProfile(observations []c2HTTPObservation) *model.MalleableProfileMatch {
	if len(observations) == 0 {
		return nil
	}

	var best *malleableCandidateScore

	for i := range knownMalleableProfiles {
		p := &knownMalleableProfiles[i]
		cs := &malleableCandidateScore{profile: p}

		for _, obs := range observations {
			path := strings.ToLower(strings.TrimSpace(obs.path))
			ua := strings.ToLower(strings.TrimSpace(obs.userAgent))
			ct := strings.ToLower(strings.TrimSpace(obs.contentType))

			// ── URI pattern matching ──
			for _, pattern := range p.URIPatterns {
				lp := strings.ToLower(pattern)
				if lp != "" && strings.Contains(path, lp) {
					cs.uriHits++
					cs.matchedOn = uniqueStrings(append(cs.matchedOn, "uri:"+pattern))
					break // one URI match per observation is enough
				}
			}

			// ── Header presence/value matching ──
			payloadText := decodeHTTPPayloadText(obs.packet.Payload)
			headers := extractHTTPHeaders(payloadText)
			for _, hdr := range p.HeaderPresence {
				if val := strings.TrimSpace(headerValueCI(headers, hdr)); val != "" {
					cs.headerHits++
					cs.matchedOn = uniqueStrings(append(cs.matchedOn, "header:"+hdr))
				}
			}
			for hdrName, expectedVal := range p.HeaderValues {
				actualVal := strings.TrimSpace(headerValueCI(headers, hdrName))
				if actualVal != "" {
					if expectedVal == "" || strings.Contains(strings.ToLower(actualVal), strings.ToLower(expectedVal)) {
						cs.headerHits++
						cs.matchedOn = uniqueStrings(append(cs.matchedOn, "header-val:"+hdrName))
					}
				}
			}

			// ── User-Agent matching ──
			if p.UserAgent != "" && ua != "" && strings.Contains(ua, strings.ToLower(p.UserAgent)) {
				cs.uaHit = true
				cs.matchedOn = uniqueStrings(append(cs.matchedOn, "ua"))
			}

			// ── Content-Type matching ──
			if p.ContentType != "" && ct != "" && strings.Contains(ct, strings.ToLower(p.ContentType)) {
				cs.ctHit = true
				cs.matchedOn = uniqueStrings(append(cs.matchedOn, "content-type"))
			}
		}

		// Require at least 1 URI match as primary signal.
		if cs.uriHits == 0 {
			continue
		}
		// Require at least 1 corroborating signal.
		corroborating := cs.headerHits + boolToInt(cs.uaHit) + boolToInt(cs.ctHit)
		if corroborating == 0 {
			continue
		}

		if best == nil || scoreMalleable(cs) > scoreMalleable(best) {
			best = cs
		}
	}

	if best == nil {
		return nil
	}

	confidence := best.profile.Confidence
	totalSignals := best.uriHits + best.headerHits + boolToInt(best.uaHit) + boolToInt(best.ctHit)
	// Boost confidence for multi-signal matches.
	if totalSignals >= 4 {
		confidence += 8
	} else if totalSignals >= 3 {
		confidence += 4
	}
	if confidence > 99 {
		confidence = 99
	}

	return &model.MalleableProfileMatch{
		ProfileName: best.profile.Name,
		Family:      best.profile.Family,
		Confidence:  confidence,
		MatchReason: buildMalleableMatchReason(best),
		MatchedOn:   best.matchedOn,
	}
}

// MatchMalleableProfileFromIndicators runs malleable profile matching against
// the indicator records from a C2FamilyAnalysis result. This is useful when
// we only have the final candidate list, not the raw HTTP observations.
func MatchMalleableProfileFromIndicators(candidates []model.C2IndicatorRecord) *model.MalleableProfileMatch {
	if len(candidates) == 0 {
		return nil
	}

	var best *malleableCandidateScore

	for i := range knownMalleableProfiles {
		p := &knownMalleableProfiles[i]
		cs := &malleableCandidateScore{profile: p}

		for _, c := range candidates {
			uri := strings.ToLower(strings.TrimSpace(c.URI))

			// ── URI pattern matching ──
			for _, pattern := range p.URIPatterns {
				lp := strings.ToLower(pattern)
				if lp != "" && strings.Contains(uri, lp) {
					cs.uriHits++
					cs.matchedOn = uniqueStrings(append(cs.matchedOn, "uri:"+pattern))
					break
				}
			}

			// ── Indicator value contains header hints ──
			iv := strings.ToLower(strings.TrimSpace(c.IndicatorValue))
			for _, hdr := range p.HeaderPresence {
				if strings.Contains(iv, strings.ToLower(hdr)) {
					cs.headerHits++
					cs.matchedOn = uniqueStrings(append(cs.matchedOn, "header:"+hdr))
					break
				}
			}
			for hdrName, expectedVal := range p.HeaderValues {
				if strings.Contains(iv, strings.ToLower(hdrName)) {
					if expectedVal == "" || strings.Contains(iv, strings.ToLower(expectedVal)) {
						cs.headerHits++
						cs.matchedOn = uniqueStrings(append(cs.matchedOn, "header-val:"+hdrName))
					}
				}
			}

			// ── Tags contain encoding hints ──
			for _, tag := range c.Tags {
				lt := strings.ToLower(tag)
				for _, enc := range p.EncodingModes {
					if strings.Contains(lt, strings.ToLower(enc)) {
						cs.encodingHits++
						cs.matchedOn = uniqueStrings(append(cs.matchedOn, "encoding:"+enc))
						break
					}
				}
			}
		}

		if cs.uriHits == 0 {
			continue
		}
		corroborating := cs.headerHits + boolToInt(cs.uaHit) + boolToInt(cs.ctHit) + cs.encodingHits
		if corroborating == 0 {
			continue
		}

		if best == nil || scoreMalleable(cs) > scoreMalleable(best) {
			best = cs
		}
	}

	if best == nil {
		return nil
	}

	confidence := best.profile.Confidence
	totalSignals := best.uriHits + best.headerHits + boolToInt(best.uaHit) + boolToInt(best.ctHit) + best.encodingHits
	if totalSignals >= 4 {
		confidence += 8
	} else if totalSignals >= 3 {
		confidence += 4
	}
	if confidence > 99 {
		confidence = 99
	}

	return &model.MalleableProfileMatch{
		ProfileName: best.profile.Name,
		Family:      best.profile.Family,
		Confidence:  confidence,
		MatchReason: buildMalleableMatchReason(best),
		MatchedOn:   best.matchedOn,
	}
}

func scoreMalleable(cs *malleableCandidateScore) int {
	return cs.uriHits*10 + cs.headerHits*3 + boolToInt(cs.uaHit)*4 + boolToInt(cs.ctHit)*2 + cs.encodingHits
}

func buildMalleableMatchReason(cs *malleableCandidateScore) string {
	parts := []string{}
	if cs.uriHits > 0 {
		parts = append(parts, "URI 命中")
	}
	if cs.headerHits > 0 {
		parts = append(parts, "Header 匹配")
	}
	if cs.uaHit {
		parts = append(parts, "User-Agent 匹配")
	}
	if cs.ctHit {
		parts = append(parts, "Content-Type 匹配")
	}
	if cs.encodingHits > 0 {
		parts = append(parts, "编码模式匹配")
	}
	return strings.Join(parts, " + ")
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

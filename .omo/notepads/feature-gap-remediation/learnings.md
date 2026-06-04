# Feature Gap Remediation - Learnings

## MITRE ATT&CK Mapping (2026-06-04)

### Patterns Discovered
- `ThreatHit` struct in `types_packet.go:66-74` is the core detection hit model
- `EvidenceRecord` struct in `types_evidence.go` is the unified evidence model
- Detection rules are spread across: `analysis.go` (flag/anomaly/stego), `threat_hunt_stream.go` (stream-based), `tool_c2.go` (C2 analysis), `stream_payload_sources.go` (webshell), `tool_apt.go` (APT), `tool_bruteforce.go` (brute force), `yara_batch.go` (YARA)
- Rule names use mixed Chinese/English: "异常扫描行为", "Flag 嗅探", "非标准协议端口画像", "隐写术初筛异常"
- `containsString` helper already exists in `stream_payload_inspector_test.go` - don't redeclare in new test files
- Pre-existing LSP errors: unused `fmt` in `threat_hunt_stream.go`, `shannonEntropy` redeclared across `tool_udp_tunnel.go`/`dga_detection.go`

### Approach
- MITRE mapping uses a lookup table (`mitreRuleMappings`) with exact-match + substring fallback + category keyword heuristic
- `AnnotateThreatHitWithMITRE` / `AnnotateEvidenceRecordWithMITRE` are idempotent (skip if already annotated)
- Mapping covers: WebShell (T1505.003), C2 (T1071/T1573/T1571), Anomaly (T1046/T1595), BruteForce (T1110), Industrial (T0831), Stego (T1027), Flag/CTF (T1005)

## JA3/JA3S TLS Fingerprint (2026-06-04)

### Patterns Discovered
- `TLSFingerprint` struct added to `types_packet.go` with `JA3Hash`, `JA3SHash`, `JA3Raw`, `JA3SRaw` fields
- `Packet.TLSFingerprint` is `*TLSFingerprint` (pointer, omitempty) — nil when no TLS fingerprint available
- `MatchTLSFingerprint()` is a pure function (no receiver) returning `[]TLSFingerprintMatch` — easy to unit test
- TLS fingerprint inspection integrated into `inspectPacket()` flow, runs after HTTP/DNS/SMB/VShell inspections
- All C2 candidates (including non-CS families like Sliver, Meterpreter) go to CS bucket since model only has CS/VShell buckets
- `classifyScoreFactor` extended with `tls-fingerprint` (+12 weight) and `ja3-match`/`ja3s-match` (+12 weight) positive factors
- Case-insensitive hash comparison via `strings.ToLower()` on both input and lookup

### Known Malicious JA3 Hashes (initial set)
- CS: `72a589da586844d7f0818ce684948eea`, `a0e9f5d64349fb13191bc781f81f42e1`, `b32309a26951912be7dba376398abc3b`, `51c64c77e60f3980eea90869b68c58a8`
- Sliver: `3b5074b1b5d032e5620f69f9f700ff0e`
- Meterpreter: `19e29534fd49dd27d09234e639c4057e`
- IcedID: `baf309487b346df56b66a42bdd023749`
- Emotet: `3e5801bdd284407884e7857692af8111`, `4d7a28d6f2263ed61de88ca66eb011e3`
- TrickBot: `c12f54a3f91dc7bafd92c258b5209e74`

### Gotchas
- Pre-existing `TestBundledPublicBenignHTTPThreatHuntStaysQuiet` failure is from DGA detection (false positive on `pagead2.googlesyndication.com`), unrelated to JA3 changes
- Pre-existing build errors in `dga_detection.go` (duplicate `shannonEntropy`), `mitre_attack_mapping.go` (missing `TechniqueIDs`/`TacticIDs` on `ThreatHit`), and `threat_hunt_stream.go` (unused `fmt`) may block full test suite — these are from other work sessions

## DNS Tunneling Detection (2026-06-04)

### Patterns Discovered
- DNS tunneling detection added to 	hreat_hunt_stream.go via observeDNSTunnel() method on 	hreatHunter struct
- Reuses existing DNS utilities from 	ool_udp_tunnel.go: xtractDNSQueryName, aseDomain, xtractSubdomain, shannonEntropy, dnsQueryNameRE
- xtractDNSQueryName lowercases the domain — encoding detection (base64/hex) must use original-case info via xtractOriginalCaseQueryName()
- aseDomain returns last 2 labels (e.g., 	unnel.example.com → xample.com), not 3
- Detection integrates into the existing 	hreatHunter Observe/Results pipeline
- Standalone DetectDNSTunneling(packets) function wraps the hunter for direct use

### Detection Rules Implemented
1. **Long subdomain** (Level: high): label length > 50 chars → dns-tunneling category
2. **Base64-encoded subdomain** (Level: medium): 85%+ base64 chars with mixed case + digit → dns-tunneling category
3. **Hex-encoded subdomain** (Level: medium): 90%+ hex chars, length >= 16 → dns-tunneling category
4. **High-entropy subdomain** (Level: medium): Shannon entropy > 3.5 and length > 20 → dns-tunneling category
5. **High-frequency queries** (Level: high): > 10 queries to same base domain → dns-tunneling category

### Gotchas
- isBase64Like requires hasUpper && hasDigit — fails on lowercased domains; fixed by using xtractOriginalCaseQueryName for encoding checks
- isHexLike uses > 90% threshold — a string with 20/22 hex chars (90.9%) passes; adjust test expectations accordingly
- Pre-existing TestBundledPublicBenignHTTPThreatHuntStaysQuiet failure is from DGA detection (false positive on pagead2.googlesyndication.com), unrelated to DNS tunneling
- Pre-existing build errors in mitre_attack_mapping.go (missing TechniqueIDs/TacticIDs on ThreatHit) block full test suite — from other work sessions

## DGA Domain Detection (2026-06-04)

### Patterns Discovered
- DGA detection added to `dga_detection.go` with standalone functions + integration into `threatHunter.observeDGA()`
- Reuses `shannonEntropy` from `tool_udp_tunnel.go` and `extractDNSQueryName` from same file
- Multi-signal approach: requires >= 2 signals to flag (reduces false positives)
- Integration points: (1) `observeDGA()` called from `observeDNSTunnel()` for streaming, (2) `detectDGADomains()` called from `HuntThreats()` for standalone, (3) exported `DetectDGADomains()` for HTTP handler

### Detection Signals
1. **Shannon entropy > 4.0**: Real DGA domains typically exceed 4.0; legitimate domains with common words stay below
2. **Domain length > 30 chars**: Conservative threshold; CDN domains like `pagead2.googlesyndication.com` (31 chars) are borderline
3. **Consonant ratio > 0.8**: DGA strings are often all-consonant gibberish
4. **Digit ratio > 0.3**: DGA domains often embed random numbers

### Gotchas
- Initial thresholds (entropy 3.5, length 20) caused false positive on `pagead2.googlesyndication.com` — raised to (4.0, 30)
- `observeDGA` must be called BEFORE the `subdomain == ""` early return in `observeDNSTunnel()`, since DGA detection works on the full domain (not just subdomains)
- `extractDNSQueryName` lowercases the domain — this is fine for entropy/consonant/digit analysis
- The `dgaRuleName` bootstrap domain must itself trigger detection (use long consonant-heavy domain)
- Category is `"DGA"` (not `"dns-tunneling"`) to distinguish from DNS tunneling alerts
- Severity: `"high"` when 3+ signals fire, `"medium"` for exactly 2

package engine

import (
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestLookupMITREReturns_ExactMatch(t *testing.T) {
	tests := []struct {
		rule     string
		wantTech []string
		wantTact []string
	}{
		{
			rule:     "异常扫描行为",
			wantTech: []string{TIDNetworkServiceScan, TIDActiveScanning},
			wantTact: []string{TacticDiscovery, TacticReconnaissance},
		},
		{
			rule:     "非标准协议端口画像",
			wantTech: []string{TIDNonStandardPort, TIDAppLayerProtocol},
			wantTact: []string{TacticCommandAndControl},
		},
		{
			rule:     "Flag 嗅探",
			wantTech: []string{TIDDataFromLocalSystem},
			wantTact: []string{TacticCollection},
		},
		{
			rule:     "隐写术初筛异常",
			wantTech: []string{TIDObfuscatedFiles},
			wantTact: []string{TacticDefenseEvasion},
		},
		{
			rule:     "Modbus 可疑写突发",
			wantTech: []string{TIDManipulateControl},
			wantTact: []string{TacticImpact},
		},
	}

	for _, tt := range tests {
		t.Run(tt.rule, func(t *testing.T) {
			techs, tactics := LookupMITREReturns(tt.rule)
			if len(techs) == 0 {
				t.Fatalf("LookupMITREReturns(%q) returned empty techniques", tt.rule)
			}
			if len(tactics) == 0 {
				t.Fatalf("LookupMITREReturns(%q) returned empty tactics", tt.rule)
			}
			for _, want := range tt.wantTech {
				if !containsString(techs, want) {
					t.Errorf("techniques = %v, want to contain %q", techs, want)
				}
			}
			for _, want := range tt.wantTact {
				if !containsString(tactics, want) {
					t.Errorf("tactics = %v, want to contain %q", tactics, want)
				}
			}
		})
	}
}

func TestLookupMITREReturns_SubstringMatch(t *testing.T) {
	// "YARA 扫描异常" should match via substring on "yara"
	techs, tactics := LookupMITREReturns("YARA 扫描异常")
	if len(techs) == 0 {
		t.Fatal("expected techniques for YARA rule")
	}
	if !containsString(techs, TIDObtainCapabilities) {
		t.Errorf("techniques = %v, want TIDObtainCapabilities", techs)
	}
	if !containsString(tactics, TacticResourceDev) {
		t.Errorf("tactics = %v, want TacticResourceDev", tactics)
	}
}

func TestLookupMITREReturns_CategoryFallback(t *testing.T) {
	tests := []struct {
		input    string
		wantTech string
	}{
		{"webshell-detected", TIDWebShell},
		{"c2-beacon-traffic", TIDAppLayerProtocol},
		{"dns-tunneling", TIDDNS},
		{"brute-force-attempt", TIDBruteForce},
		{"port-scan-detected", TIDNetworkServiceScan},
		{"steg-image-found", TIDObfuscatedFiles},
		{"exploit-attempt", TIDExploitPublicApp},
		{"yara-rule-hit", TIDObtainCapabilities},
		{"modbus-illegal-write", TIDManipulateControl},
		{"dns-tunnel", TIDProtocolTunneling},
		{"flag-captured", TIDDataFromLocalSystem},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			techs, _ := LookupMITREReturns(tt.input)
			if len(techs) == 0 {
				t.Fatalf("LookupMITREReturns(%q) returned empty techniques", tt.input)
			}
			if !containsString(techs, tt.wantTech) {
				t.Errorf("techniques = %v, want to contain %q", techs, tt.wantTech)
			}
		})
	}
}

func TestLookupMITREReturns_EmptyAndUnknown(t *testing.T) {
	techs, tactics := LookupMITREReturns("")
	if techs != nil {
		t.Errorf("expected nil for empty rule, got %v", techs)
	}
	if tactics != nil {
		t.Errorf("expected nil for empty rule, got %v", tactics)
	}

	techs, tactics = LookupMITREReturns("completely-unknown-rule-xyz-123")
	if techs != nil {
		t.Errorf("expected nil for unknown rule, got %v", techs)
	}
	if tactics != nil {
		t.Errorf("expected nil for unknown rule, got %v", tactics)
	}
}

func TestAnnotateThreatHitWithMITRE(t *testing.T) {
	hit := model.ThreatHit{
		ID:       1,
		PacketID: 100,
		Category: "Anomaly",
		Rule:     "异常扫描行为",
		Level:    "medium",
	}

	annotated := AnnotateThreatHitWithMITRE(hit)
	if len(annotated.TechniqueIDs) == 0 {
		t.Fatal("expected technique IDs on annotated hit")
	}
	if !containsString(annotated.TechniqueIDs, TIDNetworkServiceScan) {
		t.Errorf("technique IDs = %v, want TIDNetworkServiceScan", annotated.TechniqueIDs)
	}
	if !containsString(annotated.TacticIDs, TacticDiscovery) {
		t.Errorf("tactic IDs = %v, want TacticDiscovery", annotated.TacticIDs)
	}
}

func TestAnnotateThreatHitWithMITRE_AlreadyAnnotated(t *testing.T) {
	hit := model.ThreatHit{
		ID:           1,
		PacketID:     100,
		Category:     "Anomaly",
		Rule:         "异常扫描行为",
		Level:        "medium",
		TechniqueIDs: []string{"T9999"},
		TacticIDs:    []string{"TA9999"},
	}

	annotated := AnnotateThreatHitWithMITRE(hit)
	if !containsString(annotated.TechniqueIDs, "T9999") {
		t.Errorf("expected original technique IDs preserved, got %v", annotated.TechniqueIDs)
	}
}

func TestAnnotateThreatHitWithMITRE_FallbackToCategory(t *testing.T) {
	hit := model.ThreatHit{
		ID:       1,
		PacketID: 100,
		Category: "WebShell",
		Rule:     "custom-webshell-rule",
		Level:    "high",
	}

	annotated := AnnotateThreatHitWithMITRE(hit)
	if len(annotated.TechniqueIDs) == 0 {
		t.Fatal("expected technique IDs via category fallback")
	}
	if !containsString(annotated.TechniqueIDs, TIDWebShell) {
		t.Errorf("technique IDs = %v, want TIDWebShell via category fallback", annotated.TechniqueIDs)
	}
}

func TestAnnotateThreatHitsWithMITRE(t *testing.T) {
	hits := []model.ThreatHit{
		{ID: 1, Rule: "Flag 嗅探", Category: "CTF"},
		{ID: 2, Rule: "非标准协议端口画像", Category: "Anomaly"},
		{ID: 3, Rule: "unknown-rule", Category: "Unknown"},
	}

	annotated := AnnotateThreatHitsWithMITRE(hits)
	if len(annotated) != 3 {
		t.Fatalf("expected 3 hits, got %d", len(annotated))
	}
	if len(annotated[0].TechniqueIDs) == 0 {
		t.Error("hit 0 should have technique IDs")
	}
	if len(annotated[1].TechniqueIDs) == 0 {
		t.Error("hit 1 should have technique IDs")
	}
	if len(annotated[2].TechniqueIDs) != 0 {
		t.Errorf("hit 2 should have no technique IDs, got %v", annotated[2].TechniqueIDs)
	}
}

func TestAnnotateEvidenceRecordWithMITRE(t *testing.T) {
	record := model.EvidenceRecord{
		ID:         "test:1",
		Module:     "hunting",
		Summary:    "异常扫描行为",
		SourceType: "rule-match",
		Severity:   "medium",
	}

	annotated := AnnotateEvidenceRecordWithMITRE(record)
	if len(annotated.TechniqueIDs) == 0 {
		t.Fatal("expected technique IDs on annotated record")
	}
	if !containsString(annotated.TechniqueIDs, TIDNetworkServiceScan) {
		t.Errorf("technique IDs = %v, want TIDNetworkServiceScan", annotated.TechniqueIDs)
	}
}

func TestAnnotateEvidenceRecordWithMITRE_FallbackToSourceType(t *testing.T) {
	record := model.EvidenceRecord{
		ID:         "test:2",
		Module:     "c2",
		Summary:    "some summary",
		SourceType: "webshell",
		Severity:   "high",
	}

	annotated := AnnotateEvidenceRecordWithMITRE(record)
	if len(annotated.TechniqueIDs) == 0 {
		t.Fatal("expected technique IDs via source type fallback")
	}
	if !containsString(annotated.TechniqueIDs, TIDWebShell) {
		t.Errorf("technique IDs = %v, want TIDWebShell", annotated.TechniqueIDs)
	}
}

func TestAnnotateEvidenceRecordWithMITRE_FallbackToModule(t *testing.T) {
	record := model.EvidenceRecord{
		ID:         "test:3",
		Module:     "c2-indicator",
		Summary:    "something",
		SourceType: "something",
		Severity:   "medium",
	}

	annotated := AnnotateEvidenceRecordWithMITRE(record)
	if len(annotated.TechniqueIDs) == 0 {
		t.Fatal("expected technique IDs via module fallback")
	}
}

func TestAnnotateEvidenceRecordsWithMITRE(t *testing.T) {
	records := []model.EvidenceRecord{
		{ID: "1", Module: "hunting", Summary: "Flag 嗅探", Severity: "high"},
		{ID: "2", Module: "c2", Summary: "c2-http-beacon", Severity: "critical"},
		{ID: "3", Module: "unknown", Summary: "nothing", Severity: "info"},
	}

	annotated := AnnotateEvidenceRecordsWithMITRE(records)
	if len(annotated) != 3 {
		t.Fatalf("expected 3 records, got %d", len(annotated))
	}
	if len(annotated[0].TechniqueIDs) == 0 {
		t.Error("record 0 should have technique IDs")
	}
	if len(annotated[1].TechniqueIDs) == 0 {
		t.Error("record 1 should have technique IDs")
	}
}

func TestLookupMITREReturns_CaseInsensitive(t *testing.T) {
	techs, _ := LookupMITREReturns("FLAG 嗅探")
	if len(techs) == 0 {
		t.Fatal("expected case-insensitive match for 'FLAG 嗅探'")
	}

	techs2, _ := LookupMITREReturns("BRUTEFORCE")
	if len(techs2) == 0 {
		t.Fatal("expected case-insensitive match for 'BRUTEFORCE'")
	}
}

func TestAnnotateThreatHitWithMITRE_C2Rules(t *testing.T) {
	tests := []struct {
		rule     string
		wantTech string
	}{
		{"c2-http-beacon", TIDWebProtocols},
		{"c2-dns-channel", TIDDNS},
		{"c2-smb-pivot", TIDLateralToolTransfer},
		{"c2-tcp-stream", TIDEncryptedChannel},
		{"c2-websocket", TIDWebProtocols},
	}

	for _, tt := range tests {
		t.Run(tt.rule, func(t *testing.T) {
			hit := model.ThreatHit{ID: 1, Rule: tt.rule, Category: "C2"}
			annotated := AnnotateThreatHitWithMITRE(hit)
			if !containsString(annotated.TechniqueIDs, tt.wantTech) {
				t.Errorf("techniques = %v, want %q", annotated.TechniqueIDs, tt.wantTech)
			}
			if !containsString(annotated.TacticIDs, TacticCommandAndControl) {
				t.Errorf("tactics = %v, want TacticCommandAndControl", annotated.TacticIDs)
			}
		})
	}
}

func TestLookupMITREReturns_TechniqueFormat(t *testing.T) {
	techs, _ := LookupMITREReturns("webshell")
	for _, tech := range techs {
		if len(tech) < 2 || tech[0] != 'T' {
			t.Errorf("technique ID %q does not look like a MITRE ATT&CK ID (expected T...)", tech)
		}
	}
}

func TestLookupMITREReturns_TacticFormat(t *testing.T) {
	_, tactics := LookupMITREReturns("bruteforce")
	for _, tact := range tactics {
		if len(tact) < 2 || tact[:2] != "TA" {
			t.Errorf("tactic ID %q does not look like a MITRE ATT&CK tactic ID (expected TA...)", tact)
		}
	}
}

// containsString is defined in stream_payload_inspector_test.go

package engine

import (
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestClassifyWebShellFamiliesEmpty(t *testing.T) {
	result := ClassifyWebShellFamilies(nil)
	if result != nil {
		t.Fatalf("expected nil for empty input, got %v", result)
	}
	result = ClassifyWebShellFamilies([]model.StreamPayloadSource{})
	if result != nil {
		t.Fatalf("expected nil for empty slice, got %v", result)
	}
}

func TestClassifyWebShellFamiliesGroupsByFamily(t *testing.T) {
	sources := []model.StreamPayloadSource{
		{
			ID:         "src-1",
			FamilyHint: "antsword_like",
			Confidence: 85,
			Signals:    []string{"chr-chain", "script-keyword"},
			SourceRole: "script_or_command",
		},
		{
			ID:         "src-2",
			FamilyHint: "antsword_like",
			Confidence: 90,
			Signals:    []string{"script-after-base64", "numeric-webshell-param"},
			SourceRole: "script_or_command",
		},
		{
			ID:         "src-3",
			FamilyHint: "behinder_v2",
			Confidence: 92,
			Signals:    []string{"behinder-v2-hex-key"},
			SourceRole: "key_negotiation",
		},
	}

	classifications := ClassifyWebShellFamilies(sources)
	if len(classifications) != 2 {
		t.Fatalf("expected 2 families, got %d: %+v", len(classifications), classifications)
	}

	// AntSword should be first (higher aggregate confidence due to 2 sources).
	if classifications[0].Family != "antsword" {
		t.Fatalf("expected first family 'antsword', got %q", classifications[0].Family)
	}
	if classifications[0].DisplayName != "蚁剑 (AntSword)" {
		t.Fatalf("expected display name '蚁剑 (AntSword)', got %q", classifications[0].DisplayName)
	}
	if classifications[0].EvidenceCount != 2 {
		t.Fatalf("expected 2 evidence for antsword, got %d", classifications[0].EvidenceCount)
	}

	// Behinder should be second.
	if classifications[1].Family != "behinder" {
		t.Fatalf("expected second family 'behinder', got %q", classifications[1].Family)
	}
	if classifications[1].DisplayName != "冰蝎 (Behinder)" {
		t.Fatalf("expected display name '冰蝎 (Behinder)', got %q", classifications[1].DisplayName)
	}
}

func TestClassifyWebShellFamiliesConfidenceBoost(t *testing.T) {
	// Two corroborating sources should get a confidence boost over a single source.
	single := []model.StreamPayloadSource{
		{
			ID:         "src-1",
			FamilyHint: "antsword_like",
			Confidence: 80,
			Signals:    []string{"chr-chain"},
		},
	}
	corroborated := []model.StreamPayloadSource{
		{
			ID:         "src-1",
			FamilyHint: "antsword_like",
			Confidence: 80,
			Signals:    []string{"chr-chain"},
		},
		{
			ID:         "src-2",
			FamilyHint: "antsword_like",
			Confidence: 82,
			Signals:    []string{"script-keyword"},
		},
	}

	singleResult := ClassifyWebShellFamilies(single)
	corroboratedResult := ClassifyWebShellFamilies(corroborated)

	if len(singleResult) != 1 || len(corroboratedResult) != 1 {
		t.Fatalf("expected 1 classification each, got %d and %d", len(singleResult), len(corroboratedResult))
	}
	if corroboratedResult[0].Confidence <= singleResult[0].Confidence {
		t.Fatalf("corroborated confidence (%d) should exceed single (%d)",
			corroboratedResult[0].Confidence, singleResult[0].Confidence)
	}
}

func TestClassifyWebShellFamiliesSignalDiversity(t *testing.T) {
	// More diverse signals should yield higher confidence.
	diverse := []model.StreamPayloadSource{
		{
			ID:         "src-1",
			FamilyHint: "godzilla_like",
			Confidence: 78,
			Signals:    []string{"base64-aes-block", "godzilla-random-param", "suspicious-param"},
		},
		{
			ID:         "src-2",
			FamilyHint: "godzilla_like",
			Confidence: 80,
			Signals:    []string{"hex-block-cipher", "godzilla-random-param", "structured-http-field"},
		},
	}
	singleSignal := []model.StreamPayloadSource{
		{
			ID:         "src-3",
			FamilyHint: "godzilla_like",
			Confidence: 78,
			Signals:    []string{"base64-aes-block"},
		},
	}

	diverseResult := ClassifyWebShellFamilies(diverse)
	singleResult := ClassifyWebShellFamilies(singleSignal)

	if len(diverseResult) != 1 || len(singleResult) != 1 {
		t.Fatalf("expected 1 classification each")
	}
	if diverseResult[0].Confidence <= singleResult[0].Confidence {
		t.Fatalf("diverse confidence (%d) should exceed single-signal (%d)",
			diverseResult[0].Confidence, singleResult[0].Confidence)
	}
}

func TestClassifyWebShellFamiliesVersionBehinderV2(t *testing.T) {
	sources := []model.StreamPayloadSource{
		{
			ID:         "src-hexkey",
			FamilyHint: "behinder_v2",
			Confidence: 92,
			Signals:    []string{"behinder-v2-hex-key"},
			SourceRole: "key_negotiation",
			DecoderOptionsHint: map[string]any{
				"decoder":        "behinder",
				"versionHint":    "v2.0",
				"keyNegotiation": true,
				"keyFormat":      "hex16",
			},
		},
		{
			ID:         "src-pass",
			FamilyHint: "behinder_v2",
			Confidence: 75,
			Signals:    []string{"behinder-v2-pass-param"},
			SourceRole: "key_negotiation",
			DecoderOptionsHint: map[string]any{
				"decoder":        "behinder",
				"versionHint":    "v2.0",
				"keyNegotiation": true,
				"handshakePhase": "initiation",
			},
		},
	}

	classifications := ClassifyWebShellFamilies(sources)
	if len(classifications) != 1 {
		t.Fatalf("expected 1 classification, got %d", len(classifications))
	}
	uc := classifications[0]
	if uc.Family != "behinder" {
		t.Fatalf("family = %q, want behinder", uc.Family)
	}
	if uc.Version != "v2.0" {
		t.Fatalf("version = %q, want v2.0", uc.Version)
	}
}

func TestClassifyWebShellFamiliesVersionBehinderV3(t *testing.T) {
	sources := []model.StreamPayloadSource{
		{
			ID:         "src-aes",
			FamilyHint: "aes_webshell_like",
			Confidence: 78,
			Signals:    []string{"base64-aes-block"},
			SourceRole: "encrypted_blob",
			DecoderOptionsHint: map[string]any{
				"decoder":     "behinder",
				"versionHint": "v3.0",
			},
		},
	}

	classifications := ClassifyWebShellFamilies(sources)
	if len(classifications) != 1 {
		t.Fatalf("expected 1 classification, got %d", len(classifications))
	}
	uc := classifications[0]
	if uc.Version != "v3.0" {
		t.Fatalf("version = %q, want v3.0", uc.Version)
	}
}

func TestClassifyWebShellFamiliesVersionGodzilla(t *testing.T) {
	sources := []model.StreamPayloadSource{
		{
			ID:         "src-gz1",
			FamilyHint: "godzilla_like",
			Confidence: 90,
			Signals:    []string{"base64-aes-block", "godzilla-random-param"},
			DecoderOptionsHint: map[string]any{
				"decoder": "godzilla",
				"cipher":  "aes_ecb",
			},
		},
		{
			ID:         "src-gz2",
			FamilyHint: "godzilla_like",
			Confidence: 88,
			Signals:    []string{"hex-block-cipher", "godzilla-random-param"},
			DecoderOptionsHint: map[string]any{
				"decoder": "godzilla",
				"cipher":  "aes_ecb",
			},
		},
	}

	classifications := ClassifyWebShellFamilies(sources)
	if len(classifications) != 1 {
		t.Fatalf("expected 1 classification, got %d", len(classifications))
	}
	uc := classifications[0]
	if uc.Family != "godzilla" {
		t.Fatalf("family = %q, want godzilla", uc.Family)
	}
	if uc.Version != "v2.0+" {
		t.Fatalf("version = %q, want v2.0+", uc.Version)
	}
	if uc.DisplayName != "哥斯拉 (Godzilla)" {
		t.Fatalf("display name = %q, want 哥斯拉 (Godzilla)", uc.DisplayName)
	}
}

func TestClassifyWebShellFamiliesVersionAntSword(t *testing.T) {
	sources := []model.StreamPayloadSource{
		{
			ID:         "src-as1",
			FamilyHint: "antsword_like",
			Confidence: 92,
			Signals:    []string{"chr-chain", "script-keyword"},
			SourceRole: "script_or_command",
		},
	}

	classifications := ClassifyWebShellFamilies(sources)
	if len(classifications) != 1 {
		t.Fatalf("expected 1 classification, got %d", len(classifications))
	}
	uc := classifications[0]
	if uc.Family != "antsword" {
		t.Fatalf("family = %q, want antsword", uc.Family)
	}
	if uc.Version != "chr-encoding" {
		t.Fatalf("version = %q, want chr-encoding", uc.Version)
	}
}

func TestClassifyWebShellFamiliesChinaChopper(t *testing.T) {
	sources := []model.StreamPayloadSource{
		{
			ID:         "src-cc1",
			FamilyHint: "china_chopper",
			Confidence: 95,
			Signals:    []string{"china-chopper-eval"},
			SourceRole: "script_or_command",
		},
		{
			ID:         "src-cc2",
			FamilyHint: "china_chopper",
			Confidence: 88,
			Signals:    []string{"china-chopper-param"},
			SourceRole: "script_or_command",
		},
	}

	classifications := ClassifyWebShellFamilies(sources)
	if len(classifications) != 1 {
		t.Fatalf("expected 1 classification, got %d", len(classifications))
	}
	uc := classifications[0]
	if uc.Family != "china_chopper" {
		t.Fatalf("family = %q, want china_chopper", uc.Family)
	}
	if uc.DisplayName != "菜刀 (China Chopper)" {
		t.Fatalf("display name = %q, want 菜刀 (China Chopper)", uc.DisplayName)
	}
	if uc.EvidenceCount != 2 {
		t.Fatalf("evidence count = %d, want 2", uc.EvidenceCount)
	}
}

func TestClassifyWebShellFamiliesReGeorg(t *testing.T) {
	sources := []model.StreamPayloadSource{
		{
			ID:         "src-rg1",
			FamilyHint: "regeorg",
			Confidence: 96,
			Signals:    []string{"regeorg-tunnel-headers"},
			SourceRole: "tunnel",
		},
	}

	classifications := ClassifyWebShellFamilies(sources)
	if len(classifications) != 1 {
		t.Fatalf("expected 1 classification, got %d", len(classifications))
	}
	uc := classifications[0]
	if uc.Family != "regeorg" {
		t.Fatalf("family = %q, want regeorg", uc.Family)
	}
	if uc.DisplayName != "reGeorg / neo-reGeorg" {
		t.Fatalf("display name = %q, want reGeorg / neo-reGeorg", uc.DisplayName)
	}
}

func TestClassifyWebShellFamiliesInferFromSignals(t *testing.T) {
	// Sources without FamilyHint should be inferred from signals.
	sources := []model.StreamPayloadSource{
		{
			ID:         "src-infer-1",
			Confidence: 80,
			Signals:    []string{"chr-chain"},
		},
		{
			ID:         "src-infer-2",
			Confidence: 78,
			Signals:    []string{"base64-aes-block"},
		},
		{
			ID:         "src-infer-3",
			Confidence: 90,
			Signals:    []string{"regeorg-tunnel-headers"},
		},
	}

	classifications := ClassifyWebShellFamilies(sources)
	if len(classifications) != 3 {
		t.Fatalf("expected 3 families, got %d: %+v", len(classifications), classifications)
	}

	families := map[string]bool{}
	for _, uc := range classifications {
		families[uc.Family] = true
	}
	if !families["antsword"] {
		t.Fatal("expected antsword family from signal inference")
	}
	if !families["behinder"] {
		t.Fatal("expected behinder family from signal inference")
	}
	if !families["regeorg"] {
		t.Fatal("expected regeorg family from signal inference")
	}
}

func TestClassifyWebShellFamiliesSortedByConfidence(t *testing.T) {
	sources := []model.StreamPayloadSource{
		{
			ID:         "src-low",
			FamilyHint: "antsword_like",
			Confidence: 60,
			Signals:    []string{"script-keyword"},
		},
		{
			ID:         "src-high",
			FamilyHint: "behinder_v2",
			Confidence: 95,
			Signals:    []string{"behinder-v2-hex-key"},
			SourceRole: "key_negotiation",
		},
	}

	classifications := ClassifyWebShellFamilies(sources)
	if len(classifications) != 2 {
		t.Fatalf("expected 2 classifications, got %d", len(classifications))
	}
	if classifications[0].Confidence < classifications[1].Confidence {
		t.Fatalf("expected sorted by confidence descending: %+v", classifications)
	}
}

func TestClassifyWebShellFamiliesSignalSummary(t *testing.T) {
	sources := []model.StreamPayloadSource{
		{
			ID:         "src-1",
			FamilyHint: "antsword_like",
			Confidence: 85,
			Signals:    []string{"chr-chain", "suspicious-param"},
		},
		{
			ID:         "src-2",
			FamilyHint: "antsword_like",
			Confidence: 88,
			Signals:    []string{"chr-chain", "script-keyword"},
		},
	}

	classifications := ClassifyWebShellFamilies(sources)
	if len(classifications) != 1 {
		t.Fatalf("expected 1 classification, got %d", len(classifications))
	}
	uc := classifications[0]
	if len(uc.SignalSummary) == 0 {
		t.Fatal("expected non-empty signal summary")
	}
	// "chr-chain" appears in both sources, so it should be first.
	if uc.SignalSummary[0] != "chr-chain" {
		t.Fatalf("expected chr-chain first in signal summary, got %q", uc.SignalSummary[0])
	}
}

func TestClassifyWebShellFamiliesCandidatesPopulated(t *testing.T) {
	sources := []model.StreamPayloadSource{
		{
			ID:         "src-1",
			FamilyHint: "godzilla_like",
			Confidence: 90,
			ParamName:  "7f0e6f",
			Signals:    []string{"base64-aes-block", "godzilla-random-param"},
			SourceRole: "encrypted_blob",
		},
	}

	classifications := ClassifyWebShellFamilies(sources)
	if len(classifications) != 1 {
		t.Fatalf("expected 1 classification, got %d", len(classifications))
	}
	uc := classifications[0]
	if len(uc.Candidates) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(uc.Candidates))
	}
	c := uc.Candidates[0]
	if c.SourceID != "src-1" {
		t.Fatalf("candidate source_id = %q, want src-1", c.SourceID)
	}
	if c.ParamName != "7f0e6f" {
		t.Fatalf("candidate param_name = %q, want 7f0e6f", c.ParamName)
	}
	if c.SourceRole != "encrypted_blob" {
		t.Fatalf("candidate source_role = %q, want encrypted_blob", c.SourceRole)
	}
}

func TestClassifyWebShellFamiliesMaxConfidenceCapped(t *testing.T) {
	// With many high-confidence sources, aggregate confidence should be capped at 100.
	sources := make([]model.StreamPayloadSource, 0, 10)
	for i := 0; i < 10; i++ {
		sources = append(sources, model.StreamPayloadSource{
			ID:         "src-many",
			FamilyHint: "antsword_like",
			Confidence: 95,
			Signals:    []string{"chr-chain", "script-keyword", "command-exec-function", "suspicious-param", "repeat-burst", "script-after-base64"},
			SourceRole: "script_or_command",
		})
	}

	classifications := ClassifyWebShellFamilies(sources)
	if len(classifications) != 1 {
		t.Fatalf("expected 1 classification, got %d", len(classifications))
	}
	if classifications[0].Confidence > 100 {
		t.Fatalf("confidence = %d, should be capped at 100", classifications[0].Confidence)
	}
}

func TestClassifyWebShellFamiliesMultipleFamiliesMixed(t *testing.T) {
	sources := []model.StreamPayloadSource{
		{
			ID:         "src-cc",
			FamilyHint: "china_chopper",
			Confidence: 95,
			Signals:    []string{"china-chopper-eval"},
			SourceRole: "script_or_command",
		},
		{
			ID:         "src-bh",
			FamilyHint: "behinder_v2",
			Confidence: 92,
			Signals:    []string{"behinder-v2-hex-key"},
			SourceRole: "key_negotiation",
		},
		{
			ID:         "src-gz",
			FamilyHint: "godzilla_like",
			Confidence: 90,
			Signals:    []string{"base64-aes-block", "godzilla-random-param"},
			SourceRole: "encrypted_blob",
		},
		{
			ID:         "src-as",
			FamilyHint: "antsword_like",
			Confidence: 88,
			Signals:    []string{"chr-chain"},
			SourceRole: "script_or_command",
		},
		{
			ID:         "src-rg",
			FamilyHint: "regeorg",
			Confidence: 96,
			Signals:    []string{"regeorg-tunnel-headers"},
			SourceRole: "tunnel",
		},
	}

	classifications := ClassifyWebShellFamilies(sources)
	if len(classifications) != 5 {
		t.Fatalf("expected 5 families, got %d: %+v", len(classifications), classifications)
	}

	// Verify all families present.
	families := map[string]string{}
	for _, uc := range classifications {
		families[uc.Family] = uc.DisplayName
	}
	expected := map[string]string{
		"behinder":      "冰蝎 (Behinder)",
		"antsword":      "蚁剑 (AntSword)",
		"godzilla":      "哥斯拉 (Godzilla)",
		"china_chopper": "菜刀 (China Chopper)",
		"regeorg":       "reGeorg / neo-reGeorg",
	}
	for fam, displayName := range expected {
		if families[fam] != displayName {
			t.Fatalf("family %q: display name = %q, want %q", fam, families[fam], displayName)
		}
	}
}

func TestInferSourceFamilyFromDecoderHints(t *testing.T) {
	tests := []struct {
		name     string
		source   model.StreamPayloadSource
		expected string
	}{
		{
			name: "behinder from decoder hint",
			source: model.StreamPayloadSource{
				DecoderHints: []string{"behinder"},
			},
			expected: "behinder",
		},
		{
			name: "antsword from decoder hint",
			source: model.StreamPayloadSource{
				DecoderHints: []string{"antsword"},
			},
			expected: "antsword",
		},
		{
			name: "godzilla from decoder hint",
			source: model.StreamPayloadSource{
				DecoderHints: []string{"godzilla"},
			},
			expected: "godzilla",
		},
		{
			name: "china_chopper from decoder hint",
			source: model.StreamPayloadSource{
				DecoderHints: []string{"china_chopper"},
			},
			expected: "china_chopper",
		},
		{
			name: "regeorg from decoder hint",
			source: model.StreamPayloadSource{
				DecoderHints: []string{"regeorg"},
			},
			expected: "regeorg",
		},
		{
			name: "empty when no hints",
			source: model.StreamPayloadSource{
				DecoderHints: []string{},
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := inferSourceFamily(tt.source)
			if result != tt.expected {
				t.Fatalf("inferSourceFamily() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestNormalizeFamily(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"antsword_like", "antsword"},
		{"godzilla_like", "godzilla"},
		{"behinder_v2", "behinder"},
		{"behinder", "behinder"},
		{"aes_webshell_like", "behinder"},
		{"hex_cipher", "behinder"},
		{"china_chopper", "china_chopper"},
		{"regeorg", "regeorg"},
		{"neo-regeorg", "regeorg"},
		{"", ""},
		{"unknown", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeFamily(tt.input)
			if result != tt.expected {
				t.Fatalf("normalizeFamily(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

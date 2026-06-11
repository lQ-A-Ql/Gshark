package engine

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestFingerprintPayloadCandidateCoversChrAndHexBranches(t *testing.T) {
	tests := []struct {
		name          string
		candidate     model.StreamPayloadCandidate
		wantFamily    string
		wantSuggested string
		wantHint      string
		wantRole      string
		wantFP        string
		wantOption    string
		wantOptValue  any
	}{
		{
			name: "antsword chr chain",
			candidate: model.StreamPayloadCandidate{
				Kind:      "form",
				ParamName: "ant",
				Value:     "chr(65).chr(66).chr(67).chr(68)",
			},
			wantFamily:    "antsword_like",
			wantSuggested: "antsword",
			wantHint:      "antsword_like",
			wantRole:      "script_or_command",
			wantFP:        "chr-chain",
			wantOption:    "decoder",
			wantOptValue:  "antsword",
		},
		{
			name: "hex block cipher generic",
			candidate: model.StreamPayloadCandidate{
				Kind:      "form",
				ParamName: "pass",
				Value:     hex.EncodeToString([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}),
			},
			wantFamily:    "hex_cipher",
			wantSuggested: "auto",
			wantHint:      "hex_cipher",
			wantRole:      "encrypted_blob",
			wantFP:        "hex-block-cipher",
			wantOption:    "inputEncoding",
			wantOptValue:  "hex",
		},
		{
			name: "hex block cipher godzilla",
			candidate: model.StreamPayloadCandidate{
				Kind:      "form",
				ParamName: "7f0e6f",
				Value:     hex.EncodeToString([]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}),
			},
			wantFamily:    "godzilla_like",
			wantSuggested: "godzilla",
			wantHint:      "godzilla_like",
			wantRole:      "encrypted_blob",
			wantFP:        "godzilla-random-param",
			wantOption:    "inputEncoding",
			wantOptValue:  "hex",
		},
		{
			name: "hex printable payload",
			candidate: model.StreamPayloadCandidate{
				Kind:  "payload",
				Value: "48656c6c6f2d7061796c6f6164",
			},
			wantFamily:    "hex_payload",
			wantSuggested: "base64",
			wantFP:        "hex-token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := fingerprintPayloadCandidate(tt.candidate)
			if fp.Family != tt.wantFamily || fp.Suggested != tt.wantSuggested {
				t.Fatalf("fingerprint = %+v, want family=%q suggested=%q", fp, tt.wantFamily, tt.wantSuggested)
			}
			if tt.wantHint != "" && fp.FamilyHint != tt.wantHint {
				t.Fatalf("FamilyHint = %q, want %q; fp=%+v", fp.FamilyHint, tt.wantHint, fp)
			}
			if tt.wantRole != "" && fp.SourceRole != tt.wantRole {
				t.Fatalf("SourceRole = %q, want %q; fp=%+v", fp.SourceRole, tt.wantRole, fp)
			}
			if tt.wantFP != "" && !containsString(fp.Fingerprints, tt.wantFP) {
				t.Fatalf("Fingerprints = %#v, want %q", fp.Fingerprints, tt.wantFP)
			}
			if tt.wantOption != "" {
				if fp.DecoderOptionsHint[tt.wantOption] != tt.wantOptValue {
					t.Fatalf("DecoderOptionsHint[%q] = %#v, want %#v in %#v", tt.wantOption, fp.DecoderOptionsHint[tt.wantOption], tt.wantOptValue, fp.DecoderOptionsHint)
				}
			}
		})
	}
}

func TestInspectStreamPayloadCoversFallbackAndEmbeddedTokenBranches(t *testing.T) {
	empty := InspectStreamPayload("   ")
	if len(empty.Candidates) != 0 || empty.Confidence != 0 {
		t.Fatalf("expected empty inspection for blank payload, got %+v", empty)
	}

	base64Token := "AAECAwQFBgcICQoLDA0ODw=="
	hexToken := "48656c6c6f2d66726f6d2d686578"
	raw := "blob=" + base64Token + "&hex=" + hexToken + "&tail=suffix"
	inspection := InspectStreamPayload(raw)
	if !c2More85HasCandidateKind(inspection.Candidates, "token", base64Token) {
		t.Fatalf("expected embedded base64 token candidate, got %#v", inspection.Candidates)
	}
	if !c2More85HasCandidateKind(inspection.Candidates, "token", hexToken) {
		t.Fatalf("expected embedded hex token candidate, got %#v", inspection.Candidates)
	}

	wrappedHTTP := hex.EncodeToString([]byte("POST /api HTTP/1.1\r\nHost: demo\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\ncmd=whoami"))
	wrapped := InspectStreamPayload(wrappedHTTP)
	if !hasCandidate(wrapped.Candidates, "form", "cmd") {
		t.Fatalf("expected form candidate from hex wrapped HTTP body, got %#v", wrapped.Candidates)
	}
}

func TestCollectJSONCandidatesCoversInvalidLimitsAndOrdering(t *testing.T) {
	if got := collectJSONCandidates(""); got != nil {
		t.Fatalf("empty JSON candidates = %#v, want nil", got)
	}
	if got := collectJSONCandidates("not-json"); got != nil {
		t.Fatalf("non JSON candidates = %#v, want nil", got)
	}
	if got := collectJSONCandidates("{broken"); got != nil {
		t.Fatalf("invalid JSON candidates = %#v, want nil", got)
	}

	fields := make([]string, 0, 14)
	for i := 0; i < 14; i++ {
		fields = append(fields, `"`+string(rune('a'+i))+`":"`+strings.Repeat("x", 8+i)+`"`)
	}
	got := collectJSONCandidates("{" + strings.Join(fields, ",") + "}")
	if len(got) != 12 {
		t.Fatalf("expected JSON candidates to be capped at 12, got %d: %#v", len(got), got)
	}
	if got[0].paramName != "a" {
		t.Fatalf("expected stable lexical ordering, got %#v", got[:3])
	}
}

func c2More85HasCandidateKind(items []model.StreamPayloadCandidate, kind, value string) bool {
	for _, item := range items {
		if item.Kind == kind && item.Value == value {
			return true
		}
	}
	return false
}

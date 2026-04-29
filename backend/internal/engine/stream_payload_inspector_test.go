package engine

import (
	"encoding/base64"
	"net/url"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestInspectStreamPayloadSuggestsAntSwordFromHTTPForm(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("assert($_POST['cmd']);"))
	raw := "POST /shell.php HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\npass=" + url.QueryEscape(encoded)

	inspection := InspectStreamPayload(raw)
	if inspection.SuggestedDecoder != "antsword" {
		t.Fatalf("SuggestedDecoder = %q, want antsword", inspection.SuggestedDecoder)
	}
	if inspection.SuggestedFamily != "antsword_like" {
		t.Fatalf("SuggestedFamily = %q, want antsword_like", inspection.SuggestedFamily)
	}
	if inspection.Confidence < 80 {
		t.Fatalf("Confidence = %d, want >= 80", inspection.Confidence)
	}

	found := false
	for _, candidate := range inspection.Candidates {
		if candidate.Kind == "form" && candidate.ParamName == "pass" {
			found = true
			if !containsString(candidate.DecoderHints, "antsword") {
				t.Fatalf("candidate.DecoderHints = %#v, want antsword", candidate.DecoderHints)
			}
		}
	}
	if !found {
		t.Fatal("expected form candidate for param 'pass'")
	}
}

func TestInspectStreamPayloadSuggestsBehinderForAESLikeCipher(t *testing.T) {
	raw := "pass=AAECAwQFBgcICQoLDA0ODw=="

	inspection := InspectStreamPayload(raw)
	if inspection.SuggestedDecoder != "behinder" {
		t.Fatalf("SuggestedDecoder = %q, want behinder", inspection.SuggestedDecoder)
	}
	if inspection.SuggestedFamily != "aes_webshell_like" {
		t.Fatalf("SuggestedFamily = %q, want aes_webshell_like", inspection.SuggestedFamily)
	}
	if inspection.Confidence < 70 {
		t.Fatalf("Confidence = %d, want >= 70", inspection.Confidence)
	}
}

func TestInspectStreamPayloadExtractsMultipartCandidate(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("system('whoami');"))
	raw := "--demo\r\n" +
		"Content-Disposition: form-data; name=\"payload\"\r\n\r\n" +
		encoded + "\r\n" +
		"--demo--\r\n"

	inspection := InspectStreamPayload(raw)
	found := false
	for _, candidate := range inspection.Candidates {
		if candidate.Kind == "multipart" && candidate.ParamName == "payload" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected multipart candidate for param 'payload'")
	}
}

func TestInspectStreamPayloadExtractsHTTPQueryAndFormCandidates(t *testing.T) {
	queryEncoded := base64.RawURLEncoding.EncodeToString([]byte("<?php echo 'query';"))
	formEncoded := base64.StdEncoding.EncodeToString([]byte("assert($_POST['cmd']);"))
	raw := "POST /shell.php?cmd=" + queryEncoded + " HTTP/1.1\r\n" +
		"Host: example.test\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n\r\n" +
		"pass=" + url.QueryEscape(formEncoded)

	inspection := InspectStreamPayload(raw)

	if !hasCandidate(inspection.Candidates, "query", "cmd") {
		t.Fatalf("expected query candidate for cmd, got %#v", inspection.Candidates)
	}
	if !hasCandidate(inspection.Candidates, "form", "pass") {
		t.Fatalf("expected form candidate for pass, got %#v", inspection.Candidates)
	}
}

func TestInspectStreamPayloadExtractsJSONCandidateFromHTTPResponse(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("system('id');"))
	raw := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" +
		`{"data":{"payload":"` + encoded + `"},"noise":"short"}`

	inspection := InspectStreamPayload(raw)

	found := false
	for _, candidate := range inspection.Candidates {
		if candidate.Kind == "json" && candidate.ParamName == "data.payload" {
			found = true
			if candidate.Value != encoded {
				t.Fatalf("json candidate value = %q, want %q", candidate.Value, encoded)
			}
			if !containsString(candidate.DecoderHints, "base64") {
				t.Fatalf("json candidate hints = %#v, want base64", candidate.DecoderHints)
			}
		}
	}
	if !found {
		t.Fatalf("expected JSON candidate data.payload, got %#v", inspection.Candidates)
	}
}

func TestInspectStreamPayloadRecognizesBase64URLCandidate(t *testing.T) {
	raw := base64.RawURLEncoding.EncodeToString([]byte("assert($_POST['cmd']);"))

	inspection := InspectStreamPayload(raw)
	if inspection.SuggestedDecoder != "antsword" {
		t.Fatalf("SuggestedDecoder = %q, want antsword", inspection.SuggestedDecoder)
	}
	if inspection.Confidence < 80 {
		t.Fatalf("Confidence = %d, want >= 80", inspection.Confidence)
	}
}

func TestInspectStreamPayloadUnwrapsHexText(t *testing.T) {
	inspection := InspectStreamPayload("48656c6c6f2047536861726b")

	if inspection.NormalizedPayload != "Hello GShark" {
		t.Fatalf("NormalizedPayload = %q, want Hello GShark", inspection.NormalizedPayload)
	}
	if len(inspection.Candidates) == 0 || inspection.Candidates[0].Value != "Hello GShark" {
		t.Fatalf("expected normalized hex text candidate, got %#v", inspection.Candidates)
	}
}

func containsString(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

func hasCandidate(items []model.StreamPayloadCandidate, kind, paramName string) bool {
	for _, item := range items {
		if item.Kind == kind && item.ParamName == paramName {
			return true
		}
	}
	return false
}

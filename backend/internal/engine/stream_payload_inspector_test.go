package engine

import (
	"encoding/base64"
	"net/url"
	"testing"
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

func containsString(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

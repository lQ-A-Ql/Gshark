package engine

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
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

func TestInspectStreamPayloadExtractsHTTPBodyAndMultipartCandidates(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("system('whoami');"))
	multipartBody := "--demo\r\n" +
		"Content-Disposition: form-data; name=\"payload\"\r\n\r\n" +
		encoded + "\r\n" +
		"--demo--\r\n"
	raw := "POST /upload.php HTTP/1.1\r\n" +
		"Host: example.test\r\n" +
		"Content-Type: multipart/form-data; boundary=demo\r\n\r\n" +
		multipartBody

	inspection := InspectStreamPayload(raw)

	if inspection.NormalizedPayload != strings.TrimRight(multipartBody, "\r\n") {
		t.Fatalf("NormalizedPayload should keep HTTP body content, got %q", inspection.NormalizedPayload)
	}
	if !hasCandidate(inspection.Candidates, "multipart", "payload") {
		t.Fatalf("expected multipart candidate from full HTTP message, got %#v", inspection.Candidates)
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

func TestInspectStreamPayloadExtractsNestedJSONArrayCandidate(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("assert($_POST['cmd']);"))
	raw := `{"items":[{"noise":"short"},{"payload":"` + encoded + `"}]}`

	inspection := InspectStreamPayload(raw)

	if !hasCandidate(inspection.Candidates, "json", "items[1].payload") {
		t.Fatalf("expected JSON array candidate items[1].payload, got %#v", inspection.Candidates)
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

func TestInspectStreamPayloadHintsAntSwordNumericParam(t *testing.T) {
	raw := `1=%40ini_set%28%22display_errors%22%2C0%29%3B%40system%28%24_POST%5B%22cmd%22%5D%29%3B`

	inspection := InspectStreamPayload(raw)
	candidate := findCandidate(inspection.Candidates, "form", "1")
	if candidate == nil {
		t.Fatalf("expected numeric AntSword form candidate, got %#v", inspection.Candidates)
	}
	if candidate.FamilyHint != "antsword_like" {
		t.Fatalf("FamilyHint = %q, want antsword_like", candidate.FamilyHint)
	}
	if candidate.SourceRole != "script_or_command" {
		t.Fatalf("SourceRole = %q, want script_or_command", candidate.SourceRole)
	}
	if candidate.DecoderOptionsHint["decoder"] != "antsword" {
		t.Fatalf("decoder hint = %#v, want antsword", candidate.DecoderOptionsHint["decoder"])
	}
	if candidate.DecoderOptionsHint["pass"] != "1" {
		t.Fatalf("pass hint = %#v, want 1", candidate.DecoderOptionsHint["pass"])
	}
	if candidate.DecoderOptionsHint["extractParam"] != true {
		t.Fatalf("extractParam hint = %#v, want true", candidate.DecoderOptionsHint["extractParam"])
	}
	if rounds, ok := candidate.DecoderOptionsHint["urlDecodeRounds"].(int); !ok || rounds < 2 {
		t.Fatalf("urlDecodeRounds hint = %#v, want >= 2", candidate.DecoderOptionsHint["urlDecodeRounds"])
	}
}

func TestInspectStreamPayloadHintsHexWrappedAntSwordNumericParam(t *testing.T) {
	raw := hex.EncodeToString([]byte(`1=%40ini_set%28%22display_errors%22%2C0%29%3B%40system%28%24_POST%5B%22cmd%22%5D%29%3B`))

	inspection := InspectStreamPayload(raw)
	candidate := findCandidate(inspection.Candidates, "form", "1")
	if candidate == nil {
		t.Fatalf("expected hex-wrapped numeric AntSword form candidate, got %#v", inspection.Candidates)
	}
	if candidate.FamilyHint != "antsword_like" || candidate.SourceRole != "script_or_command" {
		t.Fatalf("unexpected candidate hints: %+v", *candidate)
	}
	if candidate.DecoderOptionsHint["decoder"] != "antsword" || candidate.DecoderOptionsHint["pass"] != "1" {
		t.Fatalf("unexpected decoder options hint: %#v", candidate.DecoderOptionsHint)
	}
}

func TestInspectStreamPayloadHintsGodzillaRandomParam(t *testing.T) {
	ciphertext := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	raw := "7f0e6f=" + url.QueryEscape(base64.StdEncoding.EncodeToString(ciphertext))

	inspection := InspectStreamPayload(raw)
	candidate := findCandidate(inspection.Candidates, "form", "7f0e6f")
	if candidate == nil {
		t.Fatalf("expected Godzilla random-param candidate, got %#v", inspection.Candidates)
	}
	if candidate.FamilyHint != "godzilla_like" {
		t.Fatalf("FamilyHint = %q, want godzilla_like", candidate.FamilyHint)
	}
	if candidate.SourceRole != "encrypted_blob" {
		t.Fatalf("SourceRole = %q, want encrypted_blob", candidate.SourceRole)
	}
	if candidate.DecoderOptionsHint["decoder"] != "godzilla" {
		t.Fatalf("decoder hint = %#v, want godzilla", candidate.DecoderOptionsHint["decoder"])
	}
	if candidate.DecoderOptionsHint["pass"] != "7f0e6f" {
		t.Fatalf("pass hint = %#v, want 7f0e6f", candidate.DecoderOptionsHint["pass"])
	}
	if candidate.DecoderOptionsHint["inputEncoding"] != "base64" || candidate.DecoderOptionsHint["cipher"] != "aes_ecb" {
		t.Fatalf("unexpected Godzilla options hint: %#v", candidate.DecoderOptionsHint)
	}
	if candidate.DecoderOptionsHint["stripMarkers"] != true {
		t.Fatalf("stripMarkers hint = %#v, want true", candidate.DecoderOptionsHint["stripMarkers"])
	}
}

func TestListStreamPayloadSourcesScansHTTPQueryFormJSONAndMultipart(t *testing.T) {
	svc := NewService(NopEmitter{}, nil)
	defer svc.packetStore.Close()

	queryEncoded := base64.StdEncoding.EncodeToString([]byte("assert($_POST['cmd']);"))
	jsonEncoded := base64.StdEncoding.EncodeToString([]byte("system('id');"))
	multipartEncoded := base64.StdEncoding.EncodeToString([]byte("eval($_POST['x']);"))
	if err := svc.packetStore.Append([]model.Packet{
		{
			ID:         10,
			Protocol:   "HTTP",
			Info:       "GET /shell.php?pass=" + url.QueryEscape(queryEncoded) + " HTTP/1.1",
			Payload:    "GET /shell.php?pass=" + url.QueryEscape(queryEncoded) + " HTTP/1.1\r\nHost: web.test\r\n\r\n",
			StreamID:   3,
			DestIP:     "10.0.0.2",
			DestPort:   80,
			SourceIP:   "10.0.0.1",
			SourcePort: 50100,
		},
		{
			ID:         11,
			Protocol:   "HTTP",
			Info:       "POST /api/upload HTTP/1.1",
			Payload:    "POST /api/upload HTTP/1.1\r\nHost: web.test\r\nContent-Type: application/json\r\n\r\n" + `{"data":{"payload":"` + jsonEncoded + `"}}`,
			StreamID:   4,
			DestIP:     "10.0.0.2",
			DestPort:   80,
			SourceIP:   "10.0.0.1",
			SourcePort: 50101,
		},
		{
			ID:         12,
			Protocol:   "HTTP",
			Info:       "POST /upload.aspx HTTP/1.1",
			Payload:    "POST /upload.aspx HTTP/1.1\r\nHost: web.test\r\nContent-Type: multipart/form-data; boundary=demo\r\n\r\n--demo\r\nContent-Disposition: form-data; name=\"payload\"\r\n\r\n" + multipartEncoded + "\r\n--demo--\r\n",
			StreamID:   5,
			DestIP:     "10.0.0.2",
			DestPort:   80,
			SourceIP:   "10.0.0.1",
			SourcePort: 50102,
		},
	}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	sources, err := svc.ListStreamPayloadSources(20)
	if err != nil {
		t.Fatalf("ListStreamPayloadSources() error = %v", err)
	}
	if !hasPayloadSource(sources, "query", "pass") {
		t.Fatalf("expected query pass payload source, got %#v", sources)
	}
	if !hasPayloadSource(sources, "json", "data.payload") {
		t.Fatalf("expected JSON payload source, got %#v", sources)
	}
	if !hasPayloadSource(sources, "multipart", "payload") {
		t.Fatalf("expected multipart payload source, got %#v", sources)
	}
	for _, source := range sources {
		if source.Confidence <= 0 || len(source.Signals) == 0 {
			t.Fatalf("expected scored source with signals, got %+v", source)
		}
	}
}

func TestListStreamPayloadSourcesKeepsWebshellSourceUnderNoiseLimit(t *testing.T) {
	svc := NewService(NopEmitter{}, nil)
	defer svc.packetStore.Close()

	packets := make([]model.Packet, 0, 61)
	for i := 0; i < 60; i++ {
		packets = append(packets, model.Packet{
			ID:        int64(i + 1),
			Timestamp: fmt.Sprintf("2026-05-02T10:%02d:00Z", i%60),
			Protocol:  "HTTP",
			Info:      "POST /login HTTP/1.1",
			Payload: fmt.Sprintf(
				"POST /login HTTP/1.1\r\nHost: benign.test\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=user%d&remember=true",
				i,
			),
			StreamID:   int64(100 + i),
			DestIP:     "10.0.0.2",
			DestPort:   80,
			SourceIP:   "10.0.0.1",
			SourcePort: 50000 + i,
		})
	}
	payload := "1=" + url.QueryEscape(`@system($_POST["cmd"]);`)
	packets = append(packets, model.Packet{
		ID:         1000,
		Timestamp:  "2026-05-02T11:00:00Z",
		Protocol:   "HTTP",
		Info:       "POST /shell.php HTTP/1.1",
		Payload:    "POST /shell.php HTTP/1.1\r\nHost: web.test\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n" + payload,
		StreamID:   77,
		DestIP:     "10.0.0.2",
		DestPort:   80,
		SourceIP:   "10.0.0.1",
		SourcePort: 51000,
	})
	if err := svc.packetStore.Append(packets); err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	sources, err := svc.ListStreamPayloadSources(20)
	if err != nil {
		t.Fatalf("ListStreamPayloadSources() error = %v", err)
	}
	for _, source := range sources {
		if source.SourceType == "form" && source.ParamName == "1" {
			if source.FamilyHint != "antsword_like" {
				t.Fatalf("FamilyHint = %q, want antsword_like", source.FamilyHint)
			}
			return
		}
	}
	t.Fatalf("expected webshell source under noise limit, got %#v", sources)
}

func TestListStreamPayloadSourcesDoesNotPromoteBenignHTTP(t *testing.T) {
	svc := NewService(NopEmitter{}, nil)
	defer svc.packetStore.Close()
	if err := svc.packetStore.Append([]model.Packet{
		{
			ID:         20,
			Protocol:   "HTTP",
			Info:       "POST /login HTTP/1.1",
			Payload:    "POST /login HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=alice&remember=true",
			StreamID:   2,
			DestIP:     "10.0.0.2",
			DestPort:   80,
			SourceIP:   "10.0.0.1",
			SourcePort: 50100,
		},
	}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	sources, err := svc.ListStreamPayloadSources(20)
	if err != nil {
		t.Fatalf("ListStreamPayloadSources() error = %v", err)
	}
	if len(sources) != 0 {
		t.Fatalf("expected benign login not to become payload source, got %#v", sources)
	}
}

func TestListStreamPayloadSourcesPromotesRepeatBurst(t *testing.T) {
	svc := NewService(NopEmitter{}, nil)
	defer svc.packetStore.Close()
	packets := make([]model.Packet, 0, 3)
	for i := 0; i < 3; i++ {
		packets = append(packets, model.Packet{
			ID:        int64(30 + i),
			Timestamp: "2026-05-02T10:00:" + []string{"00", "10", "20"}[i] + "Z",
			Protocol:  "HTTP",
			Info:      "POST /shell.php HTTP/1.1",
			Payload:   "POST /shell.php HTTP/1.1\r\nHost: burst.test\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\ncmd=whoami",
			StreamID:  int64(3 + i),
			DestIP:    "10.0.0.2",
			DestPort:  80,
			SourceIP:  "10.0.0.1",
		})
	}
	if err := svc.packetStore.Append(packets); err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	sources, err := svc.ListStreamPayloadSources(20)
	if err != nil {
		t.Fatalf("ListStreamPayloadSources() error = %v", err)
	}
	var matched *model.StreamPayloadSource
	for i := range sources {
		if sources[i].ParamName == "cmd" {
			matched = &sources[i]
			break
		}
	}
	if matched == nil {
		t.Fatalf("expected repeat cmd payload source, got %#v", sources)
	}
	if matched.OccurrenceCount < 3 || !containsString(matched.Signals, "repeat-burst") {
		t.Fatalf("expected repeat-burst signal and occurrence count, got %+v", *matched)
	}
	if len(matched.RelatedPackets) < 3 || matched.RepeatWindowSeconds != 30 {
		t.Fatalf("expected related packets and repeat window, got %+v", *matched)
	}
}

func TestListStreamPayloadSourcesDetectsDecodedCommandExecFunction(t *testing.T) {
	svc := NewService(NopEmitter{}, nil)
	defer svc.packetStore.Close()
	encoded := base64.StdEncoding.EncodeToString([]byte("Runtime.getRuntime().exec(\"whoami\")"))
	if err := svc.packetStore.Append([]model.Packet{{
		ID:        40,
		Timestamp: "2026-05-02T10:01:00Z",
		Protocol:  "HTTP",
		Info:      "GET /api.jsp?payload=" + url.QueryEscape(encoded) + " HTTP/1.1",
		Payload:   "GET /api.jsp?payload=" + url.QueryEscape(encoded) + " HTTP/1.1\r\nHost: cmd.test\r\n\r\n",
		StreamID:  7,
		DestIP:    "10.0.0.2",
		DestPort:  80,
		SourceIP:  "10.0.0.1",
	}}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	sources, err := svc.ListStreamPayloadSources(20)
	if err != nil {
		t.Fatalf("ListStreamPayloadSources() error = %v", err)
	}
	for _, source := range sources {
		if source.ParamName == "payload" && containsString(source.Signals, "command-exec-function") {
			if source.Confidence < 70 {
				t.Fatalf("expected command exec source to be high confidence, got %+v", source)
			}
			return
		}
	}
	t.Fatalf("expected decoded command-exec-function source, got %#v", sources)
}

func containsString(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

func hasPayloadSource(items []model.StreamPayloadSource, kind, paramName string) bool {
	for _, item := range items {
		if item.SourceType == kind && item.ParamName == paramName {
			return true
		}
	}
	return false
}

func findCandidate(items []model.StreamPayloadCandidate, kind, paramName string) *model.StreamPayloadCandidate {
	for i := range items {
		if items[i].Kind == kind && items[i].ParamName == paramName {
			return &items[i]
		}
	}
	return nil
}

func hasCandidate(items []model.StreamPayloadCandidate, kind, paramName string) bool {
	for _, item := range items {
		if item.Kind == kind && item.ParamName == paramName {
			return true
		}
	}
	return false
}

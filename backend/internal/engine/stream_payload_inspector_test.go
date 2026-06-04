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
	svc := NewService(NopEmitter{})
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
	svc := NewService(NopEmitter{})
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
	svc := NewService(NopEmitter{})
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
	svc := NewService(NopEmitter{})
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
	svc := NewService(NopEmitter{})
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

func TestInspectStreamPayloadSuggestsChinaChopperFromEval(t *testing.T) {
	raw := `@eval($_POST['caidao']);`

	inspection := InspectStreamPayload(raw)
	if inspection.SuggestedDecoder != "china_chopper" {
		t.Fatalf("SuggestedDecoder = %q, want china_chopper", inspection.SuggestedDecoder)
	}
	if inspection.SuggestedFamily != "china_chopper" {
		t.Fatalf("SuggestedFamily = %q, want china_chopper", inspection.SuggestedFamily)
	}
	if inspection.Confidence < 90 {
		t.Fatalf("Confidence = %d, want >= 90", inspection.Confidence)
	}
}

func TestInspectStreamPayloadSuggestsChinaChopperFromAssert(t *testing.T) {
	raw := `@assert($_POST['pass']);`

	inspection := InspectStreamPayload(raw)
	if inspection.SuggestedDecoder != "china_chopper" {
		t.Fatalf("SuggestedDecoder = %q, want china_chopper", inspection.SuggestedDecoder)
	}
	if inspection.SuggestedFamily != "china_chopper" {
		t.Fatalf("SuggestedFamily = %q, want china_chopper", inspection.SuggestedFamily)
	}
	if inspection.Confidence < 90 {
		t.Fatalf("Confidence = %d, want >= 90", inspection.Confidence)
	}
}

func TestInspectStreamPayloadSuggestsChinaChopperFromParamName(t *testing.T) {
	// When parameter name is "caidao", suggest china_chopper
	command := `system("whoami");`
	encodedCommand := base64.StdEncoding.EncodeToString([]byte(command))
	raw := "caidao=" + url.QueryEscape(encodedCommand)

	inspection := InspectStreamPayload(raw)
	if inspection.SuggestedDecoder != "china_chopper" {
		t.Fatalf("SuggestedDecoder = %q, want china_chopper", inspection.SuggestedDecoder)
	}
	if inspection.SuggestedFamily != "china_chopper" {
		t.Fatalf("SuggestedFamily = %q, want china_chopper", inspection.SuggestedFamily)
	}
	if inspection.Confidence < 85 {
		t.Fatalf("Confidence = %d, want >= 85", inspection.Confidence)
	}
}

func TestInspectStreamPayloadSuggestsReGeorgFromHeaders(t *testing.T) {
	raw := "GET /tunnel.php HTTP/1.1\r\n" +
		"Host: target.test\r\n" +
		"X-CMD: CONNECT\r\n" +
		"X-TARGET: 192.168.1.100:3389\r\n" +
		"\r\n"

	inspection := InspectStreamPayload(raw)
	if inspection.SuggestedDecoder != "regeorg" {
		t.Fatalf("SuggestedDecoder = %q, want regeorg", inspection.SuggestedDecoder)
	}
	if inspection.SuggestedFamily != "regeorg" {
		t.Fatalf("SuggestedFamily = %q, want regeorg", inspection.SuggestedFamily)
	}
	if inspection.Confidence < 90 {
		t.Fatalf("Confidence = %d, want >= 90", inspection.Confidence)
	}
}

func TestInspectStreamPayloadSuggestsReGeorgFromResponseStatus(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\n" +
		"X-STATUS-CODE: 200\r\n" +
		"X-CMD: READ\r\n" +
		"\r\n" +
		"data from tunnel"

	inspection := InspectStreamPayload(raw)
	if inspection.SuggestedDecoder != "regeorg" {
		t.Fatalf("SuggestedDecoder = %q, want regeorg", inspection.SuggestedDecoder)
	}
	if inspection.SuggestedFamily != "regeorg" {
		t.Fatalf("SuggestedFamily = %q, want regeorg", inspection.SuggestedFamily)
	}
}

func TestInspectStreamPayloadReGeorgHighConfidenceWithBothHeaders(t *testing.T) {
	raw := "POST /tunnel.jsp HTTP/1.1\r\n" +
		"Host: target.test\r\n" +
		"X-CMD: CONNECT\r\n" +
		"X-TARGET: 10.0.0.5:22\r\n" +
		"\r\n"

	inspection := InspectStreamPayload(raw)
	if inspection.Confidence < 95 {
		t.Fatalf("Confidence = %d, want >= 95 with both X-CMD and X-TARGET", inspection.Confidence)
	}
	if inspection.SuggestedFamily != "regeorg" {
		t.Fatalf("SuggestedFamily = %q, want regeorg", inspection.SuggestedFamily)
	}
}

// ── Behinder v2.0 key negotiation tests ────────────────────────────────────

func TestInspectStreamPayloadBehinderV2HexKeyResponse(t *testing.T) {
	// Behinder v2.0 returns a 16-char hex key from the pass=<digits> GET request.
	raw := "GET /shell.php?pass=645 HTTP/1.1\r\n" +
		"Host: target.test\r\n" +
		"\r\n" +
		"a1b2c3d4e5f67890"

	inspection := InspectStreamPayload(raw)

	found := false
	for _, candidate := range inspection.Candidates {
		if candidate.FamilyHint == "behinder_v2" && containsString(candidate.Fingerprints, "behinder-v2-hex-key") {
			found = true
			if candidate.SourceRole != "key_negotiation" {
				t.Fatalf("SourceRole = %q, want key_negotiation", candidate.SourceRole)
			}
			if candidate.Confidence < 90 {
				t.Fatalf("Confidence = %d, want >= 90", candidate.Confidence)
			}
			if !containsString(candidate.DecoderHints, "behinder") {
				t.Fatalf("DecoderHints = %#v, want behinder", candidate.DecoderHints)
			}
			if candidate.DecoderOptionsHint["keyNegotiation"] != true {
				t.Fatalf("keyNegotiation hint = %#v, want true", candidate.DecoderOptionsHint["keyNegotiation"])
			}
			if candidate.DecoderOptionsHint["keyFormat"] != "hex16" {
				t.Fatalf("keyFormat hint = %#v, want hex16", candidate.DecoderOptionsHint["keyFormat"])
			}
		}
	}
	if !found {
		t.Fatalf("expected Behinder v2.0 hex key candidate, got %#v", inspection.Candidates)
	}
}

func TestInspectStreamPayloadBehinderV2PassParamInitiation(t *testing.T) {
	// Phase 1 initiation: GET /shell.php?pass=645
	raw := "pass=645"

	inspection := InspectStreamPayload(raw)
	found := false
	for _, candidate := range inspection.Candidates {
		if candidate.FamilyHint == "behinder_v2" && containsString(candidate.Fingerprints, "behinder-v2-pass-param") {
			found = true
			if candidate.SourceRole != "key_negotiation" {
				t.Fatalf("SourceRole = %q, want key_negotiation", candidate.SourceRole)
			}
			if candidate.Confidence < 70 {
				t.Fatalf("Confidence = %d, want >= 70", candidate.Confidence)
			}
			if !containsString(candidate.DecoderHints, "behinder") {
				t.Fatalf("DecoderHints = %#v, want behinder", candidate.DecoderHints)
			}
			if candidate.DecoderOptionsHint["handshakePhase"] != "initiation" {
				t.Fatalf("handshakePhase hint = %#v, want initiation", candidate.DecoderOptionsHint["handshakePhase"])
			}
		}
	}
	if !found {
		t.Fatalf("expected Behinder v2.0 pass param candidate, got %#v", inspection.Candidates)
	}
}

func TestInspectStreamPayloadBehinderV2PassParam123(t *testing.T) {
	// Phase 2: GET /shell.php?pass=123
	raw := "pass=123"

	inspection := InspectStreamPayload(raw)
	found := false
	for _, candidate := range inspection.Candidates {
		if candidate.FamilyHint == "behinder_v2" && containsString(candidate.Fingerprints, "behinder-v2-pass-param") {
			found = true
			if candidate.DecoderOptionsHint["handshakePhase"] != "initiation" {
				t.Fatalf("handshakePhase hint = %#v, want initiation", candidate.DecoderOptionsHint["handshakePhase"])
			}
		}
	}
	if !found {
		t.Fatalf("expected Behinder v2.0 pass=123 candidate, got %#v", inspection.Candidates)
	}
}

func TestInspectStreamPayloadBehinderV2FullHTTPRequest(t *testing.T) {
	// Full HTTP request with hex key response body
	key := "e45e329feb5d925b"
	raw := "GET /shell.php?pass=645 HTTP/1.1\r\n" +
		"Host: target.test\r\n" +
		"Accept: text/html\r\n" +
		"\r\n" +
		key

	inspection := InspectStreamPayload(raw)

	// The suggested family should be behinder_v2 with high confidence
	if inspection.SuggestedFamily != "behinder_v2" {
		t.Fatalf("SuggestedFamily = %q, want behinder_v2", inspection.SuggestedFamily)
	}
	if inspection.SuggestedDecoder != "behinder" {
		t.Fatalf("SuggestedDecoder = %q, want behinder", inspection.SuggestedDecoder)
	}
	if inspection.Confidence < 90 {
		t.Fatalf("Confidence = %d, want >= 90", inspection.Confidence)
	}
}

func TestInspectStreamPayloadBehinderV2DefaultKeyDetection(t *testing.T) {
	// The default Behinder v3/v4 key "e45e329feb5d925b" is also 16 hex chars.
	// As a standalone hex token, it should be detected as Behinder v2.0 key.
	raw := "e45e329feb5d925b"

	inspection := InspectStreamPayload(raw)
	found := false
	for _, candidate := range inspection.Candidates {
		if candidate.FamilyHint == "behinder_v2" && containsString(candidate.Fingerprints, "behinder-v2-hex-key") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected Behinder v2.0 hex key for default key, got %#v", inspection.Candidates)
	}
}

func TestInspectStreamPayloadNotBehinderV2ShortHex(t *testing.T) {
	// 8-char hex should NOT match Behinder v2.0 key
	raw := "a1b2c3d4"

	inspection := InspectStreamPayload(raw)
	for _, candidate := range inspection.Candidates {
		if candidate.FamilyHint == "behinder_v2" {
			t.Fatalf("unexpected Behinder v2.0 match for short hex: %+v", candidate)
		}
	}
}

func TestInspectStreamPayloadNotBehinderV2SingleDigitPass(t *testing.T) {
	// pass=5 (single digit) should NOT match Behinder v2.0 (requires 2-3 digits)
	raw := "pass=5"

	inspection := InspectStreamPayload(raw)
	for _, candidate := range inspection.Candidates {
		if candidate.FamilyHint == "behinder_v2" {
			t.Fatalf("unexpected Behinder v2.0 match for single digit pass: %+v", candidate)
		}
	}
}

func TestListStreamPayloadSourcesDetectsBehinderV2HexKey(t *testing.T) {
	svc := NewService(NopEmitter{})
	defer svc.packetStore.Close()

	if err := svc.packetStore.Append([]model.Packet{
		{
			ID:         200,
			Timestamp:  "2026-06-04T10:00:00Z",
			Protocol:   "HTTP",
			Info:       "GET /shell.php?pass=645 HTTP/1.1",
			Payload:    "GET /shell.php?pass=645 HTTP/1.1\r\nHost: target.test\r\n\r\na1b2c3d4e5f67890",
			StreamID:   50,
			DestIP:     "10.0.0.2",
			DestPort:   80,
			SourceIP:   "10.0.0.1",
			SourcePort: 52000,
		},
	}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	sources, err := svc.ListStreamPayloadSources(20)
	if err != nil {
		t.Fatalf("ListStreamPayloadSources() error = %v", err)
	}

	found := false
	for _, source := range sources {
		if source.FamilyHint == "behinder_v2" {
			found = true
			if source.SourceRole != "key_negotiation" {
				t.Fatalf("SourceRole = %q, want key_negotiation", source.SourceRole)
			}
			if !containsString(source.Signals, "behinder-v2-hex-key") {
				t.Fatalf("Signals = %#v, want behinder-v2-hex-key", source.Signals)
			}
			if source.Confidence < 90 {
				t.Fatalf("Confidence = %d, want >= 90", source.Confidence)
			}
			break
		}
	}
	if !found {
		t.Fatalf("expected Behinder v2.0 payload source, got %#v", sources)
	}
}

func TestListStreamPayloadSourcesDetectsBehinderV2PassParam(t *testing.T) {
	svc := NewService(NopEmitter{})
	defer svc.packetStore.Close()

	if err := svc.packetStore.Append([]model.Packet{
		{
			ID:         201,
			Timestamp:  "2026-06-04T10:00:01Z",
			Protocol:   "HTTP",
			Info:       "GET /shell.php?pass=645 HTTP/1.1",
			Payload:    "GET /shell.php?pass=645 HTTP/1.1\r\nHost: target.test\r\n\r\n",
			StreamID:   51,
			DestIP:     "10.0.0.2",
			DestPort:   80,
			SourceIP:   "10.0.0.1",
			SourcePort: 52001,
		},
	}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	sources, err := svc.ListStreamPayloadSources(20)
	if err != nil {
		t.Fatalf("ListStreamPayloadSources() error = %v", err)
	}

	found := false
	for _, source := range sources {
		if source.FamilyHint == "behinder_v2" && containsString(source.Signals, "behinder-v2-pass-param") {
			found = true
			if source.SourceRole != "key_negotiation" {
				t.Fatalf("SourceRole = %q, want key_negotiation", source.SourceRole)
			}
			break
		}
	}
	if !found {
		t.Fatalf("expected Behinder v2.0 pass param source, got %#v", sources)
	}
}

func TestListStreamPayloadSourcesBehinderV2TwoPhaseCorrelation(t *testing.T) {
	svc := NewService(NopEmitter{})
	defer svc.packetStore.Close()

	// Simulate Behinder v2.0 two-phase handshake:
	// Phase 1: GET /shell.php?pass=645 → key response
	// Phase 2: GET /shell.php?pass=123 → second request
	if err := svc.packetStore.Append([]model.Packet{
		{
			ID:         300,
			Timestamp:  "2026-06-04T10:00:00Z",
			Protocol:   "HTTP",
			Info:       "GET /shell.php?pass=645 HTTP/1.1",
			Payload:    "GET /shell.php?pass=645 HTTP/1.1\r\nHost: target.test\r\n\r\ne45e329feb5d925b",
			StreamID:   60,
			DestIP:     "10.0.0.2",
			DestPort:   80,
			SourceIP:   "10.0.0.1",
			SourcePort: 53000,
		},
		{
			ID:         301,
			Timestamp:  "2026-06-04T10:00:01Z",
			Protocol:   "HTTP",
			Info:       "GET /shell.php?pass=123 HTTP/1.1",
			Payload:    "GET /shell.php?pass=123 HTTP/1.1\r\nHost: target.test\r\n\r\n",
			StreamID:   61,
			DestIP:     "10.0.0.2",
			DestPort:   80,
			SourceIP:   "10.0.0.1",
			SourcePort: 53001,
		},
	}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	sources, err := svc.ListStreamPayloadSources(20)
	if err != nil {
		t.Fatalf("ListStreamPayloadSources() error = %v", err)
	}

	hexKeyFound := false
	passParamFound := false
	for _, source := range sources {
		if source.FamilyHint == "behinder_v2" && containsString(source.Signals, "behinder-v2-hex-key") {
			hexKeyFound = true
		}
		if source.FamilyHint == "behinder_v2" && containsString(source.Signals, "behinder-v2-pass-param") {
			passParamFound = true
		}
	}
	if !hexKeyFound {
		t.Fatalf("expected Behinder v2.0 hex key source in two-phase correlation, got %#v", sources)
	}
	if !passParamFound {
		t.Fatalf("expected Behinder v2.0 pass param source in two-phase correlation, got %#v", sources)
	}
}

// ── Behinder HTTP header fingerprint tests ────────────────────────────────

func TestInspectStreamPayloadBehinderUAFromJava1_8_0_211(t *testing.T) {
	raw := "POST /shell.jsp HTTP/1.1\r\n" +
		"Host: target.test\r\n" +
		"User-Agent: Java/1.8.0_211\r\n" +
		"Content-Type: application/octet-stream\r\n" +
		"\r\n" +
		base64.StdEncoding.EncodeToString([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})

	inspection := InspectStreamPayload(raw)
	if inspection.SuggestedDecoder != "behinder" {
		t.Fatalf("SuggestedDecoder = %q, want behinder", inspection.SuggestedDecoder)
	}
	if inspection.SuggestedFamily != "behinder" {
		t.Fatalf("SuggestedFamily = %q, want behinder", inspection.SuggestedFamily)
	}
	if inspection.Confidence < 78 {
		t.Fatalf("Confidence = %d, want >= 78", inspection.Confidence)
	}
	if !containsString(inspection.Reasons, "User-Agent 'Java/1.8.0_211' 命中冰蝎内置 UA 库。") {
		t.Fatalf("Reasons = %#v, want Behinder UA reason", inspection.Reasons)
	}
}

func TestInspectStreamPayloadBehinderUAFromJava1_6_0_45(t *testing.T) {
	raw := "POST /api.jsp HTTP/1.1\r\n" +
		"Host: target.test\r\n" +
		"User-Agent: Java/1.6.0_45\r\n" +
		"\r\n" +
		"AAECAwQFBgcICQoLDA0ODw=="

	inspection := InspectStreamPayload(raw)
	if inspection.SuggestedDecoder != "behinder" {
		t.Fatalf("SuggestedDecoder = %q, want behinder", inspection.SuggestedDecoder)
	}
	if inspection.SuggestedFamily != "behinder" {
		t.Fatalf("SuggestedFamily = %q, want behinder", inspection.SuggestedFamily)
	}
	if inspection.Confidence < 78 {
		t.Fatalf("Confidence = %d, want >= 78", inspection.Confidence)
	}
}

func TestInspectStreamPayloadBehinderAcceptHeader(t *testing.T) {
	raw := "POST /shell.php HTTP/1.1\r\n" +
		"Host: target.test\r\n" +
		"Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2\r\n" +
		"Content-Type: application/octet-stream\r\n" +
		"\r\n" +
		base64.StdEncoding.EncodeToString([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})

	inspection := InspectStreamPayload(raw)
	if inspection.SuggestedDecoder != "behinder" {
		t.Fatalf("SuggestedDecoder = %q, want behinder", inspection.SuggestedDecoder)
	}
	if inspection.SuggestedFamily != "behinder" {
		t.Fatalf("SuggestedFamily = %q, want behinder", inspection.SuggestedFamily)
	}
	if inspection.Confidence < 86 {
		t.Fatalf("Confidence = %d, want >= 86", inspection.Confidence)
	}
	if !containsString(inspection.Reasons, "Accept 头命中冰蝎 v2.x 固定特征。") {
		t.Fatalf("Reasons = %#v, want Behinder Accept reason", inspection.Reasons)
	}
}

func TestInspectStreamPayloadBehinderUAAndAcceptCombined(t *testing.T) {
	raw := "POST /shell.php HTTP/1.1\r\n" +
		"Host: target.test\r\n" +
		"User-Agent: Java/1.8.0_211\r\n" +
		"Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2\r\n" +
		"Content-Type: application/octet-stream\r\n" +
		"\r\n" +
		base64.StdEncoding.EncodeToString([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})

	inspection := InspectStreamPayload(raw)
	if inspection.SuggestedDecoder != "behinder" {
		t.Fatalf("SuggestedDecoder = %q, want behinder", inspection.SuggestedDecoder)
	}
	if inspection.SuggestedFamily != "behinder" {
		t.Fatalf("SuggestedFamily = %q, want behinder", inspection.SuggestedFamily)
	}
	if inspection.Confidence < 93 {
		t.Fatalf("Confidence = %d, want >= 93", inspection.Confidence)
	}
	if !containsString(inspection.Reasons, "User-Agent 'Java/1.8.0_211' 命中冰蝎内置 UA 库。") {
		t.Fatalf("Reasons = %#v, want Behinder UA reason", inspection.Reasons)
	}
	if !containsString(inspection.Reasons, "Accept 头命中冰蝎 v2.x 固定特征。") {
		t.Fatalf("Reasons = %#v, want Behinder Accept reason", inspection.Reasons)
	}
}

func TestInspectStreamPayloadBenignUANotBehinder(t *testing.T) {
	raw := "POST /login HTTP/1.1\r\n" +
		"Host: example.test\r\n" +
		"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"\r\n" +
		"username=alice&password=secret"

	inspection := InspectStreamPayload(raw)
	if inspection.SuggestedFamily == "behinder" {
		t.Fatalf("SuggestedFamily = %q, should not be behinder for benign UA", inspection.SuggestedFamily)
	}
}

func TestInspectStreamPayloadBehinderHTTPFingerprintDetectedViaSourceList(t *testing.T) {
	svc := NewService(NopEmitter{})
	defer svc.packetStore.Close()

	if err := svc.packetStore.Append([]model.Packet{
		{
			ID:         400,
			Timestamp:  "2026-06-04T11:00:00Z",
			Protocol:   "HTTP",
			Info:       "POST /shell.php HTTP/1.1",
			Payload:    "POST /shell.php HTTP/1.1\r\nHost: target.test\r\nUser-Agent: Java/1.8.0_211\r\nAccept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2\r\n\r\n" + base64.StdEncoding.EncodeToString([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}),
			StreamID:   80,
			DestIP:     "10.0.0.2",
			DestPort:   80,
			SourceIP:   "10.0.0.1",
			SourcePort: 54000,
		},
	}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	sources, err := svc.ListStreamPayloadSources(20)
	if err != nil {
		t.Fatalf("ListStreamPayloadSources() error = %v", err)
	}

	found := false
	for _, source := range sources {
		if source.FamilyHint == "behinder" && containsString(source.Signals, "behinder-ua") {
			found = true
			if source.SourceRole != "http_header" {
				t.Fatalf("SourceRole = %q, want http_header", source.SourceRole)
			}
			if source.Confidence < 90 {
				t.Fatalf("Confidence = %d, want >= 90", source.Confidence)
			}
			break
		}
	}
	if !found {
		t.Fatalf("expected Behinder HTTP header payload source, got %#v", sources)
	}
}

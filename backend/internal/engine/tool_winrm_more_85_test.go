package engine

import (
	"bytes"
	"crypto/rc4"
	"encoding/base64"
	"strings"
	"testing"
)

func TestWinRMNoPreviewReportsCoverDiagnosticBranches(t *testing.T) {
	cases := []struct {
		name     string
		rows     int
		report   winrmDecryptReport
		contains string
	}{
		{name: "no rows", rows: 0, report: winrmDecryptReport{}, contains: "HTTP / WinRM"},
		{name: "only errors", rows: 2, report: winrmDecryptReport{errorFrameCount: 2}, contains: "NTLM"},
		{name: "no frame", rows: 2, report: winrmDecryptReport{}, contains: "NTLM"},
		{name: "no extraction", rows: 2, report: winrmDecryptReport{frameCount: 1}, contains: "Command"},
		{name: "empty after extraction", rows: 2, report: winrmDecryptReport{frameCount: 1, extractedFrameCount: 1}, contains: "空"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got := buildWinRMNoPreviewReport("demo.pcapng", 5985, tt.rows, tt.report)
			if !strings.Contains(got, "demo.pcapng") || !strings.Contains(got, "5985") || !strings.Contains(got, tt.contains) {
				t.Fatalf("diagnostic report missing expected text %q:\n%s", tt.contains, got)
			}
		})
	}
	if got := winRMDecryptResultMessage(winrmDecryptReport{text: "plain"}); got != "ok" {
		t.Fatalf("winRMDecryptResultMessage(nonempty) = %q", got)
	}
	if got := winRMDecryptResultMessage(winrmDecryptReport{}); got == "ok" || strings.TrimSpace(got) == "" {
		t.Fatalf("winRMDecryptResultMessage(empty) = %q", got)
	}
}

func TestDecryptWinRMMessagesRecordsHandshakeAndDecryptErrors(t *testing.T) {
	type1 := append([]byte("NTLMSSP\x00"), byte(1))
	type3Short := append([]byte("NTLMSSP\x00"), byte(3))
	report, err := decryptWinRMMessages([]winrmMessageRow{
		{
			frameNumber: "1",
			timestamp:   "t1",
			src:         "10.0.0.1",
			dst:         "10.0.0.2",
			srcPort:     "50000",
			dstPort:     "5985",
			authHeader:  "NTLM " + base64.StdEncoding.EncodeToString(type1),
		},
		{
			frameNumber: "2",
			timestamp:   "t2",
			src:         "10.0.0.1",
			dst:         "10.0.0.2",
			srcPort:     "50000",
			dstPort:     "5985",
			authHeader:  "Negotiate " + base64.StdEncoding.EncodeToString(type3Short),
			mimeData:    "00:11:22:33",
		},
	}, 5985, []byte("0123456789abcdef"), winrmDecryptOptions{includeErrorFrames: true})
	if err != nil {
		t.Fatalf("decryptWinRMMessages() error = %v", err)
	}
	if report.errorFrameCount == 0 || !strings.Contains(report.text, "[error]") {
		t.Fatalf("expected handshake error frame in report: %+v", report)
	}

	if token := parseHTTPAuthToken("Basic abc, Negotiate " + base64.StdEncoding.EncodeToString(type1)); !hasNTLMType(token, 1) {
		t.Fatalf("parseHTTPAuthToken did not find negotiate NTLM type1: %#v", token)
	}
	if token := parseHTTPAuthToken("NTLM !!!"); token != nil {
		t.Fatalf("invalid base64 token = %#v, want nil", token)
	}
}

func TestWinRMSecurityContextUnwrapAndContextHelpers(t *testing.T) {
	initCipher, err := rc4.NewCipher([]byte("0123456789abcdef"))
	if err != nil {
		t.Fatalf("init rc4: %v", err)
	}
	acceptCipher, err := rc4.NewCipher([]byte("fedcba9876543210"))
	if err != nil {
		t.Fatalf("accept rc4: %v", err)
	}
	ctx := &winrmSecurityContext{
		port:               50000,
		sealCipherInitiate: initCipher,
		sealCipherAccept:   acceptCipher,
		signKeyInitiate:    []byte("init-sign-key"),
		signKeyAccept:      []byte("accept-sign-key"),
	}
	if _, err := ctx.unwrapInitiate([]byte("short")); err == nil {
		t.Fatal("unwrapInitiate should reject short encrypted messages")
	}
	if ctx.initiateSeqNo != 1 {
		t.Fatalf("initiate seq = %d, want increment after unwrap", ctx.initiateSeqNo)
	}
	longMessage := append(bytes.Repeat([]byte{0x00}, 20), []byte("ciphertext")...)
	if _, err := ctx.unwrapAccept(longMessage); err == nil || !strings.Contains(err.Error(), "签") && !strings.Contains(err.Error(), "绛") {
		t.Fatalf("unwrapAccept signature error = %v", err)
	}
	if ctx.acceptSeqNo != 1 {
		t.Fatalf("accept seq = %d, want increment after unwrap", ctx.acceptSeqNo)
	}

	contexts := []*winrmSecurityContext{{port: 1}, {port: 50000}}
	if found := findWinRMContext(contexts, 50000); found == nil || found.port != 50000 {
		t.Fatalf("findWinRMContext existing = %+v", found)
	}
	if found := findWinRMContext(contexts, 404); found != nil {
		t.Fatalf("findWinRMContext missing = %+v", found)
	}
	if err := (&winrmSecurityContext{}).addToken(append([]byte("NTLMSSP\x00"), byte(2))); err != nil {
		t.Fatalf("type2 addToken should be ignored, got %v", err)
	}
	if err := (&winrmSecurityContext{}).addToken(append([]byte("NTLMSSP\x00"), byte(3))); err == nil {
		t.Fatal("short type3 addToken should fail")
	}

	preview, truncated := previewTextByLines([]string{"a", "b", "c"}, 2)
	if preview != "a\nb" || !truncated {
		t.Fatalf("previewTextByLines limited = %q truncated=%v", preview, truncated)
	}
	preview, truncated = previewTextByLines([]string{"a", "b"}, 0)
	if preview != "a\nb" || truncated {
		t.Fatalf("previewTextByLines unlimited = %q truncated=%v", preview, truncated)
	}
}

package engine

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestGenerateSMB3RandomSessionKey(t *testing.T) {
	svc := NewService(nil, nil)
	result, err := svc.GenerateSMB3RandomSessionKey(model.SMB3RandomSessionKeyRequest{
		Username:            "user",
		Domain:              "domain",
		NTLMHash:            "5f4dcc3b5aa765d61d8327deb882cf99",
		NTProofStr:          "00112233445566778899aabbccddeeff",
		EncryptedSessionKey: "11223344556677889900aabbccddeeff",
	})
	if err != nil {
		t.Fatalf("GenerateSMB3RandomSessionKey error = %v", err)
	}
	if result.RandomSessionKey == "" {
		t.Fatal("expected random session key")
	}
}

func TestGenerateSMB3RandomSessionKeyRejectsInvalidHex(t *testing.T) {
	svc := NewService(nil, nil)
	_, err := svc.GenerateSMB3RandomSessionKey(model.SMB3RandomSessionKeyRequest{
		Username:            "user",
		Domain:              "domain",
		NTLMHash:            "xyz",
		NTProofStr:          "00112233445566778899aabbccddeeff",
		EncryptedSessionKey: "11223344556677889900aabbccddeeff",
	})
	if err == nil {
		t.Fatal("expected invalid hex error")
	}
}

func TestGenerateSMB3RandomSessionKeyAllowsEmptyDomain(t *testing.T) {
	svc := NewService(nil, nil)
	result, err := svc.GenerateSMB3RandomSessionKey(model.SMB3RandomSessionKeyRequest{
		Username:            "user",
		Domain:              "",
		NTLMHash:            "5f4dcc3b5aa765d61d8327deb882cf99",
		NTProofStr:          "00112233445566778899aabbccddeeff",
		EncryptedSessionKey: "11223344556677889900aabbccddeeff",
	})
	if err != nil {
		t.Fatalf("GenerateSMB3RandomSessionKey with empty domain error = %v", err)
	}
	if result.RandomSessionKey == "" {
		t.Fatal("expected random session key with empty domain")
	}
}

func TestGenerateSMB3RandomSessionKeyTreatsNullDomainAsEmpty(t *testing.T) {
	svc := NewService(nil, nil)
	withEmptyDomain, err := svc.GenerateSMB3RandomSessionKey(model.SMB3RandomSessionKeyRequest{
		Username:            "user",
		Domain:              "",
		NTLMHash:            "5f4dcc3b5aa765d61d8327deb882cf99",
		NTProofStr:          "00112233445566778899aabbccddeeff",
		EncryptedSessionKey: "11223344556677889900aabbccddeeff",
	})
	if err != nil {
		t.Fatalf("GenerateSMB3RandomSessionKey empty domain error = %v", err)
	}

	withNullDomain, err := svc.GenerateSMB3RandomSessionKey(model.SMB3RandomSessionKeyRequest{
		Username:            "user",
		Domain:              "NULL",
		NTLMHash:            "5f4dcc3b5aa765d61d8327deb882cf99",
		NTProofStr:          "00112233445566778899aabbccddeeff",
		EncryptedSessionKey: "11223344556677889900aabbccddeeff",
	})
	if err != nil {
		t.Fatalf("GenerateSMB3RandomSessionKey NULL domain error = %v", err)
	}

	if withEmptyDomain.RandomSessionKey != withNullDomain.RandomSessionKey {
		t.Fatalf("expected NULL domain to match empty domain, empty=%q null=%q", withEmptyDomain.RandomSessionKey, withNullDomain.RandomSessionKey)
	}
}

func TestListSMB3SessionCandidatesRejectsMissingCapture(t *testing.T) {
	svc := NewService(nil, nil)
	_, err := svc.ListSMB3SessionCandidates()
	if err == nil {
		t.Fatal("expected missing capture error")
	}
	if !strings.Contains(err.Error(), "当前未加载抓包") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestListSMB3SessionCandidatesBuildsDetailedRows(t *testing.T) {
	original := scanSMB3SessionRowsWithDisplayFilter
	defer func() { scanSMB3SessionRowsWithDisplayFilter = original }()

	scanSMB3SessionRowsWithDisplayFilter = func(_ string, fields []string, _ string, onRow func([]string)) error {
		if len(fields) != 13 {
			t.Fatalf("unexpected field count: %d", len(fields))
		}
		onRow([]string{
			"101",
			"Apr 21, 2026 10:00:00",
			"10.0.0.10",
			"",
			"10.0.0.20",
			"",
			"42",
			"0x0000000000000000",
			"0",
			"Administrator",
			"",
			"aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99",
			"11 22 33 44 55 66 77 88 99 00 aa bb cc dd ee ff",
		})
		onRow([]string{
			"102",
			"Apr 21, 2026 10:00:00",
			"10.0.0.20",
			"",
			"10.0.0.10",
			"",
			"42",
			"0x1122334455667788",
			"1",
			"",
			"",
			"",
			"",
		})
		onRow([]string{
			"103",
			"Apr 21, 2026 10:01:00",
			"",
			"fe80::1",
			"",
			"fe80::2",
			"43",
			"0x8899aabbccddeeff",
			"0",
			"user2",
			"NULL",
			"00112233445566778899aabbccddeeff",
			"abcdef0123456789",
		})
		onRow([]string{
			"104",
			"Apr 21, 2026 10:02:00",
			"10.0.0.30",
			"",
			"10.0.0.40",
			"",
			"44",
			"0x8899aabbccddeeff",
			"0",
			"user3",
			"LAB",
			"ffeeddccbbaa99887766554433221100",
			"0011",
		})
		return nil
	}

	svc := NewService(nil, nil)
	svc.pcap = "demo.pcapng"

	rows, err := svc.ListSMB3SessionCandidates()
	if err != nil {
		t.Fatalf("ListSMB3SessionCandidates error = %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("expected 3 candidates, got %d", len(rows))
	}

	first := rows[0]
	if first.SessionID != "0x1122334455667788" {
		t.Fatalf("expected response-backed session id, got %q", first.SessionID)
	}
	if first.Domain != "" {
		t.Fatalf("expected empty domain to be preserved, got %q", first.Domain)
	}
	if !first.Complete {
		t.Fatal("expected first candidate to be complete")
	}
	if first.NTProofStr != "aabbccddeeff00112233445566778899" {
		t.Fatalf("unexpected normalized NTProofStr = %q", first.NTProofStr)
	}
	if first.EncryptedSessionKey != "11223344556677889900aabbccddeeff" {
		t.Fatalf("unexpected normalized encrypted session key = %q", first.EncryptedSessionKey)
	}
	if !strings.Contains(first.DisplayLabel, "0x1122334455667788") || !strings.Contains(first.DisplayLabel, "Administrator") || !strings.Contains(first.DisplayLabel, "10.0.0.10 -> 10.0.0.20") || !strings.Contains(first.DisplayLabel, "帧 #101") {
		t.Fatalf("unexpected display label = %q", first.DisplayLabel)
	}

	second := rows[1]
	if second.SessionID != "0x8899aabbccddeeff" {
		t.Fatalf("unexpected second session id = %q", second.SessionID)
	}
	if second.Domain != "" {
		t.Fatalf("expected NULL domain to be normalized to empty, got %q", second.Domain)
	}
	if second.Src != "fe80::1" || second.Dst != "fe80::2" {
		t.Fatalf("expected ipv6 fallback, got %s -> %s", second.Src, second.Dst)
	}

	third := rows[2]
	if third.SessionID != "0x8899aabbccddeeff" {
		t.Fatalf("expected duplicate session id to be preserved, got %q", third.SessionID)
	}
}

func TestRunWinRMDecryptRejectsMissingCapture(t *testing.T) {
	svc := NewService(nil, nil)
	_, err := svc.RunWinRMDecrypt(model.WinRMDecryptRequest{Port: 5985, AuthMode: "password", Password: "pass"})
	if err == nil {
		t.Fatal("expected missing capture error")
	}
	if !strings.Contains(err.Error(), "当前未加载抓包") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNTOWFV1ProducesNTHash(t *testing.T) {
	got := hex.EncodeToString(ntowfv1("password"))
	if got != "8846f7eaee8fb117ad06bdd830b7586c" {
		t.Fatalf("unexpected ntowfv1(password) = %q", got)
	}
}

func TestExtractWinRMMessageBodiesAllowsSeparatedHex(t *testing.T) {
	bodies := extractWinRMMessageBodies("01 02:03-04")
	if len(bodies) != 1 {
		t.Fatalf("expected one body, got %d", len(bodies))
	}
	if got := hex.EncodeToString(bodies[0]); got != "01020304" {
		t.Fatalf("unexpected decoded payload = %q", got)
	}
}

func TestExtractWinRMMessageBodiesParsesMultipartFileData(t *testing.T) {
	raw := append([]byte("--Encrypted Boundary\r\nOriginalContent: type=application/soap+xml;charset=UTF-8;Length=4\r\n--Encrypted Boundary\r\nContent-Type: application/octet-stream\r\n"), []byte{0x01, 0x02, 0x03, 0x04}...)
	raw = append(raw, []byte("\r\n--Encrypted Boundary--\r\n")...)

	bodies := extractWinRMMessageBodies(string(raw))
	if len(bodies) != 1 {
		t.Fatalf("expected one extracted multipart body, got %d", len(bodies))
	}
	if got := hex.EncodeToString(bodies[0]); got != "01020304" {
		t.Fatalf("unexpected multipart body = %q", got)
	}
}

func TestExtractWinRMMessageBodiesParsesHexEncodedMultipartFileData(t *testing.T) {
	raw := append([]byte("--Encrypted Boundary\r\nOriginalContent: type=application/soap+xml;charset=UTF-8;Length=4\r\n--Encrypted Boundary\r\nContent-Type: application/octet-stream\r\n"), []byte{0x01, 0x02, 0x03, 0x04}...)
	raw = append(raw, []byte("\r\n--Encrypted Boundary--\r\n")...)

	bodies := extractWinRMMessageBodies(hex.EncodeToString(raw))
	if len(bodies) != 1 {
		t.Fatalf("expected one extracted multipart body from hex string, got %d", len(bodies))
	}
	if got := hex.EncodeToString(bodies[0]); got != "01020304" {
		t.Fatalf("unexpected multipart body from hex string = %q", got)
	}
}

func TestExplainWinRMScanErrorIncludesSMB2Hint(t *testing.T) {
	err := explainWinRMScanError(fmt.Errorf("wait tshark: exit status 1: tshark: Error loading table 'Secret session key to use for decryption': smb2_seskey_list:5: unexpected char 6"))
	if !strings.Contains(err, "SMB2 Secret Session Key 表格式错误") {
		t.Fatalf("expected smb2 hint, got %q", err)
	}
	if !strings.Contains(err, "smb2_seskey_list") {
		t.Fatalf("expected raw tshark detail to be preserved, got %q", err)
	}
}

func TestScanWinRMRowsFallsBackWhenMimeMultipartFieldUnsupported(t *testing.T) {
	original := scanWinRMRowsWithDisplayFilter
	defer func() { scanWinRMRowsWithDisplayFilter = original }()

	calls := 0
	scanWinRMRowsWithDisplayFilter = func(_ string, fields []string, _ string, onRow func([]string)) error {
		calls++
		lastField := fields[len(fields)-1]
		switch lastField {
		case "mime_multipart.data":
			return fmt.Errorf("wait tshark: exit status 1: Some fields aren't valid: mime_multipart.data")
		case "http.file_data":
			onRow([]string{"1272", "time", "1.1.1.1", "2.2.2.2", "5985", "40000", "", "", "aa bb"})
			return nil
		default:
			return fmt.Errorf("unexpected fallback field %s", lastField)
		}
	}

	rows, err := scanWinRMRows("demo.pcapng", 5985)
	if err != nil {
		t.Fatalf("scanWinRMRows error = %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected 2 scan attempts, got %d", calls)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	if rows[0].mimeData != "aa bb" {
		t.Fatalf("unexpected mimeData = %q", rows[0].mimeData)
	}
}

func TestScanWinRMRowsDecoratesSMB2PreferenceError(t *testing.T) {
	original := scanWinRMRowsWithDisplayFilter
	defer func() { scanWinRMRowsWithDisplayFilter = original }()

	scanWinRMRowsWithDisplayFilter = func(_ string, _ []string, _ string, _ func([]string)) error {
		return fmt.Errorf("wait tshark: exit status 1: tshark: Error loading table 'Secret session key to use for decryption': smb2_seskey_list:5: unexpected char 6")
	}

	_, err := scanWinRMRows("demo.pcapng", 5985)
	if err == nil {
		t.Fatal("expected smb2 preference error")
	}
	if !strings.Contains(err.Error(), "SMB2 Secret Session Key 表格式错误") {
		t.Fatalf("expected decorated hint, got %q", err)
	}
}

func TestDecryptWinRMRowsAcceptsSeparatedCiphertext(t *testing.T) {
	rows := []winrmMessageRow{{
		frameNumber: "1272",
		timestamp:   "time",
		src:         "10.0.0.1",
		dst:         "10.0.0.2",
		srcPort:     "40000",
		dstPort:     "5985",
		mimeData:    "01 02:03-04",
	}}
	text, frameCount, err := decryptWinRMRows(rows, 5985, []byte("0123456789abcdef"))
	if err != nil {
		t.Fatalf("decryptWinRMRows error = %v", err)
	}
	if frameCount != 0 {
		t.Fatalf("expected no decrypted frames without NTLM context, got %d", frameCount)
	}
	if text != "" {
		t.Fatalf("expected empty output without NTLM context, got %q", text)
	}
}

func TestWinRMSecurityContextAddTokenUppercasesUsernameOnly(t *testing.T) {
	ntHash := ntowfv1("Password123!")
	challenge := mustDecodeHex(t, "00112233445566778899aabbccddeeff")
	token := buildNTLMType3TokenForTest(t, challenge, "DomAin", "alice", 0x00000001)

	ctx := &winrmSecurityContext{port: 40000, ntHash: append([]byte(nil), ntHash...)}
	if err := ctx.addToken(token); err != nil {
		t.Fatalf("addToken error = %v", err)
	}

	wantResponseKey := hmacMD5(ntHash, utf16LE(strings.ToUpper("alice")+"DomAin"))
	wantSessionKey := hmacMD5(wantResponseKey, challenge[:16])
	if got := hex.EncodeToString(ctx.sessionKey); got != hex.EncodeToString(wantSessionKey) {
		t.Fatalf("unexpected session key: want %s got %s", hex.EncodeToString(wantSessionKey), got)
	}
}

func TestAppendWinRMExtractionPreservesRawXMLAndAddsCommand(t *testing.T) {
	raw := `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"><s:Body><rsp:CommandLine><rsp:Command>"cmd"</rsp:Command></rsp:CommandLine></s:Body></s:Envelope>`

	block, extracted := appendWinRMExtraction(raw)
	if !extracted {
		t.Fatal("expected extraction flag to be true")
	}
	if !strings.Contains(block, raw) {
		t.Fatal("expected raw xml to be preserved")
	}
	if !strings.Contains(block, "[extract]") {
		t.Fatal("expected extract block")
	}
	if !strings.Contains(block, `command:`) || !strings.Contains(block, `"cmd"`) {
		t.Fatalf("expected command extract, got %q", block)
	}
}

func TestExtractWinRMCommandOutputDecodesStdoutAndStdin(t *testing.T) {
	raw := `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"><s:Body><rsp:Send><rsp:Stream Name="stdin">d2hvYW1pDQo=</rsp:Stream></rsp:Send><rsp:ReceiveResponse><rsp:Stream Name="stdout">cGNcYWRtaW5pc3RyYXRvcg0K</rsp:Stream></rsp:ReceiveResponse></s:Body></s:Envelope>`

	got := extractWinRMCommandOutput(raw)
	if !strings.Contains(got, "stdin:") || !strings.Contains(got, "whoami") {
		t.Fatalf("expected stdin extract, got %q", got)
	}
	if !strings.Contains(got, "stdout:") || !strings.Contains(got, `pc\administrator`) {
		t.Fatalf("expected stdout extract, got %q", got)
	}
}

func TestExtractWinRMCommandOutputDecodesGB18030(t *testing.T) {
	raw := `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"><s:Body><rsp:ReceiveResponse><rsp:Stream Name="stdout">xKzIz834udgNCg==</rsp:Stream></rsp:ReceiveResponse></s:Body></s:Envelope>`

	got := extractWinRMCommandOutput(raw)
	if !strings.Contains(got, "默认网关") {
		t.Fatalf("expected GB18030 stdout to be decoded, got %q", got)
	}
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("DecodeString(%q) error = %v", value, err)
	}
	return decoded
}

func buildNTLMType3TokenForTest(t *testing.T, ntChallenge []byte, domain string, username string, flags uint32) []byte {
	t.Helper()
	token := make([]byte, 64)
	copy(token, []byte("NTLMSSP\x00"))
	token[8] = 0x03

	appendField := func(offset int, value []byte) {
		fieldOffset := len(token)
		token = append(token, value...)
		binary.LittleEndian.PutUint16(token[offset:offset+2], uint16(len(value)))
		binary.LittleEndian.PutUint16(token[offset+2:offset+4], uint16(len(value)))
		binary.LittleEndian.PutUint32(token[offset+4:offset+8], uint32(fieldOffset))
	}

	appendField(20, ntChallenge)
	appendField(28, utf16LE(domain))
	appendField(36, utf16LE(username))
	binary.LittleEndian.PutUint32(token[60:64], flags)

	return token
}

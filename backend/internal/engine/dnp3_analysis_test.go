package engine

import (
	"encoding/hex"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

// buildDNP3RawHex constructs a raw Ethernet/IPv4/TCP/DNP3 frame for testing.
// It builds minimal Eth+IP+TCP headers + DNP3 link+app layer.
func buildDNP3RawHex(appPayload []byte, srcAddr, dstAddr int, control byte) string {
	// Build DNP3 link layer
	linkLen := 5 + len(appPayload) // control(1) + dst(2) + src(2) + user data
	// With CRCs every 16 bytes of user data
	userDataWithCRC := addDNP3CRCs(appPayload)
	totalUserData := len(appPayload)
	_ = totalUserData

	linkHeader := []byte{
		0x05, 0x64, // start
		byte(5 + len(userDataWithCRC)), // length
		control,
		byte(dstAddr & 0xFF), byte((dstAddr >> 8) & 0xFF),
		byte(srcAddr & 0xFF), byte((srcAddr >> 8) & 0xFF),
		0x00, 0x00, // CRC placeholder
	}
	_ = linkLen
	dnp3Frame := append(linkHeader, userDataWithCRC...)

	// Build minimal TCP header (20 bytes) with dst port 20000
	tcpHeader := []byte{
		0xC0, 0x00, // src port 49152
		0x4E, 0x20, // dst port 20000
		0x00, 0x00, 0x00, 0x01, // seq
		0x00, 0x00, 0x00, 0x01, // ack
		0x50, 0x00, 0x00, 0x00, // data offset + flags
		0x00, 0x00, 0x00, 0x00, // window + checksum
	}
	_ = linkLen

	// Build minimal IP header (20 bytes)
	totalLen := 20 + len(tcpHeader) + len(dnp3Frame)
	ipHeader := []byte{
		0x45, 0x00,
		byte(totalLen >> 8), byte(totalLen & 0xFF),
		0x00, 0x00, 0x00, 0x00,
		0x40, 0x06, 0x00, 0x00, // TTL=64, proto=TCP
		0xC0, 0xA8, 0x01, 0x01, // src 192.168.1.1
		0x0A, 0x00, 0x00, 0x01, // dst 10.0.0.1
	}

	// Build minimal Ethernet header (14 bytes)
	ethHeader := []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
		0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
		0x08, 0x00, // IPv4
	}

	full := append(ethHeader, ipHeader...)
	full = append(full, tcpHeader...)
	full = append(full, dnp3Frame...)
	return hex.EncodeToString(full)
}

// addDNP3CRCs inserts zero CRC bytes every 16 bytes of user data (simplified).
func addDNP3CRCs(data []byte) []byte {
	var out []byte
	for i := 0; i < len(data); i += 16 {
		end := i + 16
		if end > len(data) {
			end = len(data)
		}
		out = append(out, data[i:end]...)
		out = append(out, 0x00, 0x00) // CRC placeholder
	}
	return out
}

func TestDNP3FunctionCodeName(t *testing.T) {
	tests := []struct {
		fc   int
		want string
	}{
		{0x00, "Confirm"},
		{0x01, "Read"},
		{0x02, "Write"},
		{0x03, "Select"},
		{0x04, "Operate"},
		{0x05, "Direct Operate"},
		{0x0D, "Cold Restart"},
		{0x0E, "Warm Restart"},
		{0x14, "Enable Unsolicited"},
		{0x15, "Disable Unsolicited"},
		{0x81, "Response"},
		{0x82, "Unsolicited Response"},
		{0xFE, "Response 0xFE"},
	}
	for _, tc := range tests {
		got := dnp3FunctionCodeName(tc.fc)
		if got != tc.want {
			t.Errorf("dnp3FunctionCodeName(0x%02X) = %q, want %q", tc.fc, got, tc.want)
		}
	}
}

func TestDNP3IsControlFunction(t *testing.T) {
	controlFCs := []int{0x03, 0x04, 0x05, 0x0D, 0x0E, 0x02, 0x14, 0x15}
	for _, fc := range controlFCs {
		if !dnp3IsControlFunction(fc) {
			t.Errorf("expected dnp3IsControlFunction(0x%02X) = true", fc)
		}
	}
	nonControlFCs := []int{0x00, 0x01, 0x81, 0x82}
	for _, fc := range nonControlFCs {
		if dnp3IsControlFunction(fc) {
			t.Errorf("expected dnp3IsControlFunction(0x%02X) = false", fc)
		}
	}
}

func TestDNP3IsDangerousControl(t *testing.T) {
	dangerous := []int{0x0D, 0x0E, 0x12, 0x0F, 0x10}
	for _, fc := range dangerous {
		if !dnp3IsDangerousControl(fc) {
			t.Errorf("expected dnp3IsDangerousControl(0x%02X) = true", fc)
		}
	}
	safe := []int{0x01, 0x02, 0x03, 0x04}
	for _, fc := range safe {
		if dnp3IsDangerousControl(fc) {
			t.Errorf("expected dnp3IsDangerousControl(0x%02X) = false", fc)
		}
	}
}

func TestDNP3ObjectName(t *testing.T) {
	tests := []struct {
		group, variation int
		want             string
	}{
		{1, 1, "Binary Input (G1V1)"},
		{30, 1, "Analog Input (G30V1)"},
		{20, 1, "Counter (G20V1)"},
		{40, 1, "Analog Output (G40V1)"},
		{99, 1, "Group 99 Var 1"},
	}
	for _, tc := range tests {
		got := dnp3ObjectName(tc.group, tc.variation)
		if got != tc.want {
			t.Errorf("dnp3ObjectName(%d, %d) = %q, want %q", tc.group, tc.variation, got, tc.want)
		}
	}
}

func TestDNP3QualifierName(t *testing.T) {
	tests := []struct {
		qp   byte
		want string
	}{
		{0x00, "1-byte start/stop"},
		{0x01, "1-byte start/count"},
		{0x06, "no range, count"},
	}
	for _, tc := range tests {
		got := dnp3QualifierName(tc.qp)
		if got != tc.want {
			t.Errorf("dnp3QualifierName(0x%02X) = %q, want %q", tc.qp, got, tc.want)
		}
	}
}

func TestDNP3IsUnauthorizedFC(t *testing.T) {
	// Standard FCs should not be unauthorized
	standard := []int{0x01, 0x02, 0x03, 0x04, 0x05, 0x0D, 0x0E, 0x81, 0x82}
	for _, fc := range standard {
		if dnp3IsUnauthorizedFC(fc) {
			t.Errorf("expected dnp3IsUnauthorizedFC(0x%02X) = false", fc)
		}
	}
	// Unknown FCs should be unauthorized
	unauthorized := []int{0x7F, 0x50, 0x40}
	for _, fc := range unauthorized {
		if !dnp3IsUnauthorizedFC(fc) {
			t.Errorf("expected dnp3IsUnauthorizedFC(0x%02X) = true", fc)
		}
	}
}

func TestStripDNP3CRCs(t *testing.T) {
	// 16 data bytes + 2 CRC bytes
	input := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0xAA, 0xBB}
	result := stripDNP3CRCs(input)
	if len(result) != 16 {
		t.Errorf("expected 16 bytes, got %d", len(result))
	}
	if result[0] != 1 || result[15] != 16 {
		t.Errorf("unexpected data content: %v", result)
	}
}

func TestStripDNP3CRCsMultipleChunks(t *testing.T) {
	// 32 data bytes + 4 CRC bytes
	input := make([]byte, 36)
	for i := 0; i < 32; i++ {
		input[i] = byte(i)
	}
	// CRC placeholders at 16-17, 34-35
	input[16] = 0xCC
	input[17] = 0xDD
	input[34] = 0xEE
	input[35] = 0xFF

	result := stripDNP3CRCs(input)
	if len(result) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(result))
	}
}

func TestFormatDNP3IIN(t *testing.T) {
	tests := []struct {
		iin  [2]byte
		want string
	}{
		{[2]byte{0, 0}, ""},
		{[2]byte{0x80, 0}, "Device_Restart"},
		{[2]byte{0x20, 0}, "Local_Control"},
		{[2]byte{0, 0x01}, "Function_Not_Supported"},
		{[2]byte{0x80, 0x01}, "Device_Restart | Function_Not_Supported"},
	}
	for _, tc := range tests {
		got := formatDNP3IIN(tc.iin)
		if got != tc.want {
			t.Errorf("formatDNP3IIN(%+v) = %q, want %q", tc.iin, got, tc.want)
		}
	}
}

func TestParseDNP3Objects(t *testing.T) {
	// Object header: Group 30 (Analog Input), Variation 1 (32-bit with flag)
	// Qualifier 0x01 (1-byte start/count), start=0, count=2
	// Each value: 1 byte flag + 4 bytes int32
	data := []byte{
		30, 1, // group 30, variation 1
		0x01, // qualifier: 1-byte start/count
		0x00, // start index = 0
		0x02, // count = 2
		// Point 0: flag=0x01, value=100 (0x64, 0x00, 0x00, 0x00)
		0x01, 0x64, 0x00, 0x00, 0x00,
		// Point 1: flag=0x01, value=-50 (0xCE, 0xFF, 0xFF, 0xFF)
		0x01, 0xCE, 0xFF, 0xFF, 0xFF,
	}

	objects := parseDNP3Objects(data)
	if len(objects) != 2 {
		t.Fatalf("expected 2 data objects, got %d", len(objects))
	}
	if objects[0].Group != 30 || objects[0].Variation != 1 {
		t.Errorf("object[0] group/variation = %d/%d, want 30/1", objects[0].Group, objects[0].Variation)
	}
	if objects[0].PointIndex != 0 {
		t.Errorf("object[0] point index = %d, want 0", objects[0].PointIndex)
	}
	if objects[1].PointIndex != 1 {
		t.Errorf("object[1] point index = %d, want 1", objects[1].PointIndex)
	}
}

func TestParseDNP3ObjectsBinaryInput(t *testing.T) {
	// Group 1 (Binary Input), Variation 1, 1-byte start/count
	data := []byte{
		1, 1, // group 1, var 1
		0x01, // qualifier
		0x00, // start
		0x03, // count = 3
		0x80, // point 0: ON (bit 7 set)
		0x00, // point 1: OFF
		0x80, // point 2: ON
	}

	objects := parseDNP3Objects(data)
	if len(objects) != 3 {
		t.Fatalf("expected 3 objects, got %d", len(objects))
	}
	if objects[0].Value != "ON" {
		t.Errorf("object[0] value = %q, want ON", objects[0].Value)
	}
	if objects[1].Value != "OFF" {
		t.Errorf("object[1] value = %q, want OFF", objects[1].Value)
	}
}

func TestAnalyzeDNP3Packets(t *testing.T) {
	// Build a Read request app payload
	readReq := []byte{
		0xC0,  // control: FIR=1, FIN=1
		0x01,  // function code: Read
		30, 1, // Group 30, Var 1 (Analog Input)
		0x01,                         // qualifier: 1-byte start/count
		0x00,                         // start
		0x01,                         // count = 1
		0x01, 0x00, 0x00, 0x00, 0x00, // flag + value
	}

	// Build a Response app payload
	readResp := []byte{
		0xC0,       // control: FIR=1, FIN=1
		0x81,       // function code: Response
		0x00, 0x00, // IIN (no flags)
		30, 1, // Group 30, Var 1
		0x01,                         // qualifier
		0x00,                         // start
		0x01,                         // count
		0x01, 0x64, 0x00, 0x00, 0x00, // flag + value = 100
	}

	packets := []DNP3RawPacket{
		{
			PacketID: 1,
			Time:     "2026-01-01T00:00:01Z",
			Src:      "192.168.1.1",
			Dst:      "10.0.0.1",
			RawHex:   buildDNP3RawHex(readReq, 1, 10, 0xC0),
		},
		{
			PacketID: 2,
			Time:     "2026-01-01T00:00:02Z",
			Src:      "10.0.0.1",
			Dst:      "192.168.1.1",
			RawHex:   buildDNP3RawHex(readResp, 10, 1, 0xC0),
		},
	}

	analysis := AnalyzeDNP3Packets(packets)
	if analysis.TotalFrames != 2 {
		t.Errorf("TotalFrames = %d, want 2", analysis.TotalFrames)
	}
	if analysis.Requests != 1 {
		t.Errorf("Requests = %d, want 1", analysis.Requests)
	}
	if analysis.Responses != 1 {
		t.Errorf("Responses = %d, want 1", analysis.Responses)
	}
	if len(analysis.FunctionCodes) == 0 {
		t.Error("expected function codes to be populated")
	}
	if len(analysis.Frames) != 2 {
		t.Fatalf("expected 2 frames, got %d", len(analysis.Frames))
	}
}

func TestAnalyzeDNP3PacketsDangerousControl(t *testing.T) {
	// Cold Restart request
	restartReq := []byte{
		0xC0, // control
		0x0D, // function code: Cold Restart
	}

	packets := []DNP3RawPacket{
		{
			PacketID: 10,
			Time:     "2026-01-01T00:00:10Z",
			Src:      "192.168.1.100",
			Dst:      "10.0.0.5",
			RawHex:   buildDNP3RawHex(restartReq, 100, 5, 0xC0),
		},
	}

	analysis := AnalyzeDNP3Packets(packets)
	if analysis.TotalFrames != 1 {
		t.Fatalf("TotalFrames = %d, want 1", analysis.TotalFrames)
	}

	// Should detect suspicious control anomaly
	foundSuspicious := false
	for _, a := range analysis.Anomalies {
		if a.Type == "suspicious_control" {
			foundSuspicious = true
			break
		}
	}
	if !foundSuspicious {
		t.Error("expected suspicious_control anomaly for Cold Restart")
	}
}

func TestAnalyzeDNP3PacketsAnomalousResponse(t *testing.T) {
	// Response with Device_Restart IIN flag
	resp := []byte{
		0xC0,       // control
		0x81,       // function code: Response
		0x80, 0x00, // IIN: Device_Restart
	}

	packets := []DNP3RawPacket{
		{
			PacketID: 20,
			Time:     "2026-01-01T00:00:20Z",
			Src:      "10.0.0.5",
			Dst:      "192.168.1.100",
			RawHex:   buildDNP3RawHex(resp, 5, 100, 0xC0),
		},
	}

	analysis := AnalyzeDNP3Packets(packets)
	if analysis.TotalFrames != 1 {
		t.Fatalf("TotalFrames = %d, want 1", analysis.TotalFrames)
	}

	foundAnomalous := false
	for _, a := range analysis.Anomalies {
		if a.Type == "anomalous_response" {
			foundAnomalous = true
			break
		}
	}
	if !foundAnomalous {
		t.Error("expected anomalous_response for Device_Restart IIN flag")
	}
}

func TestAnalyzeDNP3PacketsUnauthorizedFC(t *testing.T) {
	// Unknown function code 0x50
	unknownFC := []byte{
		0xC0, // control
		0x50, // unknown function code
	}

	packets := []DNP3RawPacket{
		{
			PacketID: 30,
			Time:     "2026-01-01T00:00:30Z",
			Src:      "192.168.1.200",
			Dst:      "10.0.0.5",
			RawHex:   buildDNP3RawHex(unknownFC, 200, 5, 0xC0),
		},
	}

	analysis := AnalyzeDNP3Packets(packets)
	if analysis.TotalFrames != 1 {
		t.Fatalf("TotalFrames = %d, want 1", analysis.TotalFrames)
	}

	foundUnauthorized := false
	for _, a := range analysis.Anomalies {
		if a.Type == "unauthorized_fc" {
			foundUnauthorized = true
			break
		}
	}
	if !foundUnauthorized {
		t.Error("expected unauthorized_fc anomaly for function code 0x50")
	}
}

func TestAnalyzeDNP3PacketsEmpty(t *testing.T) {
	analysis := AnalyzeDNP3Packets(nil)
	if analysis.TotalFrames != 0 {
		t.Errorf("TotalFrames = %d, want 0", analysis.TotalFrames)
	}
	if len(analysis.Anomalies) != 0 {
		t.Errorf("expected no anomalies, got %d", len(analysis.Anomalies))
	}
}

func TestParseDNP3PacketInvalidHex(t *testing.T) {
	frame := ParseDNP3Packet(1, "", "", "", "not-hex")
	if frame != nil {
		t.Error("expected nil for invalid hex")
	}

	frame = ParseDNP3Packet(1, "", "", "", "")
	if frame != nil {
		t.Error("expected nil for empty hex")
	}
}

func TestParseDNP3PacketNoDNP3Start(t *testing.T) {
	// Raw bytes without DNP3 start marker
	raw := hex.EncodeToString([]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09})
	frame := ParseDNP3Packet(1, "", "", "", raw)
	if frame != nil {
		t.Error("expected nil when no DNP3 start bytes found")
	}
}

func TestDNP3ReadOperationSummary(t *testing.T) {
	// Read request with Analog Input objects
	readReq := []byte{
		0xC0,  // control: FIR=1, FIN=1
		0x01,  // Read
		30, 1, // Group 30, Var 1
		0x01,                         // qualifier: 1-byte start/count
		0x00,                         // start
		0x01,                         // count
		0x01, 0x00, 0x00, 0x00, 0x00, // value
	}

	rawHex := buildDNP3RawHex(readReq, 1, 10, 0xC0)
	frame := ParseDNP3Packet(1, "2026-01-01T00:00:01Z", "192.168.1.1", "10.0.0.1", rawHex)
	if frame == nil {
		t.Fatal("expected parsed frame, got nil")
	}

	if frame.FunctionCode != 0x01 {
		t.Errorf("FunctionCode = 0x%02X, want 0x01", frame.FunctionCode)
	}
	if frame.FunctionName != "Read" {
		t.Errorf("FunctionName = %q, want Read", frame.FunctionName)
	}
	if frame.Direction != "request" {
		t.Errorf("Direction = %q, want request", frame.Direction)
	}
	if len(frame.DataObjects) == 0 {
		t.Error("expected data objects to be populated")
	}
	if frame.Summary == "" {
		t.Error("expected non-empty summary")
	}
}

func TestDNP3ResponseWithIIN(t *testing.T) {
	resp := []byte{
		0xC0,       // control
		0x81,       // Response
		0x20, 0x00, // IIN: Local_Control
	}

	rawHex := buildDNP3RawHex(resp, 10, 1, 0xC0)
	frame := ParseDNP3Packet(2, "2026-01-01T00:00:02Z", "10.0.0.1", "192.168.1.1", rawHex)
	if frame == nil {
		t.Fatal("expected parsed frame, got nil")
	}

	if frame.Direction != "response" {
		t.Errorf("Direction = %q, want response", frame.Direction)
	}
	if frame.IIN != "Local_Control" {
		t.Errorf("IIN = %q, want Local_Control", frame.IIN)
	}
}

func TestDNP3Notes(t *testing.T) {
	tests := []struct {
		name     string
		analysis model.DNP3Analysis
		wantMin  int
	}{
		{
			name: "with frames",
			analysis: model.DNP3Analysis{
				TotalFrames: 10,
				Requests:    5,
				Responses:   5,
			},
			wantMin: 1,
		},
		{
			name: "with anomalies",
			analysis: model.DNP3Analysis{
				TotalFrames: 5,
				Anomalies: []model.DNP3Anomaly{
					{Severity: "high", Type: "unauthorized_fc"},
				},
			},
			wantMin: 2,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			notes := buildDNP3Notes(tc.analysis)
			if len(notes) < tc.wantMin {
				t.Errorf("got %d notes, want at least %d", len(notes), tc.wantMin)
			}
		})
	}
}

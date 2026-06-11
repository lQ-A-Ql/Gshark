package tshark

import (
	"reflect"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestIndustrialProtocolLabelHelpersCoverKnownAndFallbackValues(t *testing.T) {
	for raw, want := range map[int]string{
		1: "Job",
		2: "Ack",
		3: "Ack-Data",
		7: "Userdata",
		9: "ROSCTR 9",
		0: "",
	} {
		if got := s7ROSCTRName(raw); got != want {
			t.Fatalf("s7ROSCTRName(%d) = %q, want %q", raw, got, want)
		}
	}
	for raw, want := range map[int]string{
		4:   "Read Var",
		5:   "Write Var",
		26:  "Request Download",
		27:  "Download Block",
		28:  "Download Ended",
		29:  "Start Upload",
		30:  "Upload",
		31:  "End Upload",
		240: "Setup Communication",
		99:  "Func 99",
		0:   "",
	} {
		if got := s7FunctionName(raw); got != want {
			t.Fatalf("s7FunctionName(%d) = %q, want %q", raw, got, want)
		}
	}
	if got := formatS7Target("1", "0x84", "4"); got != "DB 1 / DB / Byte 4" {
		t.Fatalf("formatS7Target() = %q", got)
	}
	for raw, want := range map[string]string{
		"0x81": "Inputs",
		"0x82": "Outputs",
		"0x83": "Merkers",
		"0x84": "DB",
		"0x1c": "Counters",
		"0x1d": "Timers",
		"0xff": "Area 0Xff",
		"":     "",
	} {
		if got := s7AreaName(raw); got != want {
			t.Fatalf("s7AreaName(%q) = %q, want %q", raw, got, want)
		}
	}

	for raw, want := range map[string]string{
		"0":   "Confirm",
		"1":   "Read",
		"2":   "Write",
		"3":   "Select",
		"4":   "Operate",
		"5":   "Direct Operate",
		"13":  "Cold Restart",
		"14":  "Warm Restart",
		"20":  "Enable Unsolicited",
		"21":  "Disable Unsolicited",
		"129": "Response",
		"130": "Unsolicited Response",
		"99":  "App Func 99",
		"":    "Confirm",
	} {
		if got := dnp3AppFunctionName(raw); got != want {
			t.Fatalf("dnp3AppFunctionName(%q) = %q, want %q", raw, got, want)
		}
	}
	for raw, want := range map[string]string{
		"0":  "Reset Link",
		"3":  "Confirmed User Data",
		"4":  "Unconfirmed User Data",
		"9":  "Request Link Status",
		"11": "Link Status",
		"12": "Link Func 12",
		"":   "Reset Link",
	} {
		if got := dnp3LinkFunctionName(raw); got != want {
			t.Fatalf("dnp3LinkFunctionName(%q) = %q, want %q", raw, got, want)
		}
	}
	if got := formatDNPAddress("1", ""); got != "1 -> unknown" {
		t.Fatalf("formatDNPAddress() = %q", got)
	}
	if got := formatDNPObjectTarget("12", "7", "1"); got != "Obj 12 / Point 7 / Count 1" {
		t.Fatalf("formatDNPObjectTarget() = %q", got)
	}
}

func TestIndustrialCIPBACnetIECOPCUAAndPROFINETLabels(t *testing.T) {
	for raw, want := range map[string]string{
		"0x01": "Get Attributes All",
		"0x03": "Get Attribute List",
		"0x04": "Set Attribute List",
		"0x0e": "Get Attribute Single",
		"0x10": "Set Attribute Single",
		"0x4c": "Read Tag",
		"0x4d": "Write Tag",
		"0x52": "Read Modify Write",
		"0xff": "Service 0XFF",
		"":     "",
	} {
		if got := cipServiceName(raw); got != want {
			t.Fatalf("cipServiceName(%q) = %q, want %q", raw, got, want)
		}
	}
	for raw, want := range map[string]string{
		"0x0004": "List Services",
		"0x0063": "List Identity",
		"0x0064": "List Interfaces",
		"0x0065": "Register Session",
		"0x0066": "Unregister Session",
		"0x006f": "Send RR Data",
		"0x0070": "Send Unit Data",
		"0x9999": "Command 0X9999",
		"":       "",
	} {
		if got := enipCommandName(raw); got != want {
			t.Fatalf("enipCommandName(%q) = %q, want %q", raw, got, want)
		}
	}
	if got := formatCIPTarget("0x6b", "0x01", "0x03", "Pump.Speed", "123", "PLC"); got != "Class 0X6b / Inst 0X01 / Attr 0X03 / Tag Pump.Speed / Vendor 123 / PLC" {
		t.Fatalf("formatCIPTarget() = %q", got)
	}
	for raw, want := range map[string]string{
		"":     "",
		"0":    "Success",
		"0x01": "Connection Failure",
		"0x02": "Resource Unavailable",
		"0x04": "Path Segment Error",
		"0x05": "Path Destination Unknown",
		"0x0e": "Attribute Not Settable",
		"0x13": "Not Enough Data",
		"0xff": "General Status 0XFF",
	} {
		if got := cipGeneralStatusName(raw); got != want {
			t.Fatalf("cipGeneralStatusName(%q) = %q, want %q", raw, got, want)
		}
	}

	for raw, want := range map[string]string{
		"0": "Confirmed Request",
		"1": "Unconfirmed Request",
		"2": "Simple Ack",
		"3": "Complex Ack",
		"5": "Error",
		"6": "Reject",
		"7": "Abort",
		"9": "Message Type 9",
		"":  "Confirmed Request",
	} {
		if got := bacnetMessageTypeName(raw); got != want {
			t.Fatalf("bacnetMessageTypeName(%q) = %q, want %q", raw, got, want)
		}
	}
	for raw, want := range map[string]string{
		"5":  "Subscribe COV",
		"8":  "Read Property",
		"9":  "Read Property Conditional",
		"12": "Write Property",
		"14": "Device Communication Control",
		"15": "Confirmed Private Transfer",
		"18": "Reinitialize Device",
		"26": "Read Range",
		"99": "Confirmed Service 99",
		"":   "",
	} {
		if got := bacnetServiceName(raw, true); got != want {
			t.Fatalf("bacnetServiceName(%q,true) = %q, want %q", raw, got, want)
		}
	}
	for raw, want := range map[string]string{
		"2":  "I-Am",
		"3":  "I-Have",
		"7":  "Who-Is",
		"8":  "Who-Has",
		"9":  "UTCTimeSync",
		"10": "TimeSync",
		"99": "Unconfirmed Service 99",
	} {
		if got := bacnetServiceName(raw, false); got != want {
			t.Fatalf("bacnetServiceName(%q,false) = %q, want %q", raw, got, want)
		}
	}

	for raw, want := range map[string]string{
		"1":   "M_SP_NA_1 Single Point",
		"3":   "M_DP_NA_1 Double Point",
		"9":   "M_ME_NA_1 Measured Value",
		"13":  "M_ME_NC_1 Float",
		"30":  "M_SP_TB_1 Single Point CP56",
		"45":  "C_SC_NA_1 Single Command",
		"46":  "C_DC_NA_1 Double Command",
		"50":  "C_SE_NC_1 Setpoint Float",
		"100": "C_IC_NA_1 Interrogation",
		"103": "C_CS_NA_1 Clock Sync",
		"99":  "Type 99",
		"":    "",
	} {
		if got := iec104TypeName(raw); got != want {
			t.Fatalf("iec104TypeName(%q) = %q, want %q", raw, got, want)
		}
	}
	for raw, want := range map[string]string{
		"1":  "Periodic/Cyclic",
		"3":  "Spontaneous",
		"5":  "Requested",
		"6":  "Activation",
		"7":  "Activation Confirmation",
		"8":  "Deactivation",
		"10": "Activation Termination",
		"20": "Interrogated by Station",
		"99": "Cause 99",
		"":   "",
	} {
		if got := iec104CauseName(raw); got != want {
			t.Fatalf("iec104CauseName(%q) = %q, want %q", raw, got, want)
		}
	}

	for raw, want := range map[string]string{
		"397": "FindServers",
		"428": "GetEndpoints",
		"461": "CreateSession",
		"467": "ActivateSession",
		"473": "CloseSession",
		"527": "Read",
		"530": "Write",
		"629": "Browse",
		"787": "Call",
		"999": "ServiceNode 999",
		"":    "",
	} {
		if got := opcuaServiceName(raw); got != want {
			t.Fatalf("opcuaServiceName(%q) = %q, want %q", raw, got, want)
		}
	}

	if got := profinetDCPServiceName("3", "0"); got != "DCP Get" {
		t.Fatalf("profinetDCPServiceName get = %q", got)
	}
	if got := profinetDCPServiceName("3", "1"); got != "DCP Get Response" {
		t.Fatalf("profinetDCPServiceName get response = %q", got)
	}
	if got := profinetDCPServiceName("4", "0"); got != "DCP Set" {
		t.Fatalf("profinetDCPServiceName set = %q", got)
	}
	if got := profinetDCPServiceName("4", "1"); got != "DCP Set Response" {
		t.Fatalf("profinetDCPServiceName set response = %q", got)
	}
	if got := profinetDCPServiceName("5", "0"); got != "DCP Identify" {
		t.Fatalf("profinetDCPServiceName identify = %q", got)
	}
	if got := profinetDCPServiceName("9", "2"); got != "DCP 9 2" {
		t.Fatalf("profinetDCPServiceName fallback = %q", got)
	}
	if got := profinetDCPServiceName("", ""); got != "" {
		t.Fatalf("profinetDCPServiceName empty = %q", got)
	}
	if got := pnioOperationLabel("1", "IOCARSingle", "0x01", "0x02", "3"); got != "Op 1 / IOCARSingle / IOCRType 0X01 / IOCRRef 0X02 / IOCRCount 3" {
		t.Fatalf("pnioOperationLabel() = %q", got)
	}
	if got := pnioResultLabel("0x81", "0x82", "0x83", "0x84"); got != "ErrorCode 0X81 / Decode 0X82 / Code1 0X83 / Code2 0X84" {
		t.Fatalf("pnioResultLabel() = %q", got)
	}
	if got := formatProtocolError("Err", "0x01", "0x02"); got != "Err 0X01 / detail 0X02" {
		t.Fatalf("formatProtocolError() = %q", got)
	}
	if got := nonEmptyPrefixed("Tag", " value "); got != "Tag value" {
		t.Fatalf("nonEmptyPrefixed() = %q", got)
	}
}

func TestVehicleProtocolHelpersAndRecommendations(t *testing.T) {
	protocols := detectVehicleProtocols("eth:can:j1939:doip:uds:kwp2000:obdii:xcp", "", "0x123", "65226", "0x0005", "0x22", "1", "13400", "aa")
	wantProtocols := []string{"CAN", "J1939", "DoIP", "XCP", "UDS", "KWP2000", "OBD-II"}
	if !reflect.DeepEqual(protocols, wantProtocols) {
		t.Fatalf("detectVehicleProtocols() = %+v", protocols)
	}
	if !containsString(protocols, "CAN") || containsString(protocols, "LIN") {
		t.Fatalf("containsString helper failed for %+v", protocols)
	}

	parts := make([]string, 60)
	parts[13] = "0x1"
	if got := buildVehicleConversation("CAN", "", "", parts); got != "Bus 0X1" {
		t.Fatalf("CAN conversation = %q", got)
	}
	parts[13] = ""
	if got := buildVehicleConversation("CAN", "", "", parts); got != "CAN bus" {
		t.Fatalf("CAN fallback conversation = %q", got)
	}
	parts[26] = "0x80"
	parts[27] = "0xff"
	if got := buildVehicleConversation("J1939", "", "", parts); got != "0X80 -> 0Xff" {
		t.Fatalf("J1939 conversation = %q", got)
	}
	parts[26], parts[27] = "", ""
	if got := buildVehicleConversation("J1939", "", "", parts); got != "J1939 network" {
		t.Fatalf("J1939 fallback conversation = %q", got)
	}
	parts[34], parts[36] = "tester", "ecu"
	if got := buildVehicleConversation("UDS", "", "", parts); got != "tester -> ecu" {
		t.Fatalf("UDS conversation = %q", got)
	}
	if got := buildVehicleConversation("TCP", "a", "b", parts); got != "a -> b" {
		t.Fatalf("default conversation = %q", got)
	}

	flagParts := make([]string, 23)
	for _, idx := range []int{17, 18, 19, 20, 21, 22} {
		flagParts[idx] = "1"
	}
	if got := buildCANErrorFlags(flagParts); got != "ACK, BUS-OFF, BUS-ERROR, RESTARTED, CTRL, PROTO" {
		t.Fatalf("buildCANErrorFlags() = %q", got)
	}

	for raw, want := range map[string]string{
		"0x10": "Diagnostic Session Control",
		"0x11": "ECU Reset",
		"0x14": "Clear Diagnostic Information",
		"0x19": "Read DTC Information",
		"0x22": "Read Data By Identifier",
		"0x27": "Security Access",
		"0x2e": "Write Data By Identifier",
		"0x2f": "Input Output Control",
		"0x31": "Routine Control",
		"0x34": "Request Download",
		"0x36": "Transfer Data",
		"0x37": "Request Transfer Exit",
		"0xff": "UDS Service",
	} {
		if got := udsServiceName(raw); got != want {
			t.Fatalf("udsServiceName(%q) = %q, want %q", raw, got, want)
		}
	}
	for raw, want := range map[string]string{
		"0x10": "General Reject",
		"0x11": "Service Not Supported",
		"0x12": "SubFunction Not Supported",
		"0x13": "Incorrect Message Length",
		"0x22": "Conditions Not Correct",
		"0x31": "Request Out Of Range",
		"0x33": "Security Access Denied",
		"0x35": "Invalid Key",
		"0x36": "Exceeded Number Of Attempts",
		"0x37": "Required Time Delay Not Expired",
		"0x7e": "SubFunction Not Supported In Session",
		"0x7f": "Service Not Supported In Session",
		"0xff": "",
	} {
		if got := udsNegativeResponseName(raw); got != want {
			t.Fatalf("udsNegativeResponseName(%q) = %q, want %q", raw, got, want)
		}
	}

	stats := model.VehicleAnalysis{
		Protocols: []model.TrafficBucket{
			{Label: "OBD-II", Count: 1},
			{Label: "XCP", Count: 1},
			{Label: "KWP2000", Count: 1},
		},
		CAN: model.CANAnalysis{
			TotalFrames:      1,
			PayloadProtocols: []model.TrafficBucket{{Label: "CANopen", Count: 1}, {Label: "ISO-TP", Count: 1}},
			DecodedMessages:  []model.CANDBCMessage{{MessageName: "Status"}},
		},
		J1939: model.J1939Analysis{TotalMessages: 1},
		DoIP:  model.DoIPAnalysis{TotalMessages: 1},
		UDS: model.UDSAnalysis{
			TotalMessages: 1,
			ServiceIDs: []model.TrafficBucket{
				{Label: "0X22 Read", Count: 1},
				{Label: "0X27 Security", Count: 1},
				{Label: "0X2E Write", Count: 1},
				{Label: "0X34 Download", Count: 1},
			},
			Transactions: []model.UDSTransaction{{Status: "positive"}},
		},
	}
	recs := vehicleRecommendations(stats)
	if len(recs) < 12 {
		t.Fatalf("expected rich vehicle recommendations, got %d: %+v", len(recs), recs)
	}
	if !containsBucket(stats.Protocols, "OBD-II") || !containsBucketPrefix(stats.UDS.ServiceIDs, "0X22 ") {
		t.Fatalf("bucket helpers failed")
	}
	if got := vehicleRecommendations(model.VehicleAnalysis{}); len(got) != 1 {
		t.Fatalf("empty recommendations = %+v", got)
	}
}

func TestDBCProfileBuildersSkipNilDatabases(t *testing.T) {
	db := &DBCDatabase{Path: "demo.dbc", Name: "demo", MessageCount: 2, SignalCount: 3}
	got := buildDBCProfiles([]*DBCDatabase{nil, db})
	if !reflect.DeepEqual(got, []model.DBCProfile{{Path: "demo.dbc", Name: "demo", MessageCount: 2, SignalCount: 3}}) {
		t.Fatalf("buildDBCProfiles() = %+v", got)
	}
	if got := buildDBCProfiles(nil); got != nil {
		t.Fatalf("buildDBCProfiles(nil) = %+v", got)
	}
}

package tshark

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestHelperProcessFakeTShark(t *testing.T) {
	if os.Getenv("GO_WANT_FAKE_TSHARK") != "1" {
		return
	}
	defer os.Exit(0)
	scenario := os.Getenv("FAKE_TSHARK_SCENARIO")
	args := os.Args
	sep := "\x1f"
	for i, arg := range args {
		if arg == "--" && i+1 < len(args) {
			args = args[i+1:]
			break
		}
	}
	if scenario == "fail" {
		fmt.Fprintln(os.Stderr, "fake tshark failed")
		os.Exit(7)
	}
	if hasArg(args, "-v") {
		fmt.Println("TShark 4.6.5")
		return
	}
	if hasArg(args, "-G") {
		for _, field := range fakeTSharkAllFields() {
			fmt.Printf("F\t%s\t%s\tFT_STRING\tfake\tBASE_NONE\t0x0\t%s\n", field, field, field)
		}
		return
	}
	if hasArg(args, "--export-objects") {
		return
	}
	if hasArg(args, "-T") && argAfter(args, "-T") == "ek" {
		fmt.Println(`{"index":{"_index":"packets-2026","_type":"doc"}}`)
		fmt.Println(`{"layers":{"frame":{"frame_number":"1","frame_protocols":"eth:ip:tcp:http","frame_len":"128","frame_time_epoch":"1700000000.1"},"ip":{"ip_src":"192.0.2.10","ip_dst":"198.51.100.20"},"tcp":{"tcp_srcport":"51515","tcp_dstport":"80","tcp_stream":"9"},"_ws":{"col":{"Protocol":"HTTP","info":"GET /demo HTTP/1.1"}}}}`)
		fmt.Println(`{"layers":{"frame":{"frame_number":"bad","frame_protocols":"eth","frame_len":"bad"}}}`)
		return
	}
	if hasArg(args, "-T") && argAfter(args, "-T") == "fields" {
		fields := requestedFields(args)
		filter := argAfter(args, "-Y")
		switch {
		case len(fields) == 1 && fields[0] == "frame.number":
			fmt.Println("1")
			fmt.Println("not-a-number")
			fmt.Println("2")
		case sameStrings(fields, fastListFields):
			fmt.Println(strings.Join(fakeFastListRow(), sep))
		case sameStrings(fields, firstScreenListFields) || sameStrings(fields, compatListFields):
			fmt.Println(strings.Join(fakeCompatListRow(), sep))
			fmt.Println(strings.Join(make([]string, len(fields)), sep))
		case strings.Contains(filter, "rtsp") || sameStrings(fields, mediaControlFields):
			row := make([]string, len(fields))
			setField(row, fields, "frame.number", "10")
			setField(row, fields, "ip.src", "10.0.0.10")
			setField(row, fields, "ip.dst", "10.0.0.20")
			setField(row, fields, "tcp.srcport", "554")
			setField(row, fields, "tcp.dstport", "51515")
			setField(row, fields, "rtsp.request.method", "SETUP")
			setField(row, fields, "rtsp.request.uri", "rtsp://stream/test")
			setField(row, fields, "rtsp.transport", "RTP/AVP;unicast;client_port=5004-5005")
			setField(row, fields, "sdp.media", "video 5004 RTP/AVP 96")
			setField(row, fields, "sdp.media.port", "5004")
			setField(row, fields, "sdp.media_attr", "rtpmap:96 H264/90000|fmtp:96 packetization-mode=1")
			setField(row, fields, "_ws.col.Info", "RTSP SETUP Moonlight")
			fmt.Println(strings.Join(row, "\t"))
		case sameStrings(fields, mediaRTPFields):
			row := make([]string, len(fields))
			setField(row, fields, "frame.number", "11")
			setField(row, fields, "frame.time_epoch", "1700000002.25")
			setField(row, fields, "ip.src", "10.0.0.10")
			setField(row, fields, "ip.dst", "10.0.0.20")
			setField(row, fields, "udp.srcport", "5004")
			setField(row, fields, "udp.dstport", "5006")
			setField(row, fields, "_ws.col.Protocol", "RTP")
			setField(row, fields, "_ws.col.Info", "PT=96 H264")
			setField(row, fields, "rtp.ssrc", "0x12345678")
			setField(row, fields, "rtp.p_type", "96")
			setField(row, fields, "rtp.seq", "1")
			setField(row, fields, "rtp.timestamp", "90000")
			setField(row, fields, "rtp.marker", "1")
			setField(row, fields, "rtp.payload", "65:aa:bb")
			setField(row, fields, "h264.nal_unit_type", "5")
			fmt.Println(strings.Join(row, "\t"))
		case sameStrings(fields, mediaGameStreamUDPFields):
			row := make([]string, len(fields))
			setField(row, fields, "frame.number", "12")
			setField(row, fields, "frame.time_epoch", "1700000003.25")
			setField(row, fields, "ip.src", "10.0.0.30")
			setField(row, fields, "ip.dst", "10.0.0.40")
			setField(row, fields, "udp.srcport", "47998")
			setField(row, fields, "udp.dstport", "48010")
			setField(row, fields, "udp.payload", "90:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:01:00:00:00:05:00:10:00:20:03:00:01:01:00:00:02:4d:01:00:00:00:00:00:01:67:64:0c:2a")
			fmt.Println(strings.Join(row, "\t"))
		case sameStrings(fields, usbAnalysisFields):
			for _, row := range fakeUSBAnalysisRows() {
				fmt.Println(strings.Join(row, "\t"))
			}
		case sameStrings(fields, dbcDecodedMessageFields):
			row := make([]string, len(fields))
			setField(row, fields, "frame.number", "501")
			setField(row, fields, "frame.time_epoch", "1700000200.5")
			setField(row, fields, "_ws.col.Info", "CAN speed sample")
			setField(row, fields, "can.bus_id", "0x1")
			setField(row, fields, "can.id", "0x123")
			setField(row, fields, "can.len", "8")
			setField(row, fields, "data.data", "2a:00:00:00:00:00:00:00")
			fmt.Println(strings.Join(row, "\t"))
		case len(fields) == 1 && fields[0] == "udp.payload":
			if strings.Contains(filter, "udp.port==5004") {
				fmt.Println("80:60:00:01:00:00:00:02:12:34:56:78:65:aa")
				fmt.Println("80:60:00:02:00:00:00:03:12:34:56:78:65:bb")
				fmt.Println("80:60:00:03:00:00:00:04:12:34:56:78:65:cc")
			} else {
				fmt.Println("01:02:03")
			}
		case sameStrings(fields, []string{"frame.number", "ip.src", "tcp.srcport", "ip.dst", "tcp.dstport", "tcp.payload"}):
			for _, row := range fakeTCPFollowRows(fields, filter) {
				fmt.Println(strings.Join(row, "\t"))
			}
		case sameStrings(fields, []string{"frame.number", "ip.src", "udp.srcport", "ip.dst", "udp.dstport", "udp.payload"}):
			for _, row := range fakeUDPFollowRows(fields, filter) {
				fmt.Println(strings.Join(row, "\t"))
			}
		case sameStrings(fields, modbusAnalysisFields):
			for _, row := range fakeModbusAnalysisRows(fields) {
				fmt.Println(strings.Join(row, "\t"))
			}
		case sameStrings(fields, s7CommDetailFields):
			fmt.Println(strings.Join(fakeS7CommDetailRow(fields), "\t"))
		case sameStrings(fields, dnp3DetailFields):
			fmt.Println(strings.Join(fakeDNP3DetailRow(fields), "\t"))
		case sameStrings(fields, cipDetailFields):
			fmt.Println(strings.Join(fakeCIPDetailRow(fields), "\t"))
		case sameStrings(fields, profinetDetailFields):
			fmt.Println(strings.Join(fakePROFINETDetailRow(fields), "\t"))
		case sameStrings(fields, bacnetDetailFields):
			fmt.Println(strings.Join(fakeBACnetDetailRow(fields), "\t"))
		case sameStrings(fields, iec104DetailFields):
			fmt.Println(strings.Join(fakeIEC104DetailRow(fields), "\t"))
		case sameStrings(fields, opcuaDetailFields):
			fmt.Println(strings.Join(fakeOPCUADetailRow(fields), "\t"))
		default:
			row := make([]string, len(fields))
			for i, field := range fields {
				switch field {
				case "frame.number":
					row[i] = "42"
				case "frame.time_epoch":
					row[i] = "1700000001.1"
				case "ip.src":
					row[i] = "10.0.0.1"
				case "ip.dst":
					row[i] = "10.0.0.2"
				case "_ws.col.Info":
					row[i] = "field scan row"
				case "udp.payload", "rtp.payload":
					row[i] = "65:aa:bb"
				}
			}
			fmt.Println(strings.Join(row, "\t"))
		}
		return
	}
}

func TestRunnerStreamsUseFakeTSharkCommand(t *testing.T) {
	withFakeTSharkCommand(t, "")
	ClearFieldScanCache("")
	ClearCapabilityCache()
	t.Cleanup(func() {
		ClearFieldScanCache("")
		ClearCapabilityCache()
	})

	opts := model.ParseOptions{FilePath: "sample.pcap", DisplayFilter: "http", MaxPackets: 3}
	var ekPackets []model.Packet
	var ekProgress []int
	err := StreamPackets(context.Background(), opts, func(packet model.Packet) error {
		ekPackets = append(ekPackets, packet)
		return nil
	}, func(processed int) {
		ekProgress = append(ekProgress, processed)
	})
	if err != nil {
		t.Fatalf("StreamPackets() error = %v", err)
	}
	if len(ekPackets) != 1 || ekPackets[0].Protocol != "HTTP" || ekPackets[0].StreamID != 9 {
		t.Fatalf("unexpected EK packets: %+v", ekPackets)
	}
	if len(ekProgress) == 0 {
		t.Fatal("expected progress callbacks for EK stream")
	}

	for _, tt := range []struct {
		name string
		run  func(context.Context, model.ParseOptions, func(model.Packet) error, func(int)) error
	}{
		{name: "fast", run: StreamPacketsFast},
		{name: "first-screen", run: StreamPacketsFirstScreen},
		{name: "compat", run: StreamPacketsCompat},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var packets []model.Packet
			var progress []int
			err := tt.run(context.Background(), model.ParseOptions{FilePath: "sample.pcap", MaxPackets: 2}, func(packet model.Packet) error {
				packets = append(packets, packet)
				return nil
			}, func(processed int) {
				progress = append(progress, processed)
			})
			if err != nil {
				t.Fatalf("%s stream error = %v", tt.name, err)
			}
			if len(packets) != 1 {
				t.Fatalf("%s packets = %+v", tt.name, packets)
			}
			if packets[0].SourceIP != "192.0.2.10" || packets[0].DestIP != "198.51.100.20" {
				t.Fatalf("%s packet endpoints = %+v", tt.name, packets[0])
			}
			if len(progress) == 0 {
				t.Fatalf("%s expected progress callbacks", tt.name)
			}
		})
	}
}

func TestRunnerFrameIDEstimateFilterAndExportUseFakeTShark(t *testing.T) {
	withFakeTSharkCommand(t, "")
	ClearCapabilityCache()
	t.Cleanup(ClearCapabilityCache)

	opts := model.ParseOptions{FilePath: "sample.pcap", DisplayFilter: "tcp"}
	total, err := EstimatePackets(context.Background(), opts)
	if err != nil {
		t.Fatalf("EstimatePackets() error = %v", err)
	}
	if total != 3 {
		t.Fatalf("EstimatePackets() = %d, want 3 non-empty frame rows", total)
	}

	var scanned []int64
	if err := ScanFrameIDs(context.Background(), opts, func(id int64) {
		scanned = append(scanned, id)
	}); err != nil {
		t.Fatalf("ScanFrameIDs() error = %v", err)
	}
	if !reflect.DeepEqual(scanned, []int64{1, 2}) {
		t.Fatalf("ScanFrameIDs() = %+v", scanned)
	}

	filtered, err := FilterFrameIDs(context.Background(), opts)
	if err != nil {
		t.Fatalf("FilterFrameIDs() error = %v", err)
	}
	if !reflect.DeepEqual(filtered, []int64{1, 2}) {
		t.Fatalf("FilterFrameIDs() = %+v", filtered)
	}

	if err := ExportObjectsContext(context.Background(), "sample.pcap", t.TempDir()); err != nil {
		t.Fatalf("ExportObjectsContext() error = %v", err)
	}
	if err := ExportObjectsLegacy("sample.pcap", t.TempDir()); err != nil {
		t.Fatalf("ExportObjectsLegacy() error = %v", err)
	}
}

func TestFieldScanRowsUseFakeTSharkAndCache(t *testing.T) {
	withFakeTSharkCommand(t, "")
	ClearCapabilityCache()
	ClearFieldScanCache("")
	t.Cleanup(func() {
		ClearCapabilityCache()
		ClearFieldScanCache("")
	})

	fields := []string{"frame.number", "ip.src", "udp.payload", "_ws.col.Info"}
	var rows [][]string
	if err := ScanFieldRowsWithDisplayFilter("sample.pcap", fields, "udp", func(parts []string) {
		rows = append(rows, append([]string(nil), parts...))
	}); err != nil {
		t.Fatalf("ScanFieldRowsWithDisplayFilter() error = %v", err)
	}
	if len(rows) != 1 || rows[0][0] != "42" || rows[0][1] != "10.0.0.1" || rows[0][2] != "65:aa:bb" {
		t.Fatalf("unexpected field scan rows: %+v", rows)
	}

	withFakeTSharkCommand(t, "fail")
	var cached [][]string
	if err := ScanFieldRowsWithDisplayFilter("sample.pcap", fields, "udp", func(parts []string) {
		cached = append(cached, append([]string(nil), parts...))
	}); err != nil {
		t.Fatalf("cached ScanFieldRowsWithDisplayFilter() should not execute failing command: %v", err)
	}
	if !reflect.DeepEqual(cached, rows) {
		t.Fatalf("cached rows = %+v, want %+v", cached, rows)
	}
}

func TestRunnerPropagatesCallbackAndCommandErrors(t *testing.T) {
	withFakeTSharkCommand(t, "")
	wantErr := errors.New("stop from callback")
	err := StreamPacketsFast(context.Background(), model.ParseOptions{FilePath: "sample.pcap"}, func(model.Packet) error {
		return wantErr
	}, nil)
	if !errors.Is(err, wantErr) {
		t.Fatalf("StreamPacketsFast callback error = %v, want %v", err, wantErr)
	}

	withFakeTSharkCommand(t, "fail")
	err = StreamPacketsCompat(context.Background(), model.ParseOptions{FilePath: "sample.pcap"}, func(model.Packet) error {
		return nil
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "fake tshark failed") {
		t.Fatalf("expected wait error with stderr detail, got %v", err)
	}
}

func withFakeTSharkCommand(t *testing.T, scenario string) {
	t.Helper()
	oldCommand := commandContextFn
	oldBinary := ConfiguredBinaryPath()
	t.Cleanup(func() {
		commandContextFn = oldCommand
		SetBinaryPath(oldBinary)
	})
	SetBinaryPath(fakeTSharkBinaryPath(t))
	commandContextFn = func(ctx context.Context, _ string, args ...string) *exec.Cmd {
		cmdArgs := []string{"-test.run=TestHelperProcessFakeTShark", "--"}
		cmdArgs = append(cmdArgs, args...)
		cmd := exec.CommandContext(ctx, os.Args[0], cmdArgs...)
		cmd.Env = append(os.Environ(),
			"GO_WANT_FAKE_TSHARK=1",
			"FAKE_TSHARK_SCENARIO="+scenario,
		)
		return cmd
	}
}

func fakeTSharkBinaryPath(t *testing.T) string {
	t.Helper()
	path := t.TempDir() + string(os.PathSeparator) + "tshark"
	if err := os.WriteFile(path, []byte("fake"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func fakeTSharkAllFields() []string {
	fields := unionFieldScanFields(
		fastListFields,
		firstScreenListFields,
		compatListFields,
		mediaControlFields,
		mediaRTPFields,
		mediaGameStreamUDPFields,
		usbAnalysisFields,
		dbcDecodedMessageFields,
		modbusAnalysisFields,
		s7CommDetailFields,
		dnp3DetailFields,
		cipDetailFields,
		profinetDetailFields,
		bacnetDetailFields,
		iec104DetailFields,
		opcuaDetailFields,
		[]string{"frame.number", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport", "tcp.payload", "udp.srcport", "udp.dstport", "udp.payload", "rtp.payload"},
	)
	return fields
}

func fakeUSBAnalysisRows() [][]string {
	keyboard := makeUSBAnalysisRow(map[int]string{
		usbFieldFrameNumber:       "21",
		usbFieldFrameTime:         "1700000100.1",
		usbFieldProtocol:          "USBHID",
		usbFieldBusID:             "1",
		usbFieldDeviceAddress:     "2",
		usbFieldEndpointAddress:   "0x81",
		usbFieldEndpointDirection: "1",
		usbFieldTransferType:      "1",
		usbFieldURBType:           "c",
		usbFieldURBStatus:         "0",
		usbFieldDataLength:        "8",
		usbFieldCapData:           "0200040000000000",
		usbFieldInfo:              "keyboard A",
	})
	cbw := makeUSBAnalysisRow(map[int]string{
		usbFieldFrameNumber:                      "22",
		usbFieldFrameTime:                        "1700000100.2",
		usbFieldProtocol:                         "USBMS",
		usbFieldBusID:                            "1",
		usbFieldDeviceAddress:                    "7",
		usbFieldEndpointAddress:                  "0x02",
		usbFieldEndpointDirection:                "0",
		usbFieldTransferType:                     "3",
		usbFieldURBType:                          "s",
		usbFieldURBStatus:                        "0",
		usbFieldDataLength:                       "31",
		usbFieldFrameData:                        buildCBWHex(0x99, 512, 0x00, 0, []byte{0x2A, 0, 0, 0, 0, 0, 0, 0, 1, 0}),
		usbFieldInfo:                             "SCSI WRITE(10)",
		usbFieldMassStorageCBWSignature:          "0x43425355",
		usbFieldMassStorageCBWTag:                "0x99",
		usbFieldMassStorageCBWDataTransferLength: "512",
		usbFieldMassStorageCBWFlags:              "0x00",
		usbFieldMassStorageCBWLUN:                "0",
		usbFieldMassStorageCBWCBLength:           "10",
		usbFieldSCSIOpcode:                       "0x2A",
		usbFieldSCSILUN:                          "0",
	})
	csw := makeUSBAnalysisRow(map[int]string{
		usbFieldFrameNumber:               "23",
		usbFieldFrameTime:                 "1700000100.3",
		usbFieldProtocol:                  "USBMS",
		usbFieldBusID:                     "1",
		usbFieldDeviceAddress:             "7",
		usbFieldEndpointAddress:           "0x81",
		usbFieldEndpointDirection:         "1",
		usbFieldTransferType:              "3",
		usbFieldURBType:                   "c",
		usbFieldURBStatus:                 "0",
		usbFieldDataLength:                "13",
		usbFieldInfo:                      "SCSI WRITE(10) complete",
		usbFieldMassStorageCBWTag:         "0x99",
		usbFieldMassStorageCSWSignature:   "0x53425355",
		usbFieldMassStorageCSWStatus:      "1",
		usbFieldMassStorageCSWDataResidue: "8",
		usbFieldSCSIOpcode:                "0x2A",
		usbFieldSCSILUN:                   "0",
		usbFieldSCSIRequestFrame:          "22",
		usbFieldSCSIResponseFrame:         "23",
		usbFieldSCSITime:                  "0.002",
		usbFieldSCSIStatus:                "check_condition",
	})
	return [][]string{keyboard, cbw, csw}
}

func requestedFields(args []string) []string {
	fields := []string{}
	for idx := 0; idx < len(args); idx++ {
		if args[idx] == "-e" && idx+1 < len(args) {
			fields = append(fields, args[idx+1])
			idx++
		}
	}
	return fields
}

func hasArg(args []string, want string) bool {
	for _, arg := range args {
		if arg == want {
			return true
		}
	}
	return false
}

func argAfter(args []string, want string) string {
	for idx, arg := range args {
		if arg == want && idx+1 < len(args) {
			return args[idx+1]
		}
	}
	return ""
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for idx := range left {
		if left[idx] != right[idx] {
			return false
		}
	}
	return true
}

func setField(row []string, fields []string, field string, value string) {
	for idx, item := range fields {
		if item == field {
			row[idx] = value
		}
	}
}

func fakeIndustrialBaseRow(fields []string, frame, protoPath, proto, info string) []string {
	row := make([]string, len(fields))
	setField(row, fields, "frame.number", frame)
	setField(row, fields, "frame.time_epoch", "1700000100."+frame)
	setField(row, fields, "ip.src", "10.10.0.10")
	setField(row, fields, "ip.dst", "10.10.0.20")
	setField(row, fields, "frame.protocols", protoPath)
	setField(row, fields, "_ws.col.Protocol", proto)
	setField(row, fields, "_ws.col.Info", info)
	return row
}

func fakeModbusAnalysisRows(fields []string) [][]string {
	request := fakeIndustrialBaseRow(fields, "101", "eth:ip:tcp:mbtcp:modbus", "Modbus/TCP", "Write Multiple Registers")
	setField(request, fields, "tcp.srcport", "55000")
	setField(request, fields, "tcp.dstport", "502")
	setField(request, fields, "mbtcp.trans_id", "1")
	setField(request, fields, "mbtcp.unit_id", "1")
	setField(request, fields, "modbus.func_code", "16")
	setField(request, fields, "modbus.write_reference_num", "40001")
	setField(request, fields, "modbus.write_word_cnt", "4")
	setField(request, fields, "modbus.regval_uint16", "102,108,97,103")
	setField(request, fields, "modbus.object_str_value", "flag")

	response := fakeIndustrialBaseRow(fields, "102", "eth:ip:tcp:mbtcp:modbus", "Modbus/TCP", "Write Multiple Registers response")
	setField(response, fields, "tcp.srcport", "502")
	setField(response, fields, "tcp.dstport", "55000")
	setField(response, fields, "mbtcp.trans_id", "1")
	setField(response, fields, "mbtcp.unit_id", "1")
	setField(response, fields, "modbus.func_code", "16")
	setField(response, fields, "modbus.request_frame", "101")
	setField(response, fields, "modbus.response_time", "0.010")
	setField(response, fields, "modbus.write_reference_num", "40001")
	setField(response, fields, "modbus.write_word_cnt", "4")

	exception := fakeIndustrialBaseRow(fields, "103", "eth:ip:tcp:mbtcp:modbus", "Modbus/TCP", "Illegal data address")
	setField(exception, fields, "tcp.srcport", "502")
	setField(exception, fields, "tcp.dstport", "55001")
	setField(exception, fields, "mbtcp.trans_id", "2")
	setField(exception, fields, "mbtcp.unit_id", "1")
	setField(exception, fields, "modbus.func_code", "3")
	setField(exception, fields, "modbus.request_frame", "100")
	setField(exception, fields, "modbus.exception", "1")
	setField(exception, fields, "modbus.exception_code", "2")
	setField(exception, fields, "modbus.read_reference_num", "40002")
	setField(exception, fields, "modbus.read_word_cnt", "126")

	return [][]string{request, response, exception}
}

func fakeTCPFollowRows(fields []string, filter string) [][]string {
	rows := [][]string{}
	if !strings.Contains(filter, "tcp.stream==") {
		return rows
	}

	clientGet := make([]string, len(fields))
	setField(clientGet, fields, "frame.number", "301")
	setField(clientGet, fields, "ip.src", "192.0.2.10")
	setField(clientGet, fields, "tcp.srcport", "51515")
	setField(clientGet, fields, "ip.dst", "198.51.100.20")
	setField(clientGet, fields, "tcp.dstport", "80")
	setField(clientGet, fields, "tcp.payload", "47:45:54:20:2f:61:20:48:54:54:50:2f:31:2e:31:0d:0a")
	rows = append(rows, clientGet)

	clientHost := make([]string, len(fields))
	setField(clientHost, fields, "frame.number", "302")
	setField(clientHost, fields, "ip.src", "192.0.2.10")
	setField(clientHost, fields, "tcp.srcport", "51515")
	setField(clientHost, fields, "ip.dst", "198.51.100.20")
	setField(clientHost, fields, "tcp.dstport", "80")
	setField(clientHost, fields, "tcp.payload", "48:6f:73:74:3a:20:65:78:61:6d:70:6c:65:0d:0a")
	rows = append(rows, clientHost)

	serverOK := make([]string, len(fields))
	setField(serverOK, fields, "frame.number", "303")
	setField(serverOK, fields, "ip.src", "198.51.100.20")
	setField(serverOK, fields, "tcp.srcport", "80")
	setField(serverOK, fields, "ip.dst", "192.0.2.10")
	setField(serverOK, fields, "tcp.dstport", "51515")
	setField(serverOK, fields, "tcp.payload", "48:54:54:50:2f:31:2e:31:20:32:30:30:20:4f:4b:0d:0a")
	rows = append(rows, serverOK)

	badPayload := make([]string, len(fields))
	setField(badPayload, fields, "frame.number", "304")
	setField(badPayload, fields, "ip.src", "192.0.2.10")
	setField(badPayload, fields, "tcp.srcport", "51515")
	setField(badPayload, fields, "ip.dst", "198.51.100.20")
	setField(badPayload, fields, "tcp.dstport", "80")
	setField(badPayload, fields, "tcp.payload", "zz")
	rows = append(rows, badPayload)

	return rows
}

func fakeUDPFollowRows(fields []string, filter string) [][]string {
	rows := [][]string{}
	if !strings.Contains(filter, "udp.stream==") {
		return rows
	}

	clientOne := make([]string, len(fields))
	setField(clientOne, fields, "frame.number", "401")
	setField(clientOne, fields, "ip.src", "203.0.113.10")
	setField(clientOne, fields, "udp.srcport", "53000")
	setField(clientOne, fields, "ip.dst", "203.0.113.53")
	setField(clientOne, fields, "udp.dstport", "53")
	setField(clientOne, fields, "udp.payload", "01:02,03:04")
	rows = append(rows, clientOne)

	clientTwo := make([]string, len(fields))
	setField(clientTwo, fields, "frame.number", "402")
	setField(clientTwo, fields, "ip.src", "203.0.113.10")
	setField(clientTwo, fields, "udp.srcport", "53000")
	setField(clientTwo, fields, "ip.dst", "203.0.113.53")
	setField(clientTwo, fields, "udp.dstport", "53")
	setField(clientTwo, fields, "udp.payload", "05:06")
	rows = append(rows, clientTwo)

	serverReply := make([]string, len(fields))
	setField(serverReply, fields, "frame.number", "403")
	setField(serverReply, fields, "ip.src", "203.0.113.53")
	setField(serverReply, fields, "udp.srcport", "53")
	setField(serverReply, fields, "ip.dst", "203.0.113.10")
	setField(serverReply, fields, "udp.dstport", "53000")
	setField(serverReply, fields, "udp.payload", "aa:bb")
	rows = append(rows, serverReply)

	emptyPayload := make([]string, len(fields))
	setField(emptyPayload, fields, "frame.number", "404")
	setField(emptyPayload, fields, "ip.src", "203.0.113.10")
	setField(emptyPayload, fields, "udp.srcport", "53000")
	setField(emptyPayload, fields, "ip.dst", "203.0.113.53")
	setField(emptyPayload, fields, "udp.dstport", "53")
	setField(emptyPayload, fields, "udp.payload", "abc")
	rows = append(rows, emptyPayload)

	return rows
}

func fakeS7CommDetailRow(fields []string) []string {
	row := fakeIndustrialBaseRow(fields, "201", "eth:ip:tcp:s7comm", "S7COMM", "S7 Write Var")
	setField(row, fields, "s7comm.header.rosctr", "1")
	setField(row, fields, "s7comm.param.func", "5")
	setField(row, fields, "s7comm.param.item.db", "1")
	setField(row, fields, "s7comm.param.item.area", "0x84")
	setField(row, fields, "s7comm.param.item.address.byte", "4")
	return row
}

func fakeDNP3DetailRow(fields []string) []string {
	row := fakeIndustrialBaseRow(fields, "202", "eth:ip:tcp:dnp3", "DNP3", "DNP3 Operate")
	setField(row, fields, "dnp3.src", "1")
	setField(row, fields, "dnp3.dst", "100")
	setField(row, fields, "dnp3.al.func", "4")
	setField(row, fields, "dnp3.al.obj", "12")
	setField(row, fields, "dnp3.al.point_index", "7")
	setField(row, fields, "dnp3.al.count", "1")
	setField(row, fields, "dnp3.al.ana.int", "42")
	setField(row, fields, "dnp3.al.ctrlstatus", "success")
	return row
}

func fakeCIPDetailRow(fields []string) []string {
	row := fakeIndustrialBaseRow(fields, "203", "eth:ip:tcp:enip:cip", "CIP", "CIP Write Tag")
	setField(row, fields, "enip.command", "0x006F")
	setField(row, fields, "cip.service", "0x4D")
	setField(row, fields, "cip.class", "0x6B")
	setField(row, fields, "cip.instance", "0x01")
	setField(row, fields, "cip.attribute", "0x03")
	setField(row, fields, "cip.genstat", "0x00")
	setField(row, fields, "cip.symbol", "Pump.Speed")
	setField(row, fields, "cip.id.vendor_id", "123")
	setField(row, fields, "cip.id.product_name", "PLC")
	return row
}

func fakeBACnetDetailRow(fields []string) []string {
	row := fakeIndustrialBaseRow(fields, "204", "eth:ip:udp:bacnet:bacapp", "BACnet", "BACnet Write Property")
	setField(row, fields, "bacnet.mesgtyp", "0")
	setField(row, fields, "bacapp.confirmed_service", "12")
	setField(row, fields, "bacapp.object_name", "analog-output,1")
	setField(row, fields, "bacapp.objectIdentifier", "analog-output:1")
	setField(row, fields, "bacapp.property_identifier", "present-value")
	setField(row, fields, "bacapp.present_value.real", "12.5")
	setField(row, fields, "bacapp.invoke_id", "7")
	return row
}

func fakeIEC104DetailRow(fields []string) []string {
	row := fakeIndustrialBaseRow(fields, "205", "eth:ip:tcp:iec104", "IEC104", "IEC104 single command")
	setField(row, fields, "iec60870_asdu.addr", "1")
	setField(row, fields, "iec60870_asdu.typeid", "45")
	setField(row, fields, "iec60870_asdu.causetx", "6")
	setField(row, fields, "iec60870_asdu.ioa", "1001")
	setField(row, fields, "iec60870_asdu.rawdata", "01:00:00:00")
	return row
}

func fakeOPCUADetailRow(fields []string) []string {
	row := fakeIndustrialBaseRow(fields, "206", "eth:ip:tcp:opcua", "OPC UA", "OPC UA Write")
	setField(row, fields, "opcua.servicenodeid.numeric", "530")
	setField(row, fields, "opcua.ApplicationUri", "urn:test:client")
	setField(row, fields, "opcua.EndpointUrl", "opc.tcp://plc.local:4840")
	setField(row, fields, "opcua.SessionName", "operator")
	setField(row, fields, "opcua.ServiceResult", "Good")
	return row
}

func fakePROFINETDetailRow(fields []string) []string {
	row := fakeIndustrialBaseRow(fields, "207", "eth:pn_dcp:profinet", "PROFINET", "PROFINET DCP Set")
	setField(row, fields, "eth.src", "00:11:22:33:44:55")
	setField(row, fields, "eth.dst", "66:77:88:99:aa:bb")
	setField(row, fields, "pn_rt.frame_id", "0x8892")
	setField(row, fields, "pn_rt.cycle_counter", "12")
	setField(row, fields, "pn_dcp.service_id", "4")
	setField(row, fields, "pn_dcp.service_type", "0")
	setField(row, fields, "pn_dcp.suboption_device_nameofstation", "station-a")
	setField(row, fields, "pn_dcp.suboption_vendor_id", "0x002a")
	setField(row, fields, "pn_dcp.suboption_device_id", "0x1001")
	setField(row, fields, "pn_dcp.suboption_ip_ip", "192.0.2.44")
	return row
}

func fakeFastListRow() []string {
	parts := make([]string, len(fastListFields))
	setField(parts, fastListFields, "frame.number", "7")
	setField(parts, fastListFields, "frame.time_epoch", "1700000000.5")
	setField(parts, fastListFields, "ip.src", "192.0.2.10")
	setField(parts, fastListFields, "ip.dst", "198.51.100.20")
	setField(parts, fastListFields, "udp.srcport", "5004")
	setField(parts, fastListFields, "udp.dstport", "5006")
	setField(parts, fastListFields, "_ws.col.Protocol", "RTP")
	setField(parts, fastListFields, "frame.len", "96")
	setField(parts, fastListFields, "_ws.col.Info", "RTP payload")
	setField(parts, fastListFields, "udp.stream", "3")
	setField(parts, fastListFields, "udp.payload", "80:60:00:01:00:00:00:02:12:34:56:78:65:aa")
	setField(parts, fastListFields, "ip.hdr_len", "20")
	return parts
}

func fakeCompatListRow() []string {
	parts := make([]string, len(compatListFields))
	setField(parts, compatListFields, "frame.number", "8")
	setField(parts, compatListFields, "frame.time_epoch", "1700000000.6")
	setField(parts, compatListFields, "ip.src", "192.0.2.10")
	setField(parts, compatListFields, "ip.dst", "198.51.100.20")
	setField(parts, compatListFields, "tcp.srcport", "51515")
	setField(parts, compatListFields, "tcp.dstport", "443")
	setField(parts, compatListFields, "_ws.col.Protocol", "TLSv1.3")
	setField(parts, compatListFields, "frame.protocols", "eth:ip:tcp:tls")
	setField(parts, compatListFields, "frame.len", "128")
	setField(parts, compatListFields, "_ws.col.Info", "Client Hello")
	setField(parts, compatListFields, "tcp.stream", strconv.Itoa(4))
	setField(parts, compatListFields, "ip.hdr_len", "20")
	setField(parts, compatListFields, "tcp.hdr_len", "20")
	return parts
}

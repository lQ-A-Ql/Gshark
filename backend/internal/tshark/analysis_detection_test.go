package tshark

import (
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestDetectIndustrialProtocol(t *testing.T) {
	if got := detectIndustrialProtocol("eth:ip:tcp:mbtcp:modbus", "Modbus/TCP", "12345", "502"); got != "Modbus/TCP" {
		t.Fatalf("expected Modbus/TCP, got %q", got)
	}
	if got := detectIndustrialProtocol("eth:ip:tcp:s7comm", "S7comm", "1025", "102"); got != "S7comm" {
		t.Fatalf("expected S7comm, got %q", got)
	}
	if got := detectIndustrialProtocol("eth:ip:tcp", "TCP", "1000", "1001"); got != "" {
		t.Fatalf("expected empty protocol, got %q", got)
	}
}

func TestDetectVehicleProtocols(t *testing.T) {
	got := detectVehicleProtocols("eth:ip:tcp:doip:uds", "DoIP", "", "", "0x8001", "0x10", "35000", "13400", "")
	if len(got) != 2 || got[0] != "DoIP" || got[1] != "UDS" {
		t.Fatalf("unexpected protocols: %#v", got)
	}

	canOnly := detectVehicleProtocols("can", "CAN", "0x123", "", "", "", "", "", "")
	if len(canOnly) != 1 || canOnly[0] != "CAN" {
		t.Fatalf("unexpected CAN protocols: %#v", canOnly)
	}
}

func TestVehicleRecommendations(t *testing.T) {
	stats := model.VehicleAnalysis{
		CAN:  model.CANAnalysis{TotalFrames: 10},
		DoIP: model.DoIPAnalysis{TotalMessages: 2},
		UDS:  model.UDSAnalysis{TotalMessages: 4},
		Protocols: []model.TrafficBucket{
			{Label: "CAN", Count: 10},
			{Label: "DoIP", Count: 2},
			{Label: "UDS", Count: 4},
		},
	}
	recommendations := vehicleRecommendations(stats)
	if len(recommendations) < 3 {
		t.Fatalf("expected multiple recommendations, got %#v", recommendations)
	}
}

func TestDecodeOBDPayload(t *testing.T) {
	service, detail := decodeOBDPayload("41 0C 1A F8")
	if service != "Mode 01 Current Data Response" {
		t.Fatalf("unexpected service: %q", service)
	}
	if detail == "" || detail != "PID 0C / Engine RPM / Data 1A F8" {
		t.Fatalf("unexpected detail: %q", detail)
	}
}

func TestCANPayloadHelpers(t *testing.T) {
	if got := isoTPFrameType("0x20", "0x3", ""); got != "Consecutive Frame 0X3" {
		t.Fatalf("unexpected isotp frame type: %q", got)
	}
	if got := canopenFunctionName("0xB"); got != "SDO Tx" {
		t.Fatalf("unexpected canopen function: %q", got)
	}
	if got := cipServiceName("0x4C"); got != "Read Tag" {
		t.Fatalf("unexpected cip service: %q", got)
	}
}

package tshark

import (
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestBuildUDSTransactions(t *testing.T) {
	events := []udsEvent{
		{
			UDSMessageSummary: model.UDSMessageSummary{
				PacketID:       10,
				Time:           "10:00:00.000",
				ServiceID:      "0X22",
				ServiceName:    "Read Data By Identifier",
				SourceAddress:  "0x0E00",
				TargetAddress:  "0x07E0",
				DataIdentifier: "0XF190",
				Summary:        "request vin",
			},
			epoch: 1.0,
		},
		{
			UDSMessageSummary: model.UDSMessageSummary{
				PacketID:       11,
				Time:           "10:00:00.015",
				ServiceID:      "0X62",
				ServiceName:    "UDS Service",
				IsReply:        true,
				SourceAddress:  "0x07E0",
				TargetAddress:  "0x0E00",
				DataIdentifier: "0XF190",
				Summary:        "response vin",
			},
			epoch: 1.015,
		},
	}

	transactions := buildUDSTransactions(events)
	if len(transactions) != 1 {
		t.Fatalf("expected 1 transaction, got %#v", transactions)
	}
	if transactions[0].Status != "positive" || transactions[0].LatencyMS != 15 {
		t.Fatalf("unexpected uds transaction: %#v", transactions[0])
	}
}

func TestBuildCANSignalTimelines(t *testing.T) {
	messages := []model.CANDBCMessage{
		{
			PacketID:    1,
			Time:        "10:00:00.000",
			MessageName: "VehicleStatus",
			Signals: []model.CANDBCSignal{
				{Name: "Speed", Value: "12.5", Unit: "km/h"},
				{Name: "Switch", Value: "1"},
			},
		},
		{
			PacketID:    2,
			Time:        "10:00:00.050",
			MessageName: "VehicleStatus",
			Signals: []model.CANDBCSignal{
				{Name: "Speed", Value: "18.0", Unit: "km/h"},
			},
		},
	}

	timelines := buildCANSignalTimelines(messages)
	if len(timelines) != 2 {
		t.Fatalf("expected 2 timelines, got %#v", timelines)
	}
	if timelines[0].Name != "Speed" && timelines[1].Name != "Speed" {
		t.Fatalf("missing speed timeline: %#v", timelines)
	}
}

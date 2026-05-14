package model

import (
	"reflect"
	"testing"
)

func TestCoreContractJSONTags(t *testing.T) {
	tests := []struct {
		name string
		typ  reflect.Type
		want map[string]string
	}{
		{
			name: "Packet",
			typ:  reflect.TypeOf(Packet{}),
			want: map[string]string{
				"ID":          "id",
				"SourceIP":    "source_ip",
				"DestIP":      "dest_ip",
				"Protocol":    "protocol",
				"Length":      "length",
				"StreamID":    "stream_id",
				"RawHex":      "raw_hex,omitempty",
				"IPHeaderLen": "ip_header_len,omitempty",
			},
		},
		{
			name: "EvidenceRecord",
			typ:  reflect.TypeOf(EvidenceRecord{}),
			want: map[string]string{
				"ID":         "id",
				"Module":     "module",
				"PacketID":   "packet_id,omitempty",
				"StreamID":   "stream_id,omitempty",
				"SourceType": "source_type",
				"Summary":    "summary",
				"Severity":   "severity",
			},
		},
		{
			name: "EvidenceResponse",
			typ:  reflect.TypeOf(EvidenceResponse{}),
			want: map[string]string{
				"Records": "records",
				"Total":   "total",
				"Notes":   "notes,omitempty",
			},
		},
		{
			name: "ToolRuntimeSnapshot",
			typ:  reflect.TypeOf(ToolRuntimeSnapshot{}),
			want: map[string]string{
				"Config": "config",
				"TShark": "tshark",
				"FFmpeg": "ffmpeg",
				"Speech": "speech",
				"Yara":   "yara",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for field, want := range tt.want {
				structField, ok := tt.typ.FieldByName(field)
				if !ok {
					t.Fatalf("missing field %s on %s", field, tt.name)
				}
				if got := structField.Tag.Get("json"); got != want {
					t.Fatalf("%s.%s json tag = %q, want %q", tt.name, field, got, want)
				}
			}
		})
	}
}

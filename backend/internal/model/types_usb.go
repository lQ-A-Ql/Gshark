package model

import "strings"

type USBPacketRecord struct {
	PacketID       int64  `json:"packet_id"`
	Time           string `json:"time"`
	Protocol       string `json:"protocol"`
	BusID          string `json:"bus_id"`
	DeviceAddress  string `json:"device_address"`
	Endpoint       string `json:"endpoint"`
	Direction      string `json:"direction"`
	TransferType   string `json:"transfer_type"`
	URBType        string `json:"urb_type"`
	Status         string `json:"status"`
	DataLength     int    `json:"data_length"`
	SetupRequest   string `json:"setup_request,omitempty"`
	PayloadPreview string `json:"payload_preview,omitempty"`
	Summary        string `json:"summary"`
}

type USBKeyboardEvent struct {
	PacketID          int64    `json:"packet_id"`
	Time              string   `json:"time"`
	Device            string   `json:"device"`
	Endpoint          string   `json:"endpoint"`
	Modifiers         []string `json:"modifiers,omitempty"`
	Keys              []string `json:"keys,omitempty"`
	PressedModifiers  []string `json:"pressed_modifiers,omitempty"`
	ReleasedModifiers []string `json:"released_modifiers,omitempty"`
	PressedKeys       []string `json:"pressed_keys,omitempty"`
	ReleasedKeys      []string `json:"released_keys,omitempty"`
	Text              string   `json:"text,omitempty"`
	Summary           string   `json:"summary"`
}

type USBMouseEvent struct {
	PacketID        int64    `json:"packet_id"`
	Time            string   `json:"time"`
	Device          string   `json:"device"`
	Endpoint        string   `json:"endpoint"`
	Source          string   `json:"source,omitempty"`
	Layout          string   `json:"layout,omitempty"`
	Buttons         []string `json:"buttons,omitempty"`
	PressedButtons  []string `json:"pressed_buttons,omitempty"`
	ReleasedButtons []string `json:"released_buttons,omitempty"`
	XDelta          int      `json:"x_delta"`
	YDelta          int      `json:"y_delta"`
	WheelVertical   int      `json:"wheel_vertical"`
	WheelHorizontal int      `json:"wheel_horizontal"`
	PositionX       int      `json:"position_x"`
	PositionY       int      `json:"position_y"`
	Summary         string   `json:"summary"`
}

type USBHIDSourceMode string

const (
	USBHIDSourceAuto    USBHIDSourceMode = "auto"
	USBHIDSourceUSBHID  USBHIDSourceMode = "usbhid"
	USBHIDSourceCapData USBHIDSourceMode = "capdata"
	USBHIDSourceBTATT   USBHIDSourceMode = "btatt"
	USBHIDSourceRaw     USBHIDSourceMode = "raw"

	DefaultUSBHIDEventLimit = 20000
	MinUSBHIDEventLimit     = 500
	MaxUSBHIDEventLimit     = 100000
)

type USBAnalysisOptions struct {
	HIDSourceMode USBHIDSourceMode `json:"hid_source_mode,omitempty"`
	HIDEventLimit int              `json:"hid_event_limit,omitempty"`
}

type USBRawAnalysis struct {
	Records                []USBPacketRecord      `json:"records"`
	KeyboardEvents         []USBKeyboardEvent     `json:"keyboard_events"`
	MouseEvents            []USBMouseEvent        `json:"mouse_events"`
	OtherRecords           []USBPacketRecord      `json:"other_records"`
	HIDSourceMode          string                 `json:"hid_source_mode,omitempty"`
	HIDSourceCandidates    []string               `json:"hid_source_candidates,omitempty"`
	HIDSelectedSource      string                 `json:"hid_selected_source,omitempty"`
	HIDSourceNotes         []string               `json:"hid_source_notes,omitempty"`
	HIDEventLimit          int                    `json:"hid_event_limit"`
	HIDEventsTruncated     bool                   `json:"hid_events_truncated"`
	HIDMouseEventsTotal    int                    `json:"hid_mouse_events_total"`
	HIDKeyboardEventsTotal int                    `json:"hid_keyboard_events_total"`
	HID                    USBHIDAnalysis         `json:"hid"`
	MassStorage            USBMassStorageAnalysis `json:"mass_storage"`
	Other                  USBOtherAnalysis       `json:"other"`
	Notes                  []string               `json:"notes"`
}

func NormalizeUSBHIDSourceMode(value string) (USBHIDSourceMode, bool) {
	switch USBHIDSourceMode(strings.ToLower(strings.TrimSpace(value))) {
	case "", USBHIDSourceAuto:
		return USBHIDSourceAuto, true
	case USBHIDSourceUSBHID:
		return USBHIDSourceUSBHID, true
	case USBHIDSourceCapData:
		return USBHIDSourceCapData, true
	case USBHIDSourceBTATT:
		return USBHIDSourceBTATT, true
	case USBHIDSourceRaw:
		return USBHIDSourceRaw, true
	default:
		return USBHIDSourceAuto, false
	}
}

func NormalizeUSBHIDEventLimit(limit int) int {
	if limit <= 0 {
		return DefaultUSBHIDEventLimit
	}
	if limit < MinUSBHIDEventLimit {
		return MinUSBHIDEventLimit
	}
	if limit > MaxUSBHIDEventLimit {
		return MaxUSBHIDEventLimit
	}
	return limit
}

type USBMassStorageOperation struct {
	PacketID       int64   `json:"packet_id"`
	Time           string  `json:"time"`
	Device         string  `json:"device"`
	Endpoint       string  `json:"endpoint"`
	LUN            string  `json:"lun"`
	Command        string  `json:"command"`
	Operation      string  `json:"operation"`
	TransferLength int     `json:"transfer_length"`
	Direction      string  `json:"direction"`
	Status         string  `json:"status"`
	RequestFrame   int64   `json:"request_frame,omitempty"`
	ResponseFrame  int64   `json:"response_frame,omitempty"`
	LatencyMs      float64 `json:"latency_ms,omitempty"`
	DataResidue    int     `json:"data_residue,omitempty"`
	Summary        string  `json:"summary"`
}

type USBHIDAnalysis struct {
	KeyboardEvents []USBKeyboardEvent `json:"keyboard_events"`
	MouseEvents    []USBMouseEvent    `json:"mouse_events"`
	Devices        []TrafficBucket    `json:"devices"`
	Notes          []string           `json:"notes"`
}

type USBMassStorageAnalysis struct {
	TotalPackets    int                       `json:"total_packets"`
	ReadPackets     int                       `json:"read_packets"`
	WritePackets    int                       `json:"write_packets"`
	ControlPackets  int                       `json:"control_packets"`
	Devices         []TrafficBucket           `json:"devices"`
	LUNs            []TrafficBucket           `json:"luns"`
	Commands        []TrafficBucket           `json:"commands"`
	ReadOperations  []USBMassStorageOperation `json:"read_operations"`
	WriteOperations []USBMassStorageOperation `json:"write_operations"`
	Notes           []string                  `json:"notes"`
}

type USBOtherAnalysis struct {
	TotalPackets   int               `json:"total_packets"`
	ControlPackets int               `json:"control_packets"`
	Devices        []TrafficBucket   `json:"devices"`
	Endpoints      []TrafficBucket   `json:"endpoints"`
	SetupRequests  []TrafficBucket   `json:"setup_requests"`
	ControlRecords []USBPacketRecord `json:"control_records"`
	Records        []USBPacketRecord `json:"records"`
	Notes          []string          `json:"notes"`
}

type USBAnalysis struct {
	TotalUSBPackets        int                    `json:"total_usb_packets"`
	KeyboardPackets        int                    `json:"keyboard_packets"`
	MousePackets           int                    `json:"mouse_packets"`
	OtherUSBPackets        int                    `json:"other_usb_packets"`
	HIDPackets             int                    `json:"hid_packets"`
	MassStoragePackets     int                    `json:"mass_storage_packets"`
	Protocols              []TrafficBucket        `json:"protocols"`
	TransferTypes          []TrafficBucket        `json:"transfer_types"`
	Directions             []TrafficBucket        `json:"directions"`
	Devices                []TrafficBucket        `json:"devices"`
	Endpoints              []TrafficBucket        `json:"endpoints"`
	SetupRequests          []TrafficBucket        `json:"setup_requests"`
	Records                []USBPacketRecord      `json:"records"`
	KeyboardEvents         []USBKeyboardEvent     `json:"keyboard_events"`
	MouseEvents            []USBMouseEvent        `json:"mouse_events"`
	OtherRecords           []USBPacketRecord      `json:"other_records"`
	HIDSourceMode          string                 `json:"hid_source_mode,omitempty"`
	HIDSourceCandidates    []string               `json:"hid_source_candidates,omitempty"`
	HIDSelectedSource      string                 `json:"hid_selected_source,omitempty"`
	HIDSourceNotes         []string               `json:"hid_source_notes,omitempty"`
	HIDEventLimit          int                    `json:"hid_event_limit"`
	HIDEventsTruncated     bool                   `json:"hid_events_truncated"`
	HIDMouseEventsTotal    int                    `json:"hid_mouse_events_total"`
	HIDKeyboardEventsTotal int                    `json:"hid_keyboard_events_total"`
	HID                    USBHIDAnalysis         `json:"hid"`
	MassStorage            USBMassStorageAnalysis `json:"mass_storage"`
	Other                  USBOtherAnalysis       `json:"other"`
	Notes                  []string               `json:"notes"`
	Report                 InvestigationReport    `json:"report,omitempty"`
}

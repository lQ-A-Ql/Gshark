package model

type CANFrameSummary struct {
	PacketID   int64  `json:"packet_id"`
	Time       string `json:"time"`
	Identifier string `json:"identifier"`
	BusID      string `json:"bus_id"`
	Length     int    `json:"length"`
	RawData    string `json:"raw_data,omitempty"`
	IsExtended bool   `json:"is_extended"`
	IsRTR      bool   `json:"is_rtr"`
	IsError    bool   `json:"is_error"`
	ErrorFlags string `json:"error_flags,omitempty"`
	Summary    string `json:"summary"`
}

type CANPayloadRecord struct {
	PacketID      int64  `json:"packet_id"`
	Time          string `json:"time"`
	BusID         string `json:"bus_id"`
	Identifier    string `json:"identifier"`
	Protocol      string `json:"protocol"`
	FrameType     string `json:"frame_type,omitempty"`
	SourceAddress string `json:"source_address,omitempty"`
	TargetAddress string `json:"target_address,omitempty"`
	Service       string `json:"service,omitempty"`
	Detail        string `json:"detail,omitempty"`
	Length        int    `json:"length"`
	RawData       string `json:"raw_data,omitempty"`
	Summary       string `json:"summary"`
}

type DBCProfile struct {
	Path         string `json:"path"`
	Name         string `json:"name"`
	MessageCount int    `json:"message_count"`
	SignalCount  int    `json:"signal_count"`
}

type CANDBCSignal struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Unit  string `json:"unit,omitempty"`
}

type CANDBCMessage struct {
	PacketID    int64          `json:"packet_id"`
	Time        string         `json:"time"`
	BusID       string         `json:"bus_id"`
	Identifier  string         `json:"identifier"`
	Database    string         `json:"database"`
	MessageName string         `json:"message_name"`
	Sender      string         `json:"sender,omitempty"`
	Signals     []CANDBCSignal `json:"signals"`
	Summary     string         `json:"summary"`
}

type CANSignalSample struct {
	PacketID    int64   `json:"packet_id"`
	Time        string  `json:"time"`
	Value       float64 `json:"value"`
	Unit        string  `json:"unit,omitempty"`
	MessageName string  `json:"message_name,omitempty"`
}

type CANSignalTimeline struct {
	Name    string            `json:"name"`
	Samples []CANSignalSample `json:"samples"`
}

type J1939MessageSummary struct {
	PacketID    int64  `json:"packet_id"`
	Time        string `json:"time"`
	CANID       string `json:"can_id"`
	PGN         string `json:"pgn"`
	Priority    int    `json:"priority"`
	SourceAddr  string `json:"source_addr"`
	TargetAddr  string `json:"target_addr"`
	DataPreview string `json:"data_preview,omitempty"`
	Summary     string `json:"summary"`
}

type DoIPMessageSummary struct {
	PacketID        int64  `json:"packet_id"`
	Time            string `json:"time"`
	Source          string `json:"source"`
	Destination     string `json:"destination"`
	Type            string `json:"type"`
	VIN             string `json:"vin,omitempty"`
	LogicalAddress  string `json:"logical_address,omitempty"`
	SourceAddress   string `json:"source_address,omitempty"`
	TargetAddress   string `json:"target_address,omitempty"`
	TesterAddress   string `json:"tester_address,omitempty"`
	ResponseCode    string `json:"response_code,omitempty"`
	DiagnosticState string `json:"diagnostic_state,omitempty"`
	Summary         string `json:"summary"`
}

type UDSMessageSummary struct {
	PacketID       int64  `json:"packet_id"`
	Time           string `json:"time"`
	ServiceID      string `json:"service_id"`
	ServiceName    string `json:"service_name"`
	IsReply        bool   `json:"is_reply"`
	SubFunction    string `json:"sub_function,omitempty"`
	SourceAddress  string `json:"source_address,omitempty"`
	TargetAddress  string `json:"target_address,omitempty"`
	DataIdentifier string `json:"data_identifier,omitempty"`
	DiagnosticVIN  string `json:"diagnostic_vin,omitempty"`
	DTC            string `json:"dtc,omitempty"`
	NegativeCode   string `json:"negative_code,omitempty"`
	Summary        string `json:"summary"`
}

type UDSTransaction struct {
	RequestPacketID  int64   `json:"request_packet_id"`
	ResponsePacketID int64   `json:"response_packet_id,omitempty"`
	RequestTime      string  `json:"request_time"`
	ResponseTime     string  `json:"response_time,omitempty"`
	SourceAddress    string  `json:"source_address,omitempty"`
	TargetAddress    string  `json:"target_address,omitempty"`
	ServiceID        string  `json:"service_id"`
	ServiceName      string  `json:"service_name"`
	SubFunction      string  `json:"sub_function,omitempty"`
	DataIdentifier   string  `json:"data_identifier,omitempty"`
	DTC              string  `json:"dtc,omitempty"`
	Status           string  `json:"status"`
	NegativeCode     string  `json:"negative_code,omitempty"`
	LatencyMS        float64 `json:"latency_ms,omitempty"`
	RequestSummary   string  `json:"request_summary,omitempty"`
	ResponseSummary  string  `json:"response_summary,omitempty"`
}

type CANAnalysis struct {
	TotalFrames        int                 `json:"total_frames"`
	ExtendedFrames     int                 `json:"extended_frames"`
	RTRFrames          int                 `json:"rtr_frames"`
	ErrorFrames        int                 `json:"error_frames"`
	BusIDs             []TrafficBucket     `json:"bus_ids"`
	MessageIDs         []TrafficBucket     `json:"message_ids"`
	PayloadProtocols   []TrafficBucket     `json:"payload_protocols"`
	PayloadRecords     []CANPayloadRecord  `json:"payload_records"`
	DBCProfiles        []DBCProfile        `json:"dbc_profiles"`
	DecodedMessageDist []TrafficBucket     `json:"decoded_message_dist"`
	DecodedSignals     []TrafficBucket     `json:"decoded_signals"`
	DecodedMessages    []CANDBCMessage     `json:"decoded_messages"`
	SignalTimelines    []CANSignalTimeline `json:"signal_timelines"`
	Frames             []CANFrameSummary   `json:"frames"`
}

type J1939Analysis struct {
	TotalMessages int                   `json:"total_messages"`
	PGNs          []TrafficBucket       `json:"pgns"`
	SourceAddrs   []TrafficBucket       `json:"source_addrs"`
	TargetAddrs   []TrafficBucket       `json:"target_addrs"`
	Messages      []J1939MessageSummary `json:"messages"`
}

type DoIPAnalysis struct {
	TotalMessages int                  `json:"total_messages"`
	MessageTypes  []TrafficBucket      `json:"message_types"`
	VINs          []TrafficBucket      `json:"vins"`
	Endpoints     []TrafficBucket      `json:"endpoints"`
	Messages      []DoIPMessageSummary `json:"messages"`
}

type UDSAnalysis struct {
	TotalMessages int                 `json:"total_messages"`
	ServiceIDs    []TrafficBucket     `json:"service_ids"`
	NegativeCodes []TrafficBucket     `json:"negative_codes"`
	DTCs          []TrafficBucket     `json:"dtcs"`
	VINs          []TrafficBucket     `json:"vins"`
	Messages      []UDSMessageSummary `json:"messages"`
	Transactions  []UDSTransaction    `json:"transactions"`
}

type VehicleAnalysis struct {
	TotalVehiclePackets int                    `json:"total_vehicle_packets"`
	Protocols           []TrafficBucket        `json:"protocols"`
	Conversations       []AnalysisConversation `json:"conversations"`
	CAN                 CANAnalysis            `json:"can"`
	J1939               J1939Analysis          `json:"j1939"`
	DoIP                DoIPAnalysis           `json:"doip"`
	UDS                 UDSAnalysis            `json:"uds"`
	Recommendations     []string               `json:"recommendations"`
	Report              InvestigationReport    `json:"report,omitempty"`
}

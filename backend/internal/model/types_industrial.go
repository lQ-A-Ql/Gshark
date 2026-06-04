package model

type ModbusBitRange struct {
	Type    string `json:"type,omitempty"`
	Start   *int   `json:"start,omitempty"`
	Count   *int   `json:"count,omitempty"`
	Values  []bool `json:"values,omitempty"`
	Preview string `json:"preview,omitempty"`
}

type ModbusDecodedInput struct {
	StartPacketID int64  `json:"start_packet_id"`
	EndPacketID   int64  `json:"end_packet_id"`
	Source        string `json:"source,omitempty"`
	Destination   string `json:"destination,omitempty"`
	UnitID        int    `json:"unit_id,omitempty"`
	FunctionCode  int    `json:"function_code,omitempty"`
	FunctionName  string `json:"function_name,omitempty"`
	Reference     string `json:"reference,omitempty"`
	Encoding      string `json:"encoding"`
	Text          string `json:"text"`
	RawText       string `json:"raw_text,omitempty"`
	Summary       string `json:"summary,omitempty"`
}

type ModbusTransaction struct {
	PacketID       int64           `json:"packet_id"`
	Time           string          `json:"time"`
	Source         string          `json:"source"`
	Destination    string          `json:"destination"`
	TransactionID  int             `json:"transaction_id"`
	UnitID         int             `json:"unit_id"`
	FunctionCode   int             `json:"function_code"`
	FunctionName   string          `json:"function_name"`
	Kind           string          `json:"kind"`
	Reference      string          `json:"reference"`
	Quantity       string          `json:"quantity"`
	ExceptionCode  int             `json:"exception_code"`
	ResponseTime   string          `json:"response_time"`
	RegisterValues string          `json:"register_values,omitempty"`
	InputText      string          `json:"input_text,omitempty"`
	BitRange       *ModbusBitRange `json:"bit_range,omitempty"`
	Summary        string          `json:"summary"`
}

type ModbusAnalysis struct {
	TotalFrames    int                  `json:"total_frames"`
	Requests       int                  `json:"requests"`
	Responses      int                  `json:"responses"`
	Exceptions     int                  `json:"exceptions"`
	FunctionCodes  []TrafficBucket      `json:"function_codes"`
	UnitIDs        []TrafficBucket      `json:"unit_ids"`
	ReferenceHits  []TrafficBucket      `json:"reference_hits"`
	ExceptionCodes []TrafficBucket      `json:"exception_codes"`
	Transactions   []ModbusTransaction  `json:"transactions"`
	DecodedInputs  []ModbusDecodedInput `json:"decoded_inputs,omitempty"`
}

type IndustrialProtocolRecord struct {
	PacketID    int64  `json:"packet_id"`
	Time        string `json:"time"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Operation   string `json:"operation"`
	Target      string `json:"target,omitempty"`
	Result      string `json:"result,omitempty"`
	Value       string `json:"value,omitempty"`
	Summary     string `json:"summary"`
}

type IndustrialProtocolDetail struct {
	Name        string                     `json:"name"`
	TotalFrames int                        `json:"total_frames"`
	Operations  []TrafficBucket            `json:"operations"`
	Targets     []TrafficBucket            `json:"targets"`
	Results     []TrafficBucket            `json:"results"`
	Records     []IndustrialProtocolRecord `json:"records"`
}

// ModbusSuspiciousWrite aggregates write operations to a specific target address.
type ModbusSuspiciousWrite struct {
	Target         string   `json:"target"`
	UnitID         int      `json:"unit_id"`
	FunctionCode   int      `json:"function_code"`
	FunctionName   string   `json:"function_name"`
	WriteCount     int      `json:"write_count"`
	Sources        []string `json:"sources"`
	FirstTime      string   `json:"first_time"`
	LastTime       string   `json:"last_time"`
	SampleValues   []string `json:"sample_values"`
	SamplePacketID int64    `json:"sample_packet_id"`
}

// IndustrialControlCommand represents a control/operate command from IEC104, DNP3, etc.
type IndustrialControlCommand struct {
	PacketID    int64  `json:"packet_id"`
	Time        string `json:"time"`
	Protocol    string `json:"protocol"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Operation   string `json:"operation"`
	Target      string `json:"target"`
	Value       string `json:"value"`
	Result      string `json:"result"`
	Summary     string `json:"summary"`
}

type IndustrialRuleHit struct {
	Rule         string `json:"rule"`
	Level        string `json:"level"`
	PacketID     int64  `json:"packet_id,omitempty"`
	Time         string `json:"time,omitempty"`
	Source       string `json:"source,omitempty"`
	Destination  string `json:"destination,omitempty"`
	FunctionCode int    `json:"function_code,omitempty"`
	FunctionName string `json:"function_name,omitempty"`
	Target       string `json:"target,omitempty"`
	Evidence     string `json:"evidence,omitempty"`
	Summary      string `json:"summary"`
}

// DNP3DataObject represents a single data object within a DNP3 application fragment.
type DNP3DataObject struct {
	Group      int    `json:"group"`
	Variation  int    `json:"variation"`
	PointIndex int    `json:"point_index"`
	ObjectName string `json:"object_name,omitempty"`
	Value      string `json:"value,omitempty"`
	Qualifier  string `json:"qualifier,omitempty"`
}

// DNP3Frame represents a parsed DNP3 frame (link + application layer).
type DNP3Frame struct {
	PacketID      int64            `json:"packet_id"`
	Time          string           `json:"time"`
	Source        string           `json:"source"`
	Destination   string           `json:"destination"`
	SrcAddress    int              `json:"src_address"`
	DstAddress    int              `json:"dst_address"`
	Direction     string           `json:"direction"` // "request" or "response"
	FunctionCode  int              `json:"function_code"`
	FunctionName  string           `json:"function_name"`
	DataObjects   []DNP3DataObject `json:"data_objects,omitempty"`
	IIN           string           `json:"iin,omitempty"` // Internal Indications (response only)
	IsControl     bool             `json:"is_control,omitempty"`
	IsUnsolicited bool             `json:"is_unsolicited,omitempty"`
	Summary       string           `json:"summary"`
}

// DNP3Anomaly represents a detected anomaly in DNP3 traffic.
type DNP3Anomaly struct {
	Type        string `json:"type"` // "unauthorized_fc", "anomalous_response", "suspicious_control", "unexpected_iin"
	Severity    string `json:"severity"`
	PacketID    int64  `json:"packet_id"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Description string `json:"description"`
	Detail      string `json:"detail,omitempty"`
}

// DNP3Analysis holds the complete analysis result for DNP3 traffic.
type DNP3Analysis struct {
	TotalFrames   int             `json:"total_frames"`
	Requests      int             `json:"requests"`
	Responses     int             `json:"responses"`
	FunctionCodes []TrafficBucket `json:"function_codes"`
	DataObjects   []TrafficBucket `json:"data_objects"`
	Frames        []DNP3Frame     `json:"frames"`
	Anomalies     []DNP3Anomaly   `json:"anomalies,omitempty"`
	Notes         []string        `json:"notes,omitempty"`
}

type IndustrialAnalysis struct {
	TotalIndustrialPackets int                        `json:"total_industrial_packets"`
	Protocols              []TrafficBucket            `json:"protocols"`
	Conversations          []AnalysisConversation     `json:"conversations"`
	Modbus                 ModbusAnalysis             `json:"modbus"`
	IEC104                 IEC104Analysis             `json:"iec104,omitempty"`
	SuspiciousWrites       []ModbusSuspiciousWrite    `json:"suspicious_writes,omitempty"`
	ControlCommands        []IndustrialControlCommand `json:"control_commands,omitempty"`
	RuleHits               []IndustrialRuleHit        `json:"rule_hits,omitempty"`
	Details                []IndustrialProtocolDetail `json:"details"`
	Notes                  []string                   `json:"notes"`
	Report                 InvestigationReport        `json:"report,omitempty"`
}

// IEC104Frame represents a single parsed IEC 60870-5-104 frame.
type IEC104Frame struct {
	PacketID    int64  `json:"packet_id"`
	Time        string `json:"time,omitempty"`
	Source      string `json:"source,omitempty"`
	Destination string `json:"destination,omitempty"`
	// APCI fields
	APCIClass string `json:"apci_class"` // "I", "S", or "U"
	// I-format: Tx/Rx sequence numbers
	SendSeq int `json:"send_seq,omitempty"`
	RecvSeq int `json:"recv_seq,omitempty"`
	// U-format: control function
	UFunction string `json:"u_function,omitempty"` // STARTDT, STOPDT, TESTFR
	// S-format: confirm sequence
	ConfirmSeq int `json:"confirm_seq,omitempty"`
	// ASDU fields (I-format only)
	TypeID         int    `json:"type_id,omitempty"`
	TypeName       string `json:"type_name,omitempty"`
	TypeDirection  string `json:"type_direction,omitempty"` // "monitor" or "control"
	COT            int    `json:"cot,omitempty"`            // Cause of Transmission
	COTName        string `json:"cot_name,omitempty"`
	OriginatorAddr int    `json:"originator_addr,omitempty"`
	CommonAddr     int    `json:"common_addr,omitempty"`
	InfoObjectAddr int    `json:"info_object_addr,omitempty"`
	ASDUSummary    string `json:"asdu_summary,omitempty"`
	IsUnconfirmed  bool   `json:"is_unconfirmed,omitempty"` // S-frame confirm outstanding I-frames
}

// IEC104Anomaly represents a detected anomaly in IEC 104 traffic.
type IEC104Anomaly struct {
	Rule        string `json:"rule"`
	Level       string `json:"level"`
	PacketID    int64  `json:"packet_id,omitempty"`
	Time        string `json:"time,omitempty"`
	Source      string `json:"source,omitempty"`
	Destination string `json:"destination,omitempty"`
	Description string `json:"description"`
	Summary     string `json:"summary"`
}

// IEC104Analysis holds the aggregated IEC 60870-5-104 analysis results.
type IEC104Analysis struct {
	TotalFrames     int                        `json:"total_frames"`
	IFrameCount     int                        `json:"i_frame_count"`
	SFrameCount     int                        `json:"s_frame_count"`
	UFrameCount     int                        `json:"u_frame_count"`
	RequestCount    int                        `json:"request_count"`
	ResponseCount   int                        `json:"response_count"`
	TypeIDs         []TrafficBucket            `json:"type_ids,omitempty"`
	COTs            []TrafficBucket            `json:"cots,omitempty"`
	Frames          []IEC104Frame              `json:"frames,omitempty"`
	Anomalies       []IEC104Anomaly            `json:"anomalies,omitempty"`
	ControlCommands []IndustrialControlCommand `json:"control_commands,omitempty"`
	Notes           []string                   `json:"notes,omitempty"`
	Report          InvestigationReport        `json:"report,omitempty"`
}

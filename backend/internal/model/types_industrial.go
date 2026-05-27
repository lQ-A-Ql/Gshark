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

type IndustrialAnalysis struct {
	TotalIndustrialPackets int                        `json:"total_industrial_packets"`
	Protocols              []TrafficBucket            `json:"protocols"`
	Conversations          []AnalysisConversation     `json:"conversations"`
	Modbus                 ModbusAnalysis             `json:"modbus"`
	SuspiciousWrites       []ModbusSuspiciousWrite    `json:"suspicious_writes,omitempty"`
	ControlCommands        []IndustrialControlCommand `json:"control_commands,omitempty"`
	RuleHits               []IndustrialRuleHit        `json:"rule_hits,omitempty"`
	Details                []IndustrialProtocolDetail `json:"details"`
	Notes                  []string                   `json:"notes"`
	Report                 InvestigationReport        `json:"report,omitempty"`
}

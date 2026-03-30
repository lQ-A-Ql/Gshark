package model

type Packet struct {
	ID              int64               `json:"id"`
	Timestamp       string              `json:"timestamp"`
	SourceIP        string              `json:"source_ip"`
	SourcePort      int                 `json:"source_port"`
	DestIP          string              `json:"dest_ip"`
	DestPort        int                 `json:"dest_port"`
	Protocol        string              `json:"protocol"`
	DisplayProtocol string              `json:"display_protocol,omitempty"`
	Length          int                 `json:"length"`
	Info            string              `json:"info"`
	Payload         string              `json:"payload"`
	RawHex          string              `json:"raw_hex,omitempty"`
	StreamID        int64               `json:"stream_id"`
	IPHeaderLen     int                 `json:"ip_header_len,omitempty"`
	L4HeaderLen     int                 `json:"l4_header_len,omitempty"`
	Color           PacketColorFeatures `json:"color_features,omitempty"`
}

type PacketColorFeatures struct {
	TCPAnalysisFlags bool `json:"tcp_analysis_flags,omitempty"`
	TCPWindowUpdate  bool `json:"tcp_window_update,omitempty"`
	TCPKeepAlive     bool `json:"tcp_keep_alive,omitempty"`
	TCPKeepAliveAck  bool `json:"tcp_keep_alive_ack,omitempty"`
	TCPRST           bool `json:"tcp_rst,omitempty"`
	TCPSYN           bool `json:"tcp_syn,omitempty"`
	TCPFIN           bool `json:"tcp_fin,omitempty"`

	HSRPState  int `json:"hsrp_state,omitempty"`
	OSPFMsg    int `json:"ospf_msg,omitempty"`
	ICMPType   int `json:"icmp_type,omitempty"`
	ICMPv6Type int `json:"icmpv6_type,omitempty"`

	IPv4TTL      int `json:"ipv4_ttl,omitempty"`
	IPv6HopLimit int `json:"ipv6_hop_limit,omitempty"`

	STPTopologyChange bool `json:"stp_topology_change,omitempty"`
	ChecksumBad       bool `json:"checksum_bad,omitempty"`
	Broadcast         bool `json:"broadcast,omitempty"`

	HasSMB        bool `json:"has_smb,omitempty"`
	HasNBSS       bool `json:"has_nbss,omitempty"`
	HasNBNS       bool `json:"has_nbns,omitempty"`
	HasNetBIOS    bool `json:"has_netbios,omitempty"`
	HasDCERPC     bool `json:"has_dcerpc,omitempty"`
	HasSystemdJnl bool `json:"has_systemd_journal,omitempty"`
	HasSysdig     bool `json:"has_sysdig,omitempty"`
	HasHSRP       bool `json:"has_hsrp,omitempty"`
	HasEIGRP      bool `json:"has_eigrp,omitempty"`
	HasOSPF       bool `json:"has_ospf,omitempty"`
	HasBGP        bool `json:"has_bgp,omitempty"`
	HasCDP        bool `json:"has_cdp,omitempty"`
	HasVRRP       bool `json:"has_vrrp,omitempty"`
	HasCARP       bool `json:"has_carp,omitempty"`
	HasGVRP       bool `json:"has_gvrp,omitempty"`
	HasIGMP       bool `json:"has_igmp,omitempty"`
	HasISMP       bool `json:"has_ismp,omitempty"`
	HasRIP        bool `json:"has_rip,omitempty"`
	HasGLBP       bool `json:"has_glbp,omitempty"`
	HasPIM        bool `json:"has_pim,omitempty"`
}

type TLSConfig struct {
	SSLKeyLogFile string `json:"ssl_key_log_file"`
	RSAPrivateKey string `json:"rsa_private_key"`
	TargetIPPort  string `json:"target_ip_port"`
}

type ThreatHit struct {
	ID       int64  `json:"id"`
	PacketID int64  `json:"packet_id"`
	Category string `json:"category"`
	Rule     string `json:"rule"`
	Level    string `json:"level"`
	Preview  string `json:"preview"`
	Match    string `json:"match"`
}

type HuntingRuntimeConfig struct {
	Prefixes      []string `json:"prefixes"`
	YaraEnabled   bool     `json:"yara_enabled"`
	YaraBin       string   `json:"yara_bin"`
	YaraRules     string   `json:"yara_rules"`
	YaraTimeoutMS int      `json:"yara_timeout_ms"`
}

type ObjectFile struct {
	ID        int64  `json:"id"`
	PacketID  int64  `json:"packet_id"`
	Name      string `json:"name"`
	SizeBytes int64  `json:"size_bytes"`
	MIME      string `json:"mime"`
	Source    string `json:"source"`
	Path      string `json:"-"`
}

type Plugin struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Tag          string   `json:"tag"`
	Author       string   `json:"author"`
	Enabled      bool     `json:"enabled"`
	Entry        string   `json:"entry,omitempty"`
	Runtime      string   `json:"runtime,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
}

type PluginSource struct {
	ID            string `json:"id"`
	ConfigPath    string `json:"config_path"`
	ConfigContent string `json:"config_content"`
	LogicPath     string `json:"logic_path,omitempty"`
	LogicContent  string `json:"logic_content,omitempty"`
	Entry         string `json:"entry,omitempty"`
}

type AuditEntry struct {
	Time          string `json:"time"`
	Method        string `json:"method"`
	Path          string `json:"path"`
	Action        string `json:"action"`
	Risk          string `json:"risk"`
	Origin        string `json:"origin,omitempty"`
	RemoteAddr    string `json:"remote_addr,omitempty"`
	Status        int    `json:"status"`
	Authenticated bool   `json:"authenticated"`
}

type ParseOptions struct {
	FilePath      string    `json:"file_path"`
	DisplayFilter string    `json:"display_filter"`
	MaxPackets    int       `json:"max_packets"`
	EmitPackets   bool      `json:"emit_packets,omitempty"`
	FastList      bool      `json:"fast_list,omitempty"`
	TLS           TLSConfig `json:"tls,omitempty"`
}

type StreamChunk struct {
	PacketID  int64  `json:"packet_id"`
	Direction string `json:"direction"`
	Body      string `json:"body"`
}

type StreamChunkPatch struct {
	Index int    `json:"index"`
	Body  string `json:"body"`
}

type StreamLoadMeta struct {
	Source       string `json:"source,omitempty"`
	Loading      bool   `json:"loading,omitempty"`
	CacheHit     bool   `json:"cache_hit,omitempty"`
	IndexHit     bool   `json:"index_hit,omitempty"`
	FileFallback bool   `json:"file_fallback,omitempty"`
	TSharkMS     int64  `json:"tshark_ms,omitempty"`
}

type ReassembledStream struct {
	StreamID int64           `json:"stream_id"`
	Protocol string          `json:"protocol"`
	From     string          `json:"from"`
	To       string          `json:"to"`
	Chunks   []StreamChunk   `json:"chunks"`
	Request  string          `json:"request,omitempty"`
	Response string          `json:"response,omitempty"`
	LoadMeta *StreamLoadMeta `json:"load_meta,omitempty"`
}

type TrafficBucket struct {
	Label string `json:"label"`
	Count int    `json:"count"`
}

type GlobalTrafficStats struct {
	TotalPackets     int             `json:"total_packets"`
	ProtocolKinds    int             `json:"protocol_kinds"`
	Timeline         []TrafficBucket `json:"timeline"`
	ProtocolDist     []TrafficBucket `json:"protocol_dist"`
	TopTalkers       []TrafficBucket `json:"top_talkers"`
	TopHostnames     []TrafficBucket `json:"top_hostnames"`
	TopDomains       []TrafficBucket `json:"top_domains"`
	TopSrcIPs        []TrafficBucket `json:"top_src_ips"`
	TopDstIPs        []TrafficBucket `json:"top_dst_ips"`
	TopComputerNames []TrafficBucket `json:"top_computer_names"`
	TopDestPorts     []TrafficBucket `json:"top_dest_ports"`
	TopSrcPorts      []TrafficBucket `json:"top_src_ports"`
}

type AnalysisConversation struct {
	Label    string `json:"label"`
	Protocol string `json:"protocol,omitempty"`
	Count    int    `json:"count"`
}

type ModbusTransaction struct {
	PacketID       int64  `json:"packet_id"`
	Time           string `json:"time"`
	Source         string `json:"source"`
	Destination    string `json:"destination"`
	TransactionID  int    `json:"transaction_id"`
	UnitID         int    `json:"unit_id"`
	FunctionCode   int    `json:"function_code"`
	FunctionName   string `json:"function_name"`
	Kind           string `json:"kind"`
	Reference      string `json:"reference"`
	Quantity       string `json:"quantity"`
	ExceptionCode  int    `json:"exception_code"`
	ResponseTime   string `json:"response_time"`
	RegisterValues string `json:"register_values,omitempty"`
	Summary        string `json:"summary"`
}

type ModbusAnalysis struct {
	TotalFrames    int                 `json:"total_frames"`
	Requests       int                 `json:"requests"`
	Responses      int                 `json:"responses"`
	Exceptions     int                 `json:"exceptions"`
	FunctionCodes  []TrafficBucket     `json:"function_codes"`
	UnitIDs        []TrafficBucket     `json:"unit_ids"`
	ReferenceHits  []TrafficBucket     `json:"reference_hits"`
	ExceptionCodes []TrafficBucket     `json:"exception_codes"`
	Transactions   []ModbusTransaction `json:"transactions"`
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

type IndustrialAnalysis struct {
	TotalIndustrialPackets int                        `json:"total_industrial_packets"`
	Protocols              []TrafficBucket            `json:"protocols"`
	Conversations          []AnalysisConversation     `json:"conversations"`
	Modbus                 ModbusAnalysis             `json:"modbus"`
	Details                []IndustrialProtocolDetail `json:"details"`
	Notes                  []string                   `json:"notes"`
}

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
}

type MediaArtifact struct {
	Token     string `json:"token"`
	Name      string `json:"name"`
	Codec     string `json:"codec,omitempty"`
	Format    string `json:"format,omitempty"`
	SizeBytes int64  `json:"size_bytes"`
}

type MediaSession struct {
	ID              string         `json:"id"`
	Family          string         `json:"family"`
	Application     string         `json:"application"`
	Source          string         `json:"source"`
	SourcePort      int            `json:"source_port"`
	Destination     string         `json:"destination"`
	DestinationPort int            `json:"destination_port"`
	Transport       string         `json:"transport"`
	SSRC            string         `json:"ssrc,omitempty"`
	PayloadType     string         `json:"payload_type,omitempty"`
	Codec           string         `json:"codec,omitempty"`
	ClockRate       int            `json:"clock_rate,omitempty"`
	StartTime       string         `json:"start_time,omitempty"`
	EndTime         string         `json:"end_time,omitempty"`
	PacketCount     int            `json:"packet_count"`
	GapCount        int            `json:"gap_count"`
	ControlSummary  string         `json:"control_summary,omitempty"`
	Tags            []string       `json:"tags,omitempty"`
	Notes           []string       `json:"notes,omitempty"`
	Artifact        *MediaArtifact `json:"artifact,omitempty"`
}

type MediaAnalysis struct {
	TotalMediaPackets int             `json:"total_media_packets"`
	Protocols         []TrafficBucket `json:"protocols"`
	Applications      []TrafficBucket `json:"applications"`
	Sessions          []MediaSession  `json:"sessions"`
	Notes             []string        `json:"notes"`
}

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

type USBAnalysis struct {
	TotalUSBPackets int               `json:"total_usb_packets"`
	Protocols       []TrafficBucket   `json:"protocols"`
	TransferTypes   []TrafficBucket   `json:"transfer_types"`
	Directions      []TrafficBucket   `json:"directions"`
	Devices         []TrafficBucket   `json:"devices"`
	Endpoints       []TrafficBucket   `json:"endpoints"`
	SetupRequests   []TrafficBucket   `json:"setup_requests"`
	Records         []USBPacketRecord `json:"records"`
	Notes           []string          `json:"notes"`
}

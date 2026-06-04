package model

type TLSFingerprint struct {
	JA3Hash  string `json:"ja3_hash,omitempty"`
	JA3SHash string `json:"ja3s_hash,omitempty"`
	JA3Raw   string `json:"ja3_raw,omitempty"`
	JA3SRaw  string `json:"ja3s_raw,omitempty"`
}

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
	UDPPayloadHex   string              `json:"udp_payload_hex,omitempty"`
	StreamID        int64               `json:"stream_id"`
	IPHeaderLen     int                 `json:"ip_header_len,omitempty"`
	L4HeaderLen     int                 `json:"l4_header_len,omitempty"`
	Color           PacketColorFeatures `json:"color_features,omitempty"`
	TLSFingerprint  *TLSFingerprint     `json:"tls_fingerprint,omitempty"`
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

type ThreatHit struct {
	ID           int64    `json:"id"`
	PacketID     int64    `json:"packet_id"`
	Category     string   `json:"category"`
	Rule         string   `json:"rule"`
	Level        string   `json:"level"`
	Preview      string   `json:"preview"`
	Match        string   `json:"match"`
	TechniqueIDs []string `json:"technique_ids,omitempty"`
	TacticIDs    []string `json:"tactic_ids,omitempty"`
}

type ParseOptions struct {
	FilePath         string    `json:"file_path"`
	DisplayFilter    string    `json:"display_filter"`
	MaxPackets       int       `json:"max_packets"`
	EmitPackets      bool      `json:"emit_packets,omitempty"`
	FastList         bool      `json:"fast_list,omitempty"`
	ListProfile      string    `json:"list_profile,omitempty"`
	EnableEnrichment bool      `json:"enable_enrichment,omitempty"`
	TLS              TLSConfig `json:"tls,omitempty"`
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
	Source        string `json:"source,omitempty"`
	Loading       bool   `json:"loading,omitempty"`
	CacheHit      bool   `json:"cache_hit,omitempty"`
	IndexHit      bool   `json:"index_hit,omitempty"`
	FileFallback  bool   `json:"file_fallback,omitempty"`
	TSharkMS      int64  `json:"tshark_ms,omitempty"`
	OverrideCount int    `json:"override_count,omitempty"`
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

type StreamPayloadCandidate struct {
	ID           string   `json:"id"`
	Label        string   `json:"label"`
	Kind         string   `json:"kind"`
	ParamName    string   `json:"param_name,omitempty"`
	Value        string   `json:"value"`
	Preview      string   `json:"preview,omitempty"`
	Confidence   int      `json:"confidence,omitempty"`
	DecoderHints []string `json:"decoder_hints,omitempty"`
	Fingerprints []string `json:"fingerprints,omitempty"`
	FamilyHint   string   `json:"family_hint,omitempty"`
	// DecoderOptionsHint remains dynamic because different payload families expose different option sets.
	DecoderOptionsHint map[string]any `json:"decoder_options_hint,omitempty"`
	SourceRole         string         `json:"source_role,omitempty"`
}

type StreamPayloadInspection struct {
	NormalizedPayload    string                   `json:"normalized_payload"`
	Candidates           []StreamPayloadCandidate `json:"candidates,omitempty"`
	SuggestedCandidateID string                   `json:"suggested_candidate_id,omitempty"`
	SuggestedDecoder     string                   `json:"suggested_decoder,omitempty"`
	SuggestedFamily      string                   `json:"suggested_family,omitempty"`
	Confidence           int                      `json:"confidence,omitempty"`
	Reasons              []string                 `json:"reasons,omitempty"`
}

type StreamPayloadSource struct {
	ID           string   `json:"id"`
	Method       string   `json:"method,omitempty"`
	Host         string   `json:"host,omitempty"`
	URI          string   `json:"uri,omitempty"`
	PacketID     int64    `json:"packet_id"`
	StreamID     int64    `json:"stream_id,omitempty"`
	SourceType   string   `json:"source_type,omitempty"`
	ParamName    string   `json:"param_name,omitempty"`
	Payload      string   `json:"payload"`
	Preview      string   `json:"preview,omitempty"`
	Confidence   int      `json:"confidence,omitempty"`
	Signals      []string `json:"signals,omitempty"`
	DecoderHints []string `json:"decoder_hints,omitempty"`
	FamilyHint   string   `json:"family_hint,omitempty"`
	// DecoderOptionsHint stays dynamic for the same reason as StreamPayloadCandidate.DecoderOptionsHint.
	DecoderOptionsHint  map[string]any `json:"decoder_options_hint,omitempty"`
	SourceRole          string         `json:"source_role,omitempty"`
	ContentType         string         `json:"content_type,omitempty"`
	OccurrenceCount     int            `json:"occurrence_count,omitempty"`
	FirstTime           string         `json:"first_time,omitempty"`
	LastTime            string         `json:"last_time,omitempty"`
	RepeatWindowSeconds int            `json:"repeat_window_seconds,omitempty"`
	RelatedPackets      []int64        `json:"related_packets,omitempty"`
	RuleReasons         []string       `json:"rule_reasons,omitempty"`
}

type TrafficBucket struct {
	Label string `json:"label"`
	Count int    `json:"count"`
}

type ProtocolTreeNode struct {
	Name     string             `json:"name"`
	Count    int                `json:"count"`
	Children []ProtocolTreeNode `json:"children,omitempty"`
}

type GlobalTrafficStats struct {
	TotalPackets      int                `json:"total_packets"`
	ProtocolKinds     int                `json:"protocol_kinds"`
	Timeline          []TrafficBucket    `json:"timeline"`
	ProtocolDist      []TrafficBucket    `json:"protocol_dist"`
	TopTalkers        []TrafficBucket    `json:"top_talkers"`
	TopHostnames      []TrafficBucket    `json:"top_hostnames"`
	TopDomains        []TrafficBucket    `json:"top_domains"`
	TopSrcIPs         []TrafficBucket    `json:"top_src_ips"`
	TopDstIPs         []TrafficBucket    `json:"top_dst_ips"`
	TopComputerNames  []TrafficBucket    `json:"top_computer_names"`
	TopDestPorts      []TrafficBucket    `json:"top_dest_ports"`
	TopSrcPorts       []TrafficBucket    `json:"top_src_ports"`
	ProtocolHierarchy []ProtocolTreeNode `json:"protocol_hierarchy,omitempty"`
}

type AnalysisConversation struct {
	Label    string `json:"label"`
	Protocol string `json:"protocol,omitempty"`
	Count    int    `json:"count"`
}

type ObjectFile struct {
	ID        int64  `json:"id"`
	PacketID  int64  `json:"packet_id"`
	Name      string `json:"name"`
	SizeBytes int64  `json:"size_bytes"`
	MIME      string `json:"mime"`
	Magic     string `json:"magic,omitempty"`
	Source    string `json:"source"`
	Path      string `json:"-"`
}

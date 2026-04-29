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
	UDPPayloadHex   string              `json:"udp_payload_hex,omitempty"`
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

type YaraConfig struct {
	Enabled   bool
	Bin       string
	Rules     string
	TimeoutMS int
}

type ToolRuntimeConfig struct {
	TSharkPath    string `json:"tshark_path"`
	FFmpegPath    string `json:"ffmpeg_path"`
	PythonPath    string `json:"python_path"`
	VoskModelPath string `json:"vosk_model_path"`
	YaraEnabled   bool   `json:"yara_enabled"`
	YaraBin       string `json:"yara_bin"`
	YaraRules     string `json:"yara_rules"`
	YaraTimeoutMS int    `json:"yara_timeout_ms"`
}

type YaraToolStatus struct {
	Available        bool   `json:"available"`
	Enabled          bool   `json:"enabled"`
	Path             string `json:"path,omitempty"`
	RulePath         string `json:"rule_path,omitempty"`
	Message          string `json:"message"`
	LastScanMessage  string `json:"last_scan_message,omitempty"`
	CustomBin        string `json:"custom_bin,omitempty"`
	CustomRules      string `json:"custom_rules,omitempty"`
	UsingCustomBin   bool   `json:"using_custom_bin"`
	UsingCustomRules bool   `json:"using_custom_rules"`
	TimeoutMS        int    `json:"timeout_ms"`
}

type ToolRuntimeSnapshot struct {
	Config ToolRuntimeConfig  `json:"config"`
	TShark any                `json:"tshark"`
	FFmpeg any                `json:"ffmpeg"`
	Speech SpeechToTextStatus `json:"speech"`
	Yara   YaraToolStatus     `json:"yara"`
}

type WinRMDecryptRequest struct {
	Port                 int    `json:"port"`
	AuthMode             string `json:"auth_mode"`
	Password             string `json:"password,omitempty"`
	NTHash               string `json:"nt_hash,omitempty"`
	PreviewLines         int    `json:"preview_lines,omitempty"`
	IncludeErrorFrames   bool   `json:"include_error_frames,omitempty"`
	ExtractCommandOutput bool   `json:"extract_command_output,omitempty"`
}

type WinRMDecryptResult struct {
	ResultID            string `json:"result_id"`
	CaptureName         string `json:"capture_name"`
	Port                int    `json:"port"`
	AuthMode            string `json:"auth_mode"`
	PreviewText         string `json:"preview_text"`
	PreviewTruncated    bool   `json:"preview_truncated"`
	LineCount           int    `json:"line_count"`
	FrameCount          int    `json:"frame_count"`
	ErrorFrameCount     int    `json:"error_frame_count"`
	ExtractedFrameCount int    `json:"extracted_frame_count"`
	ExportFilename      string `json:"export_filename"`
	Message             string `json:"message"`
}

type SMB3RandomSessionKeyRequest struct {
	Username            string `json:"username"`
	Domain              string `json:"domain"`
	NTLMHash            string `json:"ntlm_hash"`
	NTProofStr          string `json:"nt_proof_str"`
	EncryptedSessionKey string `json:"encrypted_session_key"`
}

type SMB3SessionCandidate struct {
	SessionID           string `json:"session_id"`
	Username            string `json:"username"`
	Domain              string `json:"domain"`
	NTProofStr          string `json:"nt_proof_str"`
	EncryptedSessionKey string `json:"encrypted_session_key"`
	Src                 string `json:"src"`
	Dst                 string `json:"dst"`
	FrameNumber         string `json:"frame_number"`
	Timestamp           string `json:"timestamp"`
	Complete            bool   `json:"complete"`
	DisplayLabel        string `json:"display_label"`
}

type NTLMSessionMaterial struct {
	Protocol            string `json:"protocol"`
	Transport           string `json:"transport,omitempty"`
	FrameNumber         string `json:"frame_number"`
	Timestamp           string `json:"timestamp,omitempty"`
	Src                 string `json:"src,omitempty"`
	Dst                 string `json:"dst,omitempty"`
	SrcPort             string `json:"src_port,omitempty"`
	DstPort             string `json:"dst_port,omitempty"`
	Direction           string `json:"direction,omitempty"`
	Username            string `json:"username,omitempty"`
	Domain              string `json:"domain,omitempty"`
	UserDisplay         string `json:"user_display,omitempty"`
	Challenge           string `json:"challenge,omitempty"`
	NTProofStr          string `json:"nt_proof_str,omitempty"`
	EncryptedSessionKey string `json:"encrypted_session_key,omitempty"`
	SessionID           string `json:"session_id,omitempty"`
	AuthHeader          string `json:"auth_header,omitempty"`
	WWWAuthenticate     string `json:"www_authenticate,omitempty"`
	Info                string `json:"info,omitempty"`
	Complete            bool   `json:"complete"`
	DisplayLabel        string `json:"display_label"`
}

type HTTPLoginAttempt struct {
	PacketID           int64    `json:"packet_id"`
	ResponsePacketID   int64    `json:"response_packet_id,omitempty"`
	StreamID           int64    `json:"stream_id"`
	Time               string   `json:"time,omitempty"`
	ResponseTime       string   `json:"response_time,omitempty"`
	Src                string   `json:"src,omitempty"`
	Dst                string   `json:"dst,omitempty"`
	Method             string   `json:"method,omitempty"`
	Host               string   `json:"host,omitempty"`
	Path               string   `json:"path,omitempty"`
	EndpointLabel      string   `json:"endpoint_label,omitempty"`
	Username           string   `json:"username,omitempty"`
	PasswordPresent    bool     `json:"password_present,omitempty"`
	TokenPresent       bool     `json:"token_present,omitempty"`
	CaptchaPresent     bool     `json:"captcha_present,omitempty"`
	RequestKeys        []string `json:"request_keys,omitempty"`
	RequestContentType string   `json:"request_content_type,omitempty"`
	RequestPreview     string   `json:"request_preview,omitempty"`
	StatusCode         int      `json:"status_code,omitempty"`
	ResponseLocation   string   `json:"response_location,omitempty"`
	ResponseSetCookie  bool     `json:"response_set_cookie,omitempty"`
	ResponseTokenHint  bool     `json:"response_token_hint,omitempty"`
	ResponseIndicators []string `json:"response_indicators,omitempty"`
	ResponsePreview    string   `json:"response_preview,omitempty"`
	Result             string   `json:"result,omitempty"`
	Reason             string   `json:"reason,omitempty"`
	PossibleBruteforce bool     `json:"possible_bruteforce,omitempty"`
}

type HTTPLoginEndpoint struct {
	Key                string          `json:"key"`
	Method             string          `json:"method,omitempty"`
	Host               string          `json:"host,omitempty"`
	Path               string          `json:"path,omitempty"`
	AttemptCount       int             `json:"attempt_count"`
	SuccessCount       int             `json:"success_count"`
	FailureCount       int             `json:"failure_count"`
	UncertainCount     int             `json:"uncertain_count"`
	PossibleBruteforce bool            `json:"possible_bruteforce,omitempty"`
	UsernameVariants   int             `json:"username_variants,omitempty"`
	PasswordAttempts   int             `json:"password_attempts,omitempty"`
	CaptchaCount       int             `json:"captcha_count,omitempty"`
	SetCookieCount     int             `json:"set_cookie_count,omitempty"`
	TokenHintCount     int             `json:"token_hint_count,omitempty"`
	StatusCodes        []TrafficBucket `json:"status_codes,omitempty"`
	RequestKeys        []string        `json:"request_keys,omitempty"`
	ResponseIndicators []string        `json:"response_indicators,omitempty"`
	SamplePacketIDs    []int64         `json:"sample_packet_ids,omitempty"`
	Notes              []string        `json:"notes,omitempty"`
}

type HTTPLoginAnalysis struct {
	TotalAttempts      int                 `json:"total_attempts"`
	CandidateEndpoints int                 `json:"candidate_endpoints"`
	SuccessCount       int                 `json:"success_count"`
	FailureCount       int                 `json:"failure_count"`
	UncertainCount     int                 `json:"uncertain_count"`
	BruteforceCount    int                 `json:"bruteforce_count"`
	Endpoints          []HTTPLoginEndpoint `json:"endpoints,omitempty"`
	Attempts           []HTTPLoginAttempt  `json:"attempts,omitempty"`
	Notes              []string            `json:"notes,omitempty"`
}

type SMTPCommandRecord struct {
	PacketID   int64  `json:"packet_id"`
	Time       string `json:"time,omitempty"`
	Direction  string `json:"direction,omitempty"`
	Command    string `json:"command,omitempty"`
	Argument   string `json:"argument,omitempty"`
	StatusCode int    `json:"status_code,omitempty"`
	Summary    string `json:"summary,omitempty"`
}

type SMTPMessage struct {
	Sequence        int      `json:"sequence"`
	MailFrom        string   `json:"mail_from,omitempty"`
	RcptTo          []string `json:"rcpt_to,omitempty"`
	Subject         string   `json:"subject,omitempty"`
	From            string   `json:"from,omitempty"`
	To              string   `json:"to,omitempty"`
	Date            string   `json:"date,omitempty"`
	ContentType     string   `json:"content_type,omitempty"`
	Boundary        string   `json:"boundary,omitempty"`
	AttachmentNames []string `json:"attachment_names,omitempty"`
	BodyPreview     string   `json:"body_preview,omitempty"`
	PacketIDs       []int64  `json:"packet_ids,omitempty"`
}

type SMTPSession struct {
	StreamID          int64               `json:"stream_id"`
	Client            string              `json:"client,omitempty"`
	Server            string              `json:"server,omitempty"`
	ClientPort        int                 `json:"client_port,omitempty"`
	ServerPort        int                 `json:"server_port,omitempty"`
	Helo              string              `json:"helo,omitempty"`
	AuthMechanisms    []string            `json:"auth_mechanisms,omitempty"`
	AuthUsername      string              `json:"auth_username,omitempty"`
	AuthPasswordSeen  bool                `json:"auth_password_seen,omitempty"`
	MailFrom          []string            `json:"mail_from,omitempty"`
	RcptTo            []string            `json:"rcpt_to,omitempty"`
	CommandCount      int                 `json:"command_count"`
	MessageCount      int                 `json:"message_count"`
	AttachmentHints   int                 `json:"attachment_hints,omitempty"`
	Commands          []SMTPCommandRecord `json:"commands,omitempty"`
	StatusHints       []string            `json:"status_hints,omitempty"`
	Messages          []SMTPMessage       `json:"messages,omitempty"`
	PossibleCleartext bool                `json:"possible_cleartext,omitempty"`
}

type SMTPAnalysis struct {
	SessionCount        int           `json:"session_count"`
	MessageCount        int           `json:"message_count"`
	AuthCount           int           `json:"auth_count"`
	AttachmentHintCount int           `json:"attachment_hint_count"`
	Sessions            []SMTPSession `json:"sessions,omitempty"`
	Notes               []string      `json:"notes,omitempty"`
}

type MySQLQueryRecord struct {
	PacketID         int64  `json:"packet_id"`
	Time             string `json:"time,omitempty"`
	Command          string `json:"command,omitempty"`
	SQL              string `json:"sql,omitempty"`
	Database         string `json:"database,omitempty"`
	ResponsePacketID int64  `json:"response_packet_id,omitempty"`
	ResponseKind     string `json:"response_kind,omitempty"`
	ResponseCode     int    `json:"response_code,omitempty"`
	ResponseSummary  string `json:"response_summary,omitempty"`
}

type MySQLServerEvent struct {
	PacketID int64  `json:"packet_id"`
	Time     string `json:"time,omitempty"`
	Sequence int    `json:"sequence,omitempty"`
	Kind     string `json:"kind,omitempty"`
	Code     int    `json:"code,omitempty"`
	Summary  string `json:"summary,omitempty"`
}

type MySQLSession struct {
	StreamID       int64              `json:"stream_id"`
	Client         string             `json:"client,omitempty"`
	Server         string             `json:"server,omitempty"`
	ClientPort     int                `json:"client_port,omitempty"`
	ServerPort     int                `json:"server_port,omitempty"`
	ServerVersion  string             `json:"server_version,omitempty"`
	ConnectionID   int64              `json:"connection_id,omitempty"`
	Username       string             `json:"username,omitempty"`
	Database       string             `json:"database,omitempty"`
	AuthPlugin     string             `json:"auth_plugin,omitempty"`
	LoginPacketID  int64              `json:"login_packet_id,omitempty"`
	LoginSuccess   bool               `json:"login_success,omitempty"`
	QueryCount     int                `json:"query_count"`
	OKCount        int                `json:"ok_count"`
	ErrCount       int                `json:"err_count"`
	ResultsetCount int                `json:"resultset_count"`
	CommandTypes   []string           `json:"command_types,omitempty"`
	Queries        []MySQLQueryRecord `json:"queries,omitempty"`
	ServerEvents   []MySQLServerEvent `json:"server_events,omitempty"`
	Notes          []string           `json:"notes,omitempty"`
}

type MySQLAnalysis struct {
	SessionCount   int            `json:"session_count"`
	LoginCount     int            `json:"login_count"`
	QueryCount     int            `json:"query_count"`
	ErrorCount     int            `json:"error_count"`
	ResultsetCount int            `json:"resultset_count"`
	Sessions       []MySQLSession `json:"sessions,omitempty"`
	Notes          []string       `json:"notes,omitempty"`
}

type ShiroRememberMeKeyResult struct {
	Label        string `json:"label"`
	Base64       string `json:"base64,omitempty"`
	Algorithm    string `json:"algorithm,omitempty"`
	Hit          bool   `json:"hit,omitempty"`
	PayloadClass string `json:"payload_class,omitempty"`
	Preview      string `json:"preview,omitempty"`
	Reason       string `json:"reason,omitempty"`
}

type ShiroRememberMeCandidate struct {
	PacketID        int64                      `json:"packet_id"`
	StreamID        int64                      `json:"stream_id,omitempty"`
	Time            string                     `json:"time,omitempty"`
	Src             string                     `json:"src,omitempty"`
	Dst             string                     `json:"dst,omitempty"`
	Host            string                     `json:"host,omitempty"`
	Path            string                     `json:"path,omitempty"`
	SourceHeader    string                     `json:"source_header,omitempty"`
	CookieName      string                     `json:"cookie_name,omitempty"`
	CookieValue     string                     `json:"cookie_value,omitempty"`
	CookiePreview   string                     `json:"cookie_preview,omitempty"`
	DecodeOK        bool                       `json:"decode_ok,omitempty"`
	EncryptedLength int                        `json:"encrypted_length,omitempty"`
	AesBlockAligned bool                       `json:"aes_block_aligned,omitempty"`
	PossibleCBC     bool                       `json:"possible_cbc,omitempty"`
	PossibleGCM     bool                       `json:"possible_gcm,omitempty"`
	KeyResults      []ShiroRememberMeKeyResult `json:"key_results,omitempty"`
	HitCount        int                        `json:"hit_count,omitempty"`
	Notes           []string                   `json:"notes,omitempty"`
}

type ShiroRememberMeAnalysis struct {
	CandidateCount int                        `json:"candidate_count"`
	HitCount       int                        `json:"hit_count"`
	Candidates     []ShiroRememberMeCandidate `json:"candidates,omitempty"`
	Notes          []string                   `json:"notes,omitempty"`
}

type ShiroRememberMeRequest struct {
	CandidateKeys []string `json:"candidate_keys,omitempty"`
}

type MiscModuleFieldOption struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

type MiscModuleFormField struct {
	Name         string                  `json:"name"`
	Label        string                  `json:"label"`
	Type         string                  `json:"type"`
	Placeholder  string                  `json:"placeholder,omitempty"`
	DefaultValue string                  `json:"default_value,omitempty"`
	HelpText     string                  `json:"help_text,omitempty"`
	Required     bool                    `json:"required,omitempty"`
	Secret       bool                    `json:"secret,omitempty"`
	Rows         int                     `json:"rows,omitempty"`
	Options      []MiscModuleFieldOption `json:"options,omitempty"`
}

type MiscModuleFormSchema struct {
	Description string                `json:"description,omitempty"`
	SubmitLabel string                `json:"submit_label,omitempty"`
	ResultTitle string                `json:"result_title,omitempty"`
	Fields      []MiscModuleFormField `json:"fields,omitempty"`
}

type MiscModuleInterfaceSchema struct {
	Method     string `json:"method,omitempty"`
	InvokePath string `json:"invoke_path,omitempty"`
	Runtime    string `json:"runtime,omitempty"`
	Entry      string `json:"entry,omitempty"`
	HostBridge bool   `json:"host_bridge,omitempty"`
}

type MiscModuleTableColumn struct {
	Key   string `json:"key"`
	Label string `json:"label"`
}

type MiscModuleTableResult struct {
	Columns []MiscModuleTableColumn `json:"columns,omitempty"`
	Rows    []map[string]string     `json:"rows,omitempty"`
}

type MiscModuleManifest struct {
	ID              string                     `json:"id"`
	Kind            string                     `json:"kind"`
	Title           string                     `json:"title"`
	Summary         string                     `json:"summary"`
	Tags            []string                   `json:"tags"`
	APIPrefix       string                     `json:"api_prefix"`
	DocsPath        string                     `json:"docs_path,omitempty"`
	RequiresCapture bool                       `json:"requires_capture"`
	ProtocolDomain  string                     `json:"protocol_domain,omitempty"`
	SupportsExport  bool                       `json:"supports_export,omitempty"`
	Cancellable     bool                       `json:"cancellable,omitempty"`
	DependsOn       []string                   `json:"depends_on,omitempty"`
	FormSchema      *MiscModuleFormSchema      `json:"form_schema,omitempty"`
	InterfaceSchema *MiscModuleInterfaceSchema `json:"interface_schema,omitempty"`
}

type MiscModuleRunRequest struct {
	Values map[string]string `json:"values"`
}

type MiscModuleRunResult struct {
	Message string                 `json:"message,omitempty"`
	Text    string                 `json:"text,omitempty"`
	Output  any                    `json:"output,omitempty"`
	Table   *MiscModuleTableResult `json:"table,omitempty"`
}

type MiscModulePackageManifest struct {
	ID              string   `json:"id"`
	Title           string   `json:"title"`
	Summary         string   `json:"summary"`
	Version         string   `json:"version,omitempty"`
	Author          string   `json:"author,omitempty"`
	Tags            []string `json:"tags,omitempty"`
	RequiresCapture bool     `json:"requires_capture,omitempty"`
	Backend         string   `json:"backend,omitempty"`
	Form            string   `json:"form,omitempty"`
	API             string   `json:"api,omitempty"`
}

type MiscModulePackageImportResult struct {
	Module        MiscModuleManifest `json:"module"`
	InstalledPath string             `json:"installed_path"`
	Message       string             `json:"message"`
}

type SMB3RandomSessionKeyResult struct {
	RandomSessionKey string `json:"random_session_key"`
	Message          string `json:"message"`
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

type C2IndicatorRecord struct {
	PacketID              int64    `json:"packet_id"`
	StreamID              int64    `json:"stream_id,omitempty"`
	Time                  string   `json:"time,omitempty"`
	Family                string   `json:"family"`
	Channel               string   `json:"channel,omitempty"`
	Source                string   `json:"source,omitempty"`
	Destination           string   `json:"destination,omitempty"`
	Host                  string   `json:"host,omitempty"`
	URI                   string   `json:"uri,omitempty"`
	Method                string   `json:"method,omitempty"`
	IndicatorType         string   `json:"indicator_type,omitempty"`
	IndicatorValue        string   `json:"indicator_value,omitempty"`
	Confidence            int      `json:"confidence,omitempty"`
	Summary               string   `json:"summary"`
	Evidence              string   `json:"evidence,omitempty"`
	Tags                  []string `json:"tags,omitempty"`
	ActorHints            []string `json:"actor_hints,omitempty"`
	SampleFamily          string   `json:"sample_family,omitempty"`
	CampaignStage         string   `json:"campaign_stage,omitempty"`
	TransportTraits       []string `json:"transport_traits,omitempty"`
	InfrastructureHints   []string `json:"infrastructure_hints,omitempty"`
	TTPTags               []string `json:"ttp_tags,omitempty"`
	AttributionConfidence int      `json:"attribution_confidence,omitempty"`
}

type C2BeaconPattern struct {
	Name       string `json:"name"`
	Value      string `json:"value"`
	Confidence int    `json:"confidence,omitempty"`
	Summary    string `json:"summary"`
}

type C2HTTPEndpointAggregate struct {
	Host                string          `json:"host"`
	URI                 string          `json:"uri"`
	Channel             string          `json:"channel,omitempty"`
	Total               int             `json:"total"`
	GetCount            int             `json:"get_count"`
	PostCount           int             `json:"post_count"`
	Methods             []TrafficBucket `json:"methods"`
	FirstTime           string          `json:"first_time,omitempty"`
	LastTime            string          `json:"last_time,omitempty"`
	AvgInterval         string          `json:"avg_interval,omitempty"`
	Jitter              string          `json:"jitter,omitempty"`
	Streams             []int64         `json:"streams,omitempty"`
	Packets             []int64         `json:"packets,omitempty"`
	RepresentativePacket int64          `json:"representative_packet,omitempty"`
	Confidence          int             `json:"confidence,omitempty"`
	Summary             string          `json:"summary"`
}

type C2DNSAggregate struct {
	QName           string          `json:"qname"`
	Total           int             `json:"total"`
	MaxLabelLength  int             `json:"max_label_length"`
	QueryTypes      []TrafficBucket `json:"query_types"`
	TxtCount        int             `json:"txt_count"`
	NullCount       int             `json:"null_count"`
	CnameCount      int             `json:"cname_count"`
	RequestCount    int             `json:"request_count"`
	ResponseCount   int             `json:"response_count"`
	FirstTime       string          `json:"first_time,omitempty"`
	LastTime        string          `json:"last_time,omitempty"`
	AvgInterval     string          `json:"avg_interval,omitempty"`
	Jitter          string          `json:"jitter,omitempty"`
	Packets         []int64         `json:"packets,omitempty"`
	Confidence      int             `json:"confidence,omitempty"`
	Summary         string          `json:"summary"`
}

type C2StreamAggregate struct {
	StreamID        int64           `json:"stream_id"`
	Protocol        string          `json:"protocol,omitempty"`
	TotalPackets    int             `json:"total_packets"`
	ArchMarkers     []TrafficBucket `json:"arch_markers,omitempty"`
	LengthPrefix    int             `json:"length_prefix_count"`
	ShortPackets    int             `json:"short_packets"`
	LongPackets     int             `json:"long_packets"`
	Transitions     int             `json:"transitions"`
	HeartbeatAvg    string          `json:"heartbeat_avg,omitempty"`
	HeartbeatJitter string          `json:"heartbeat_jitter,omitempty"`
	HasWebSocket    bool            `json:"has_websocket"`
	WSParams        string          `json:"ws_params,omitempty"`
	ListenerHints   []TrafficBucket `json:"listener_hints,omitempty"`
	FirstTime       string          `json:"first_time,omitempty"`
	LastTime        string          `json:"last_time,omitempty"`
	Packets         []int64         `json:"packets,omitempty"`
	Confidence      int             `json:"confidence,omitempty"`
	Summary         string          `json:"summary"`
}

type C2FamilyAnalysis struct {
	CandidateCount    int                       `json:"candidate_count"`
	MatchedRuleCount  int                       `json:"matched_rule_count"`
	Channels          []TrafficBucket           `json:"channels"`
	Indicators        []TrafficBucket           `json:"indicators"`
	Conversations     []AnalysisConversation    `json:"conversations"`
	BeaconPatterns    []C2BeaconPattern         `json:"beacon_patterns,omitempty"`
	HostURIAggregates []C2HTTPEndpointAggregate `json:"host_uri_aggregates,omitempty"`
	DNSAggregates     []C2DNSAggregate          `json:"dns_aggregates,omitempty"`
	StreamAggregates  []C2StreamAggregate       `json:"stream_aggregates,omitempty"`
	Candidates        []C2IndicatorRecord       `json:"candidates"`
	Notes             []string                  `json:"notes"`
	RelatedActors     []TrafficBucket           `json:"related_actors,omitempty"`
	DeliveryChains    []TrafficBucket           `json:"delivery_chains,omitempty"`
}

type C2SampleAnalysis struct {
	TotalMatchedPackets int                    `json:"total_matched_packets"`
	Families            []TrafficBucket        `json:"families"`
	Conversations       []AnalysisConversation `json:"conversations"`
	CS                  C2FamilyAnalysis       `json:"cs"`
	VShell              C2FamilyAnalysis       `json:"vshell"`
	Notes               []string               `json:"notes"`
}

type ModbusBitRange struct {
	Type    string `json:"type,omitempty"`
	Start   *int   `json:"start,omitempty"`
	Count   *int   `json:"count,omitempty"`
	Values  []bool `json:"values,omitempty"`
	Preview string `json:"preview,omitempty"`
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
	BitRange       *ModbusBitRange `json:"bit_range,omitempty"`
	Summary        string          `json:"summary"`
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
	MediaType       string         `json:"media_type"`
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

type SpeechToTextStatus struct {
	Available       bool   `json:"available"`
	Engine          string `json:"engine"`
	Language        string `json:"language"`
	PythonAvailable bool   `json:"python_available"`
	PythonCommand   string `json:"python_command,omitempty"`
	FFmpegAvailable bool   `json:"ffmpeg_available"`
	VoskAvailable   bool   `json:"vosk_available"`
	ModelAvailable  bool   `json:"model_available"`
	ModelPath       string `json:"model_path,omitempty"`
	Message         string `json:"message"`
}

type MediaTranscriptionSegment struct {
	StartSeconds float64 `json:"start_seconds"`
	EndSeconds   float64 `json:"end_seconds"`
	Text         string  `json:"text"`
}

type MediaTranscription struct {
	Token           string                      `json:"token"`
	SessionID       string                      `json:"session_id"`
	Title           string                      `json:"title"`
	Text            string                      `json:"text"`
	Language        string                      `json:"language"`
	Engine          string                      `json:"engine"`
	Status          string                      `json:"status"`
	Error           string                      `json:"error,omitempty"`
	Cached          bool                        `json:"cached"`
	DurationSeconds float64                     `json:"duration_seconds"`
	Segments        []MediaTranscriptionSegment `json:"segments,omitempty"`
}

type SpeechBatchTaskItem struct {
	Token      string `json:"token"`
	SessionID  string `json:"session_id"`
	MediaLabel string `json:"media_label"`
	Title      string `json:"title"`
	Status     string `json:"status"`
	Error      string `json:"error,omitempty"`
	Cached     bool   `json:"cached"`
	Text       string `json:"text,omitempty"`
}

type SpeechBatchTaskStatus struct {
	TaskID       string                `json:"task_id"`
	Total        int                   `json:"total"`
	Queued       int                   `json:"queued"`
	Running      int                   `json:"running"`
	Completed    int                   `json:"completed"`
	Failed       int                   `json:"failed"`
	Skipped      int                   `json:"skipped"`
	CurrentToken string                `json:"current_token,omitempty"`
	CurrentLabel string                `json:"current_label,omitempty"`
	Done         bool                  `json:"done"`
	Cancelled    bool                  `json:"cancelled"`
	Items        []SpeechBatchTaskItem `json:"items"`
}

type MediaTranscriptionBatchItem struct {
	Token     string `json:"token"`
	SessionID string `json:"session_id"`
	Title     string `json:"title"`
	Text      string `json:"text"`
	Status    string `json:"status"`
	Cached    bool   `json:"cached"`
}

type MediaTranscriptionBatchExport struct {
	TaskID   string                        `json:"task_id"`
	Engine   string                        `json:"engine"`
	Language string                        `json:"language"`
	Items    []MediaTranscriptionBatchItem `json:"items"`
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
	TotalUSBPackets    int                    `json:"total_usb_packets"`
	KeyboardPackets    int                    `json:"keyboard_packets"`
	MousePackets       int                    `json:"mouse_packets"`
	OtherUSBPackets    int                    `json:"other_usb_packets"`
	HIDPackets         int                    `json:"hid_packets"`
	MassStoragePackets int                    `json:"mass_storage_packets"`
	Protocols          []TrafficBucket        `json:"protocols"`
	TransferTypes      []TrafficBucket        `json:"transfer_types"`
	Directions         []TrafficBucket        `json:"directions"`
	Devices            []TrafficBucket        `json:"devices"`
	Endpoints          []TrafficBucket        `json:"endpoints"`
	SetupRequests      []TrafficBucket        `json:"setup_requests"`
	Records            []USBPacketRecord      `json:"records"`
	KeyboardEvents     []USBKeyboardEvent     `json:"keyboard_events"`
	MouseEvents        []USBMouseEvent        `json:"mouse_events"`
	OtherRecords       []USBPacketRecord      `json:"other_records"`
	HID                USBHIDAnalysis         `json:"hid"`
	MassStorage        USBMassStorageAnalysis `json:"mass_storage"`
	Other              USBOtherAnalysis       `json:"other"`
	Notes              []string               `json:"notes"`
}

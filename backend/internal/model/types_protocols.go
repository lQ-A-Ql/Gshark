package model

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
	Report             InvestigationReport `json:"report,omitempty"`
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
	SessionCount        int                 `json:"session_count"`
	MessageCount        int                 `json:"message_count"`
	AuthCount           int                 `json:"auth_count"`
	AttachmentHintCount int                 `json:"attachment_hint_count"`
	Sessions            []SMTPSession       `json:"sessions,omitempty"`
	Notes               []string            `json:"notes,omitempty"`
	Report              InvestigationReport `json:"report,omitempty"`
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
	SessionCount   int                 `json:"session_count"`
	LoginCount     int                 `json:"login_count"`
	QueryCount     int                 `json:"query_count"`
	ErrorCount     int                 `json:"error_count"`
	ResultsetCount int                 `json:"resultset_count"`
	Sessions       []MySQLSession      `json:"sessions,omitempty"`
	Notes          []string            `json:"notes,omitempty"`
	Report         InvestigationReport `json:"report,omitempty"`
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
	Report         InvestigationReport        `json:"report,omitempty"`
}

type ShiroRememberMeRequest struct {
	CandidateKeys []string `json:"candidate_keys,omitempty"`
}

type SMB3RandomSessionKeyResult struct {
	RandomSessionKey string `json:"random_session_key"`
	Message          string `json:"message"`
}

// UDP Tunnel Detection

type UDPTunnelAnalysis struct {
	TotalSuspicious int                  `json:"total_suspicious"`
	DNSTunnelHits   []DNSTunnelCandidate `json:"dns_tunnel_hits"`
	UDPTunnelHits   []UDPTunnelCandidate `json:"udp_tunnel_hits"`
	Notes           []string             `json:"notes"`
}

type DNSTunnelCandidate struct {
	BaseDomain       string  `json:"base_domain"`
	QueryCount       int     `json:"query_count"`
	UniqueSubdomains int     `json:"unique_subdomains"`
	AvgSubdomainLen  float64 `json:"avg_subdomain_len"`
	MaxPayloadSize   int     `json:"max_payload_size"`
	EntropyScore     float64 `json:"entropy_score"`
	Confidence       int     `json:"confidence"`
	FirstPacketID    int64   `json:"first_packet_id"`
	Evidence         string  `json:"evidence"`
}

type UDPTunnelCandidate struct {
	Source        string  `json:"source"`
	Destination   string  `json:"destination"`
	Port          int     `json:"port"`
	PacketCount   int     `json:"packet_count"`
	BytesTotal    int     `json:"bytes_total"`
	AvgPayloadLen float64 `json:"avg_payload_len"`
	StdDevLen     float64 `json:"stddev_len"`
	DurationSec   float64 `json:"duration_sec"`
	Confidence    int     `json:"confidence"`
	FirstPacketID int64   `json:"first_packet_id"`
	Protocol      string  `json:"protocol"`
}

// Bruteforce Detection

type BruteforceAnalysis struct {
	TotalSuspicious   int                      `json:"total_suspicious"`
	PortScanHits      []PortScanCandidate      `json:"port_scan_hits"`
	DirBruteforceHits []DirBruteforceCandidate `json:"dir_bruteforce_hits"`
	Notes             []string                 `json:"notes"`
}

type PortScanCandidate struct {
	SourceIP       string  `json:"source_ip"`
	TargetIP       string  `json:"target_ip"`
	UniquePortsHit int     `json:"unique_ports_hit"`
	SynCount       int     `json:"syn_count"`
	RstCount       int     `json:"rst_count"`
	OpenPorts      []int   `json:"open_ports"`
	DurationSec    float64 `json:"duration_sec"`
	ScanType       string  `json:"scan_type"`
	Confidence     int     `json:"confidence"`
	FirstPacketID  int64   `json:"first_packet_id"`
}

type DirBruteforceCandidate struct {
	SourceIP       string   `json:"source_ip"`
	TargetHost     string   `json:"target_host"`
	TotalRequests  int      `json:"total_requests"`
	Status404Count int      `json:"status_404_count"`
	Status403Count int      `json:"status_403_count"`
	Status200Count int      `json:"status_200_count"`
	UniquePaths    int      `json:"unique_paths"`
	RequestsPerSec float64  `json:"requests_per_sec"`
	SamplePaths    []string `json:"sample_paths"`
	Confidence     int      `json:"confidence"`
	FirstPacketID  int64    `json:"first_packet_id"`
}

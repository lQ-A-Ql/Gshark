package model

type TLSConfig struct {
	SSLKeyLogFile string `json:"ssl_key_log_file"`
	RSAPrivateKey string `json:"rsa_private_key"`
	TargetIPPort  string `json:"target_ip_port"`
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

type MCPConfig struct {
	Enabled bool `json:"enabled"`
}

type MCPStatus struct {
	Config          MCPConfig `json:"config"`
	Enabled         bool      `json:"enabled"`
	Endpoint        string    `json:"endpoint"`
	Transport       string    `json:"transport"`
	AuthRequired    bool      `json:"auth_required"`
	ReadOnly        bool      `json:"read_only"`
	RemoteSupported bool      `json:"remote_supported"`
	StdioSupported  bool      `json:"stdio_supported"`
	LastError       string    `json:"last_error,omitempty"`
}

type ToolRuntimeProbeOptions struct {
	Mode string
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

type TSharkToolStatus struct {
	Available               bool     `json:"available"`
	Path                    string   `json:"path"`
	Message                 string   `json:"message"`
	CustomPath              string   `json:"custom_path,omitempty"`
	UsingCustomPath         bool     `json:"using_custom_path,omitempty"`
	Version                 string   `json:"version,omitempty"`
	FieldProfile            string   `json:"field_profile,omitempty"`
	FieldCount              int      `json:"field_count,omitempty"`
	MissingRequiredFields   []string `json:"missing_required_fields,omitempty"`
	MissingOptionalFields   []string `json:"missing_optional_fields,omitempty"`
	CapabilityMessage       string   `json:"capability_message,omitempty"`
	CapabilityCheckDegraded bool     `json:"capability_check_degraded,omitempty"`
}

type FFmpegToolStatus struct {
	Available       bool   `json:"available"`
	Path            string `json:"path"`
	Message         string `json:"message"`
	CustomPath      string `json:"custom_path,omitempty"`
	UsingCustomPath bool   `json:"using_custom_path,omitempty"`
}

type ToolRuntimeSnapshot struct {
	Config       ToolRuntimeConfig  `json:"config"`
	TShark       TSharkToolStatus   `json:"tshark"`
	FFmpeg       FFmpegToolStatus   `json:"ffmpeg"`
	Speech       SpeechToTextStatus `json:"speech"`
	Yara         YaraToolStatus     `json:"yara"`
	ProbeMode    string             `json:"probe_mode,omitempty"`
	ProbeState   string             `json:"probe_state,omitempty"`
	ProbeTimings map[string]int64   `json:"probe_timings,omitempty"`
	ProbeErrors  map[string]string  `json:"probe_errors,omitempty"`
	Cached       bool               `json:"cached,omitempty"`
	UpdatedAt    string             `json:"updated_at,omitempty"`
}

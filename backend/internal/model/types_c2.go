package model

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
	Name        string  `json:"name"`
	Value       string  `json:"value"`
	Confidence  int     `json:"confidence,omitempty"`
	Summary     string  `json:"summary"`
	SleepTimeMs int     `json:"sleep_time_ms,omitempty"`
	JitterPct   float64 `json:"jitter_pct,omitempty"`
}

type C2ScoreFactor struct {
	Name      string `json:"name"`
	Weight    int    `json:"weight"`
	Direction string `json:"direction"`
	Summary   string `json:"summary,omitempty"`
}

type C2HTTPEndpointAggregate struct {
	Host                 string          `json:"host"`
	URI                  string          `json:"uri"`
	Channel              string          `json:"channel,omitempty"`
	Total                int             `json:"total"`
	GetCount             int             `json:"get_count"`
	PostCount            int             `json:"post_count"`
	Methods              []TrafficBucket `json:"methods"`
	FirstTime            string          `json:"first_time,omitempty"`
	LastTime             string          `json:"last_time,omitempty"`
	AvgInterval          string          `json:"avg_interval,omitempty"`
	Jitter               string          `json:"jitter,omitempty"`
	Intervals            []float64       `json:"intervals,omitempty"`
	Streams              []int64         `json:"streams,omitempty"`
	Packets              []int64         `json:"packets,omitempty"`
	RepresentativePacket int64           `json:"representative_packet,omitempty"`
	Confidence           int             `json:"confidence,omitempty"`
	SignalTags           []string        `json:"signal_tags,omitempty"`
	ScoreFactors         []C2ScoreFactor `json:"score_factors,omitempty"`
	Summary              string          `json:"summary"`
}

type C2DNSAggregate struct {
	QName          string          `json:"qname"`
	Total          int             `json:"total"`
	MaxLabelLength int             `json:"max_label_length"`
	QueryTypes     []TrafficBucket `json:"query_types"`
	TxtCount       int             `json:"txt_count"`
	NullCount      int             `json:"null_count"`
	CnameCount     int             `json:"cname_count"`
	RequestCount   int             `json:"request_count"`
	ResponseCount  int             `json:"response_count"`
	FirstTime      string          `json:"first_time,omitempty"`
	LastTime       string          `json:"last_time,omitempty"`
	AvgInterval    string          `json:"avg_interval,omitempty"`
	Jitter         string          `json:"jitter,omitempty"`
	Intervals      []float64       `json:"intervals,omitempty"`
	Packets        []int64         `json:"packets,omitempty"`
	Confidence     int             `json:"confidence,omitempty"`
	Summary        string          `json:"summary"`
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
	Intervals       []float64       `json:"intervals,omitempty"`
	HasWebSocket    bool            `json:"has_websocket"`
	WSParams        string          `json:"ws_params,omitempty"`
	ListenerHints   []TrafficBucket `json:"listener_hints,omitempty"`
	FirstTime       string          `json:"first_time,omitempty"`
	LastTime        string          `json:"last_time,omitempty"`
	Packets         []int64         `json:"packets,omitempty"`
	Confidence      int             `json:"confidence,omitempty"`
	Summary         string          `json:"summary"`
}

// MalleableProfileMatch describes a positive match against a known C2 malleable profile.
type MalleableProfileMatch struct {
	ProfileName string   `json:"profile_name"`
	Family      string   `json:"family"`
	Confidence  int      `json:"confidence"`
	MatchReason string   `json:"match_reason"`
	MatchedOn   []string `json:"matched_on"`
}

type C2FamilyAnalysis struct {
	CandidateCount        int                       `json:"candidate_count"`
	MatchedRuleCount      int                       `json:"matched_rule_count"`
	Channels              []TrafficBucket           `json:"channels"`
	Indicators            []TrafficBucket           `json:"indicators"`
	Conversations         []AnalysisConversation    `json:"conversations"`
	BeaconPatterns        []C2BeaconPattern         `json:"beacon_patterns,omitempty"`
	HostURIAggregates     []C2HTTPEndpointAggregate `json:"host_uri_aggregates,omitempty"`
	DNSAggregates         []C2DNSAggregate          `json:"dns_aggregates,omitempty"`
	StreamAggregates      []C2StreamAggregate       `json:"stream_aggregates,omitempty"`
	Candidates            []C2IndicatorRecord       `json:"candidates"`
	Notes                 []string                  `json:"notes"`
	RelatedActors         []TrafficBucket           `json:"related_actors,omitempty"`
	DeliveryChains        []TrafficBucket           `json:"delivery_chains,omitempty"`
	MalleableProfileMatch *MalleableProfileMatch    `json:"malleable_profile_match,omitempty"`
	Report                InvestigationReport       `json:"report,omitempty"`
}

type C2SampleAnalysis struct {
	TotalMatchedPackets int                    `json:"total_matched_packets"`
	Families            []TrafficBucket        `json:"families"`
	Conversations       []AnalysisConversation `json:"conversations"`
	CS                  C2FamilyAnalysis       `json:"cs"`
	VShell              C2FamilyAnalysis       `json:"vshell"`
	Notes               []string               `json:"notes"`
}

type C2DecryptScope struct {
	PacketIDs     []int64 `json:"packet_ids,omitempty"`
	StreamIDs     []int64 `json:"stream_ids,omitempty"`
	UseCandidates bool    `json:"use_candidates,omitempty"`
	UseAggregates bool    `json:"use_aggregates,omitempty"`
}

type C2VShellDecryptOptions struct {
	VKey string `json:"vkey"`
	Salt string `json:"salt"`
	Mode string `json:"mode,omitempty"`
}

type C2CSDecryptOptions struct {
	KeyMode       string `json:"key_mode"`
	AESKey        string `json:"aes_key,omitempty"`
	HMACKey       string `json:"hmac_key,omitempty"`
	AESRand       string `json:"aes_rand,omitempty"`
	RSAPrivateKey string `json:"rsa_private_key,omitempty"`
	TransformMode string `json:"transform_mode,omitempty"`
}

type C2DecryptRequest struct {
	Family string                 `json:"family"`
	Scope  C2DecryptScope         `json:"scope,omitempty"`
	VShell C2VShellDecryptOptions `json:"vshell,omitempty"`
	CS     C2CSDecryptOptions     `json:"cs,omitempty"`
}

type C2DecryptedRecord struct {
	PacketID         int64  `json:"packet_id,omitempty"`
	StreamID         int64  `json:"stream_id,omitempty"`
	Time             string `json:"time,omitempty"`
	Direction        string `json:"direction,omitempty"`
	Algorithm        string `json:"algorithm,omitempty"`
	KeyStatus        string `json:"key_status,omitempty"`
	Confidence       int    `json:"confidence"`
	PlaintextPreview string `json:"plaintext_preview,omitempty"`
	// Parsed is family-specific decrypted metadata; stable fields stay beside it.
	Parsed          map[string]any `json:"parsed,omitempty"`
	RawLength       int            `json:"raw_length,omitempty"`
	DecryptedLength int            `json:"decrypted_length,omitempty"`
	Tags            []string       `json:"tags,omitempty"`
	Error           string         `json:"error,omitempty"`
}

type C2DecryptResult struct {
	Family          string              `json:"family"`
	Status          string              `json:"status"`
	TotalCandidates int                 `json:"total_candidates"`
	DecryptedCount  int                 `json:"decrypted_count"`
	FailedCount     int                 `json:"failed_count"`
	Records         []C2DecryptedRecord `json:"records"`
	Notes           []string            `json:"notes"`
}

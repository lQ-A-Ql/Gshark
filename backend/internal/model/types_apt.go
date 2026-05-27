package model

type APTScoreFactor struct {
	Name         string `json:"name"`
	Weight       int    `json:"weight"`
	Direction    string `json:"direction"`
	SourceModule string `json:"source_module,omitempty"`
	Summary      string `json:"summary,omitempty"`
}

type APTEvidenceRecord struct {
	PacketID            int64            `json:"packet_id"`
	StreamID            int64            `json:"stream_id,omitempty"`
	Time                string           `json:"time,omitempty"`
	ActorID             string           `json:"actor_id,omitempty"`
	ActorName           string           `json:"actor_name,omitempty"`
	SourceModule        string           `json:"source_module,omitempty"`
	Family              string           `json:"family,omitempty"`
	EvidenceType        string           `json:"evidence_type,omitempty"`
	EvidenceValue       string           `json:"evidence_value,omitempty"`
	Confidence          int              `json:"confidence,omitempty"`
	Source              string           `json:"source,omitempty"`
	Destination         string           `json:"destination,omitempty"`
	Host                string           `json:"host,omitempty"`
	URI                 string           `json:"uri,omitempty"`
	SampleFamily        string           `json:"sample_family,omitempty"`
	CampaignStage       string           `json:"campaign_stage,omitempty"`
	TransportTraits     []string         `json:"transport_traits,omitempty"`
	InfrastructureHints []string         `json:"infrastructure_hints,omitempty"`
	TTPTags             []string         `json:"ttp_tags,omitempty"`
	Tags                []string         `json:"tags,omitempty"`
	ScoreFactors        []APTScoreFactor `json:"score_factors,omitempty"`
	Summary             string           `json:"summary"`
	Evidence            string           `json:"evidence,omitempty"`
}

type APTActorProfile struct {
	ID                  string           `json:"id"`
	Name                string           `json:"name"`
	Aliases             []string         `json:"aliases,omitempty"`
	Summary             string           `json:"summary"`
	Confidence          int              `json:"confidence,omitempty"`
	EvidenceCount       int              `json:"evidence_count"`
	SampleFamilies      []TrafficBucket  `json:"sample_families"`
	CampaignStages      []TrafficBucket  `json:"campaign_stages"`
	TransportTraits     []TrafficBucket  `json:"transport_traits"`
	InfrastructureHints []TrafficBucket  `json:"infrastructure_hints"`
	RelatedC2Families   []TrafficBucket  `json:"related_c2_families"`
	TTPTags             []TrafficBucket  `json:"ttp_tags"`
	ScoreFactors        []APTScoreFactor `json:"score_factors,omitempty"`
	Notes               []string         `json:"notes"`
}

type APTAnalysis struct {
	TotalEvidence       int                 `json:"total_evidence"`
	Actors              []TrafficBucket     `json:"actors"`
	SampleFamilies      []TrafficBucket     `json:"sample_families"`
	CampaignStages      []TrafficBucket     `json:"campaign_stages"`
	TransportTraits     []TrafficBucket     `json:"transport_traits"`
	InfrastructureHints []TrafficBucket     `json:"infrastructure_hints"`
	RelatedC2Families   []TrafficBucket     `json:"related_c2_families"`
	Profiles            []APTActorProfile   `json:"profiles"`
	Evidence            []APTEvidenceRecord `json:"evidence"`
	Notes               []string            `json:"notes"`
}

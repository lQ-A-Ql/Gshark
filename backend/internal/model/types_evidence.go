package model

type EvidenceRecord struct {
	ID           string            `json:"id"`
	Module       string            `json:"module"`
	SourceModule string            `json:"source_module,omitempty"`
	PacketID     int64             `json:"packet_id,omitempty"`
	StreamID     int64             `json:"stream_id,omitempty"`
	Family       string            `json:"family,omitempty"`
	ActorID      string            `json:"actor_id,omitempty"`
	ActorName    string            `json:"actor_name,omitempty"`
	SourceType   string            `json:"source_type"`
	Summary      string            `json:"summary"`
	Value        string            `json:"value,omitempty"`
	Confidence   int               `json:"confidence,omitempty"`
	Severity     string            `json:"severity"`
	Source       string            `json:"source,omitempty"`
	Destination  string            `json:"destination,omitempty"`
	Host         string            `json:"host,omitempty"`
	URI          string            `json:"uri,omitempty"`
	Tags         []string          `json:"tags,omitempty"`
	TechniqueIDs []string          `json:"technique_ids,omitempty"`
	Caveats      []string          `json:"caveats,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

type EvidenceResponse struct {
	Records []EvidenceRecord `json:"records"`
	Total   int              `json:"total"`
	Notes   []string         `json:"notes,omitempty"`
}

type EvidenceFilter struct {
	Modules []string `json:"modules,omitempty"`
}

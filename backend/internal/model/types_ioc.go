package model

import "time"

// IOCFeedType enumerates supported IOC feed import formats.
const (
	IOCFeedTypeSTIX = "stix"
	IOCFeedTypeCSV  = "csv"
	IOCFeedTypeJSON = "json"
)

// IOCType enumerates supported IOC indicator types.
const (
	IOCTypeIP         = "ip"
	IOCTypeDomain     = "domain"
	IOCTypeHashMD5    = "hash_md5"
	IOCTypeHashSHA1   = "hash_sha1"
	IOCTypeHashSHA256 = "hash_sha256"
	IOCTypeURL        = "url"
)

// IOCFeed represents a configured IOC (Indicators of Compromise) data source.
type IOCFeed struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Format      string    `json:"format"` // "stix", "csv", "json"
	URL         string    `json:"url,omitempty"`
	Enabled     bool      `json:"enabled"`
	UpdatedAt   time.Time `json:"updated_at"`
	EntryCount  int       `json:"entry_count"`
	Description string    `json:"description,omitempty"`
}

// IOCEntry represents a single indicator of compromise from a feed.
type IOCEntry struct {
	ID          string    `json:"id"`
	FeedID      string    `json:"feed_id"`
	Type        string    `json:"type"` // "ip", "domain", "hash_md5", "hash_sha1", "hash_sha256", "url"
	Value       string    `json:"value"`
	Severity    string    `json:"severity,omitempty"`   // "low", "medium", "high", "critical"
	Confidence  int       `json:"confidence,omitempty"` // 0-100
	Tags        []string  `json:"tags,omitempty"`
	Description string    `json:"description,omitempty"`
	FirstSeen   time.Time `json:"first_seen,omitempty"`
	LastSeen    time.Time `json:"last_seen,omitempty"`
	Source      string    `json:"source,omitempty"`
}

// IOCMatchResult describes a single IOC match against a packet.
type IOCMatchResult struct {
	PacketID    int64    `json:"packet_id"`
	IOCType     string   `json:"ioc_type"`
	IOCValue    string   `json:"ioc_value"`
	MatchField  string   `json:"match_field"`
	MatchValue  string   `json:"match_value"`
	FeedID      string   `json:"feed_id"`
	FeedName    string   `json:"feed_name,omitempty"`
	Severity    string   `json:"severity"`
	Confidence  int      `json:"confidence,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Description string   `json:"description,omitempty"`
}

// IOCMatchSummary aggregates IOC match results for a packet set.
type IOCMatchSummary struct {
	TotalPackets   int              `json:"total_packets"`
	MatchedPackets int              `json:"matched_packets"`
	TotalMatches   int              `json:"total_matches"`
	ByType         map[string]int   `json:"by_type"`
	BySeverity     map[string]int   `json:"by_severity"`
	ByFeed         map[string]int   `json:"by_feed"`
	Matches        []IOCMatchResult `json:"matches"`
}

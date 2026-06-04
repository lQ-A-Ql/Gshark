package engine

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/gshark/sentinel/backend/internal/model"
)

// ImportIOCData parses IOC data from a reader in the specified format and returns entries.
// Supported formats: "stix", "csv", "json".
func ImportIOCData(reader io.Reader, format string, feedID string) ([]model.IOCEntry, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case model.IOCFeedTypeSTIX:
		return ImportSTIX(reader, feedID)
	case model.IOCFeedTypeCSV:
		return ImportCSV(reader, feedID)
	case model.IOCFeedTypeJSON:
		return ImportJSON(reader, feedID)
	default:
		return nil, fmt.Errorf("unsupported IOC feed format: %q", format)
	}
}

// ─── STIX 2.0 Import ────────────────────────────────────────────────────────

// stixBundle is the top-level STIX 2.0 bundle structure.
type stixBundle struct {
	Type    string       `json:"type"`
	ID      string       `json:"id,omitempty"`
	Objects []stixObject `json:"objects"`
}

// stixObject represents a generic STIX 2.0 SDO/SRO.
type stixObject struct {
	Type               string            `json:"type"`
	ID                 string            `json:"id,omitempty"`
	Name               string            `json:"name,omitempty"`
	Description        string            `json:"description,omitempty"`
	Pattern            string            `json:"pattern,omitempty"`
	Labels             []string          `json:"labels,omitempty"`
	Confidence         int               `json:"confidence,omitempty"`
	ValidFrom          string            `json:"valid_from,omitempty"`
	Created            string            `json:"created,omitempty"`
	Modified           string            `json:"modified,omitempty"`
	ExternalReferences []stixExternalRef `json:"external_references,omitempty"`
}

type stixExternalRef struct {
	SourceName string `json:"source_name"`
	URL        string `json:"url,omitempty"`
	ExternalID string `json:"external_id,omitempty"`
}

// ImportSTIX parses a STIX 2.0 bundle and extracts IOC indicators.
// It maps STIX indicator patterns to IOCEntry types.
func ImportSTIX(reader io.Reader, feedID string) ([]model.IOCEntry, error) {
	var bundle stixBundle
	decoder := json.NewDecoder(reader)
	if err := decoder.Decode(&bundle); err != nil {
		return nil, fmt.Errorf("stix decode: %w", err)
	}

	var entries []model.IOCEntry
	for _, obj := range bundle.Objects {
		if obj.Type != "indicator" {
			continue
		}
		iocType, iocValue := parseSTIXPattern(obj.Pattern)
		if iocType == "" || iocValue == "" {
			continue
		}

		severity := severityFromLabels(obj.Labels)
		confidence := obj.Confidence
		if confidence == 0 {
			confidence = 70 // default for STIX indicators
		}

		var firstSeen time.Time
		if obj.ValidFrom != "" {
			firstSeen, _ = time.Parse(time.RFC3339, obj.ValidFrom)
		}
		if firstSeen.IsZero() && obj.Created != "" {
			firstSeen, _ = time.Parse(time.RFC3339, obj.Created)
		}

		entry := model.IOCEntry{
			ID:          obj.ID,
			FeedID:      feedID,
			Type:        iocType,
			Value:       iocValue,
			Severity:    severity,
			Confidence:  confidence,
			Tags:        obj.Labels,
			Description: obj.Name,
			FirstSeen:   firstSeen,
			Source:      "stix",
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// parseSTIXPattern extracts an IOC type and value from a STIX 2.0 pattern string.
// Supports patterns like:
//
//	[ipv4-addr:value = '1.2.3.4']
//	[domain-name:value = 'evil.com']
//	[file:hashes.'MD5' = 'abc123']
//	[url:value = 'http://evil.com/malware']
func parseSTIXPattern(pattern string) (iocType, iocValue string) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return "", ""
	}

	// Remove outer brackets.
	pattern = strings.TrimPrefix(pattern, "[")
	pattern = strings.TrimSuffix(pattern, "]")
	pattern = strings.TrimSpace(pattern)

	// Split on '=' to get key and value parts.
	parts := strings.SplitN(pattern, "=", 2)
	if len(parts) != 2 {
		return "", ""
	}
	key := strings.TrimSpace(parts[0])
	value := strings.TrimSpace(parts[1])
	value = strings.Trim(value, "'\" ")

	switch {
	case strings.HasPrefix(key, "ipv4-addr:value"):
		return model.IOCTypeIP, value
	case strings.HasPrefix(key, "ipv6-addr:value"):
		return model.IOCTypeIP, value
	case strings.HasPrefix(key, "domain-name:value"):
		return model.IOCTypeDomain, value
	case strings.HasPrefix(key, "url:value"):
		return model.IOCTypeURL, value
	case strings.Contains(key, "hashes") && strings.Contains(strings.ToUpper(key), "MD5"):
		return model.IOCTypeHashMD5, value
	case strings.Contains(key, "hashes") && strings.Contains(strings.ToUpper(key), "SHA-1"):
		return model.IOCTypeHashSHA1, value
	case strings.Contains(key, "hashes") && strings.Contains(strings.ToUpper(key), "SHA-256"):
		return model.IOCTypeHashSHA256, value
	case strings.HasPrefix(key, "file:hashes"):
		// Fallback: detect hash type by length.
		return classifyHashByLength(value)
	}
	return "", ""
}

// classifyHashByLength infers hash type from its hex string length.
func classifyHashByLength(value string) (iocType, iocValue string) {
	v := strings.TrimSpace(strings.ToLower(value))
	switch len(v) {
	case 32:
		return model.IOCTypeHashMD5, v
	case 40:
		return model.IOCTypeHashSHA1, v
	case 64:
		return model.IOCTypeHashSHA256, v
	}
	return "", ""
}

// severityFromLabels maps common STIX labels to severity levels.
func severityFromLabels(labels []string) string {
	for _, label := range labels {
		lower := strings.ToLower(label)
		switch {
		case strings.Contains(lower, "critical"):
			return "critical"
		case strings.Contains(lower, "high") || strings.Contains(lower, "malicious"):
			return "high"
		case strings.Contains(lower, "medium") || strings.Contains(lower, "suspicious"):
			return "medium"
		case strings.Contains(lower, "low") || strings.Contains(lower, "benign"):
			return "low"
		}
	}
	return "medium"
}

// ─── CSV Import ──────────────────────────────────────────────────────────────

// ImportCSV parses a CSV file with IOC entries.
// Expected columns: type, value, severity, confidence, tags, description, source
// Header row is optional; if the first row's first column is "type", it is skipped.
func ImportCSV(reader io.Reader, feedID string) ([]model.IOCEntry, error) {
	r := csv.NewReader(reader)
	r.TrimLeadingSpace = true

	var entries []model.IOCEntry
	lineNum := 0
	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("csv read line %d: %w", lineNum+1, err)
		}
		lineNum++

		// Skip header row.
		if lineNum == 1 && len(record) > 0 && strings.ToLower(strings.TrimSpace(record[0])) == "type" {
			continue
		}

		if len(record) < 2 {
			continue // need at least type and value
		}

		iocType := normalizeIOCType(strings.TrimSpace(record[0]))
		value := strings.TrimSpace(record[1])
		if iocType == "" || value == "" {
			continue
		}

		entry := model.IOCEntry{
			ID:     fmt.Sprintf("%s-csv-%d", feedID, lineNum),
			FeedID: feedID,
			Type:   iocType,
			Value:  value,
			Source: "csv",
		}

		if len(record) > 2 {
			entry.Severity = strings.TrimSpace(record[2])
		}
		if len(record) > 3 {
			fmt.Sscanf(strings.TrimSpace(record[3]), "%d", &entry.Confidence)
		}
		if len(record) > 4 {
			tags := strings.TrimSpace(record[4])
			if tags != "" {
				entry.Tags = strings.Split(tags, ";")
				for i := range entry.Tags {
					entry.Tags[i] = strings.TrimSpace(entry.Tags[i])
				}
			}
		}
		if len(record) > 5 {
			entry.Description = strings.TrimSpace(record[5])
		}
		if len(record) > 6 {
			entry.Source = strings.TrimSpace(record[6])
		}

		if entry.Severity == "" {
			entry.Severity = "medium"
		}

		entries = append(entries, entry)
	}
	return entries, nil
}

// ─── JSON Import ─────────────────────────────────────────────────────────────

// ImportJSON parses a JSON array of IOC entries.
// The JSON should be an array of objects with at least "type" and "value" fields.
func ImportJSON(reader io.Reader, feedID string) ([]model.IOCEntry, error) {
	var raw []json.RawMessage
	decoder := json.NewDecoder(reader)
	if err := decoder.Decode(&raw); err != nil {
		return nil, fmt.Errorf("json decode: %w", err)
	}

	var entries []model.IOCEntry
	for i, rawMsg := range raw {
		var entry model.IOCEntry
		if err := json.Unmarshal(rawMsg, &entry); err != nil {
			return nil, fmt.Errorf("json entry %d: %w", i, err)
		}
		entry.Type = normalizeIOCType(entry.Type)
		if entry.Type == "" || entry.Value == "" {
			continue
		}
		entry.FeedID = feedID
		if entry.ID == "" {
			entry.ID = fmt.Sprintf("%s-json-%d", feedID, i+1)
		}
		if entry.Severity == "" {
			entry.Severity = "medium"
		}
		if entry.Source == "" {
			entry.Source = "json"
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// normalizeIOCType maps common IOC type strings to the standard constants.
func normalizeIOCType(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "ip", "ipv4", "ipv6", "ip-address", "ipv4-addr", "ipv6-addr":
		return model.IOCTypeIP
	case "domain", "domain-name", "hostname":
		return model.IOCTypeDomain
	case "hash_md5", "md5":
		return model.IOCTypeHashMD5
	case "hash_sha1", "sha1", "sha-1":
		return model.IOCTypeHashSHA1
	case "hash_sha256", "sha256", "sha-256":
		return model.IOCTypeHashSHA256
	case "url", "uri":
		return model.IOCTypeURL
	}
	return ""
}

// ─── IOC Cache ───────────────────────────────────────────────────────────────

// IOCCache manages an IOCIndex with thread-safe updates.
type IOCCache struct {
	index *IOCIndex
}

// NewIOCCache creates a new IOC cache with an empty index.
func NewIOCCache() *IOCCache {
	return &IOCCache{
		index: NewIOCIndex(),
	}
}

// Index returns the current IOCIndex.
func (c *IOCCache) Index() *IOCIndex {
	return c.index
}

// Reload clears the current index and rebuilds it from the provided feed data.
func (c *IOCCache) Reload(feeds []model.IOCFeed, entries []model.IOCEntry) {
	c.index.Clear()
	for _, feed := range feeds {
		c.index.AddFeed(feed)
	}
	c.index.AddEntries(entries)
}

// AddFeed adds a feed to the current index.
func (c *IOCCache) AddFeed(feed model.IOCFeed) {
	c.index.AddFeed(feed)
}

// AddEntries adds entries to the current index.
func (c *IOCCache) AddEntries(entries []model.IOCEntry) {
	c.index.AddEntries(entries)
}

// RemoveFeed removes a feed and its entries from the index.
func (c *IOCCache) RemoveFeed(feedID string) {
	// Save non-removed feeds.
	remainingFeeds := make([]model.IOCFeed, 0, len(c.index.feeds))
	for id, feed := range c.index.feeds {
		if id != feedID {
			remainingFeeds = append(remainingFeeds, feed)
		}
	}
	// Save non-removed entries.
	var remainingEntries []model.IOCEntry
	for _, entry := range c.index.allEntries {
		if entry.FeedID != feedID {
			remainingEntries = append(remainingEntries, entry)
		}
	}
	// Rebuild index.
	c.index.Clear()
	for _, feed := range remainingFeeds {
		c.index.AddFeed(feed)
	}
	c.index.AddEntries(remainingEntries)
}

// Stats returns current cache statistics.
func (c *IOCCache) Stats() IOCCacheStats {
	return IOCCacheStats{
		FeedCount:   c.index.FeedCount(),
		EntryCount:  c.index.EntryCount(),
		IPCount:     len(c.index.ipSet),
		DomainCount: len(c.index.domainSet),
		HashCount:   len(c.index.hashMD5Set) + len(c.index.hashSHA1Set) + len(c.index.hashSHA256Set),
		URLCount:    len(c.index.urlSet),
	}
}

// IOCCacheStats describes the current state of the IOC cache.
type IOCCacheStats struct {
	FeedCount   int `json:"feed_count"`
	EntryCount  int `json:"entry_count"`
	IPCount     int `json:"ip_count"`
	DomainCount int `json:"domain_count"`
	HashCount   int `json:"hash_count"`
	URLCount    int `json:"url_count"`
}

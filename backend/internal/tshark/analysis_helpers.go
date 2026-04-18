package tshark

import (
	"bufio"
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/gshark/sentinel/backend/internal/model"
)

type conversationCount struct {
	Label    string
	Protocol string
	Count    int
}

type fieldScanOptions struct {
	DisplayFilter string
	Occurrence    string
	Aggregator    string
}

type fieldScanCacheKey struct {
	FilePath      string
	DisplayFilter string
	Occurrence    string
	Aggregator    string
}

type fieldScanCacheEntry struct {
	fields     []string
	fieldIndex map[string]int
	rows       [][]string
}

type fieldScanWarmPlan struct {
	fields []string
	opts   fieldScanOptions
}

var fieldScanCache = struct {
	mu      sync.RWMutex
	entries map[fieldScanCacheKey][]*fieldScanCacheEntry
}{
	entries: map[fieldScanCacheKey][]*fieldScanCacheEntry{},
}

func scanFieldRows(filePath string, fields []string, onRow func([]string)) error {
	return scanFieldRowsWithOptions(filePath, fields, fieldScanOptions{}, onRow)
}

func scanFieldRowsWithOptions(filePath string, fields []string, opts fieldScanOptions, onRow func([]string)) error {
	normalizedFields := normalizeFieldScanFields(fields)
	if len(normalizedFields) == 0 {
		return nil
	}
	normalizedOpts := normalizeFieldScanOptions(opts)
	cacheKey := buildFieldScanCacheKey(filePath, normalizedOpts)

	if entry, indices, ok := findFieldScanCacheEntry(cacheKey, normalizedFields); ok {
		replayCachedFieldRows(entry, indices, onRow)
		return nil
	}

	args := []string{
		"-n",
		"-r", cacheKey.FilePath,
	}
	if cacheKey.DisplayFilter != "" {
		args = append(args, "-Y", cacheKey.DisplayFilter)
	}
	args = append(args,
		"-T", "fields",
		"-E", "separator=\t",
		"-E", "occurrence="+cacheKey.Occurrence,
		"-E", "aggregator="+cacheKey.Aggregator,
		"-E", "quote=n",
	)
	for _, field := range normalizedFields {
		args = append(args, "-e", field)
	}

	cmd, err := Command(args...)
	if err != nil {
		return fmt.Errorf("resolve tshark: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("create stdout pipe: %w", err)
	}

	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start tshark: %w", err)
	}

	rows := make([][]string, 0, 1024)
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		row := normalizeFieldScanRow(strings.Split(line, "\t"), len(normalizedFields))
		rows = append(rows, append([]string(nil), row...))
		if onRow != nil {
			onRow(append([]string(nil), row...))
		}
	}

	if err := scanner.Err(); err != nil {
		_ = cmd.Wait()
		return fmt.Errorf("scan tshark output: %w", err)
	}

	if err := cmd.Wait(); err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail != "" {
			return fmt.Errorf("wait tshark: %w: %s", err, detail)
		}
		return fmt.Errorf("wait tshark: %w", err)
	}

	storeFieldScanCacheEntry(cacheKey, normalizedFields, rows)
	return nil
}

func runDirectFieldScan(args []string, width int, onRow func([]string)) error {
	if width <= 0 {
		return nil
	}

	cmd, err := Command(args...)
	if err != nil {
		return fmt.Errorf("resolve tshark: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("create stdout pipe: %w", err)
	}

	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start tshark: %w", err)
	}

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		row := normalizeFieldScanRow(strings.Split(line, "\t"), width)
		if onRow != nil {
			onRow(append([]string(nil), row...))
		}
	}

	if err := scanner.Err(); err != nil {
		_ = cmd.Wait()
		return fmt.Errorf("scan tshark output: %w", err)
	}

	if err := cmd.Wait(); err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail != "" {
			return fmt.Errorf("wait tshark: %w: %s", err, detail)
		}
		return fmt.Errorf("wait tshark: %w", err)
	}
	return nil
}

func WarmFieldScanCache(filePath string, fields []string, opts fieldScanOptions) error {
	return scanFieldRowsWithOptions(filePath, fields, opts, nil)
}

func WarmSpecializedFieldCache(filePath string) error {
	for _, plan := range specializedFieldWarmPlans() {
		if err := WarmFieldScanCache(filePath, plan.fields, plan.opts); err != nil {
			return err
		}
	}
	return nil
}

func ClearFieldScanCache(filePath string) {
	normalizedPath := strings.TrimSpace(filePath)
	fieldScanCache.mu.Lock()
	defer fieldScanCache.mu.Unlock()

	if normalizedPath == "" {
		fieldScanCache.entries = map[fieldScanCacheKey][]*fieldScanCacheEntry{}
		return
	}

	for key := range fieldScanCache.entries {
		if key.FilePath == normalizedPath {
			delete(fieldScanCache.entries, key)
		}
	}
}

func specializedFieldWarmPlans() []fieldScanWarmPlan {
	return []fieldScanWarmPlan{
		{
			fields: unionFieldScanFields(
				modbusAnalysisFields,
				s7CommDetailFields,
				dnp3DetailFields,
				cipDetailFields,
				profinetDetailFields,
				bacnetDetailFields,
				iec104DetailFields,
				opcuaDetailFields,
				vehicleAnalysisFields,
				canPayloadAnalysisFields,
				dbcDecodedMessageFields,
			),
			opts: fieldScanOptions{},
		},
		{
			fields: mediaControlFields,
			opts: fieldScanOptions{
				DisplayFilter: "rtsp || sdp",
				Occurrence:    "a",
				Aggregator:    "|",
			},
		},
		{
			fields: mediaRTPFields,
			opts: fieldScanOptions{
				DisplayFilter: "rtp",
			},
		},
	}
}

func normalizeFieldScanOptions(opts fieldScanOptions) fieldScanOptions {
	return fieldScanOptions{
		DisplayFilter: strings.TrimSpace(opts.DisplayFilter),
		Occurrence:    FirstNonEmpty(strings.TrimSpace(opts.Occurrence), "f"),
		Aggregator:    FirstNonEmpty(strings.TrimSpace(opts.Aggregator), ","),
	}
}

func buildFieldScanCacheKey(filePath string, opts fieldScanOptions) fieldScanCacheKey {
	return fieldScanCacheKey{
		FilePath:      strings.TrimSpace(filePath),
		DisplayFilter: opts.DisplayFilter,
		Occurrence:    opts.Occurrence,
		Aggregator:    opts.Aggregator,
	}
}

func normalizeFieldScanFields(fields []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(fields))
	for _, field := range fields {
		value := strings.TrimSpace(field)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func normalizeFieldScanRow(parts []string, width int) []string {
	if len(parts) == width {
		return parts
	}
	if len(parts) > width {
		return parts[:width]
	}
	out := make([]string, width)
	copy(out, parts)
	return out
}

func findFieldScanCacheEntry(key fieldScanCacheKey, fields []string) (*fieldScanCacheEntry, []int, bool) {
	fieldScanCache.mu.RLock()
	defer fieldScanCache.mu.RUnlock()

	entries := fieldScanCache.entries[key]
	if len(entries) == 0 {
		return nil, nil, false
	}

	var (
		bestEntry   *fieldScanCacheEntry
		bestIndices []int
		bestWidth   int
	)
	for _, entry := range entries {
		indices, ok := buildFieldProjection(entry.fieldIndex, fields)
		if !ok {
			continue
		}
		if bestEntry == nil || len(entry.fields) < bestWidth {
			bestEntry = entry
			bestIndices = indices
			bestWidth = len(entry.fields)
		}
	}
	if bestEntry == nil {
		return nil, nil, false
	}
	return bestEntry, bestIndices, true
}

func buildFieldProjection(fieldIndex map[string]int, fields []string) ([]int, bool) {
	indices := make([]int, 0, len(fields))
	for _, field := range fields {
		idx, ok := fieldIndex[field]
		if !ok {
			return nil, false
		}
		indices = append(indices, idx)
	}
	return indices, true
}

func replayCachedFieldRows(entry *fieldScanCacheEntry, indices []int, onRow func([]string)) {
	if onRow == nil {
		return
	}
	for _, row := range entry.rows {
		projected := make([]string, len(indices))
		for i, idx := range indices {
			if idx >= 0 && idx < len(row) {
				projected[i] = row[idx]
			}
		}
		onRow(projected)
	}
}

func storeFieldScanCacheEntry(key fieldScanCacheKey, fields []string, rows [][]string) {
	entry := &fieldScanCacheEntry{
		fields:     append([]string(nil), fields...),
		fieldIndex: make(map[string]int, len(fields)),
		rows:       rows,
	}
	for idx, field := range fields {
		entry.fieldIndex[field] = idx
	}

	fieldScanCache.mu.Lock()
	defer fieldScanCache.mu.Unlock()

	existing := fieldScanCache.entries[key]
	for _, item := range existing {
		if sameFieldScanFields(item.fields, fields) {
			item.rows = rows
			item.fieldIndex = entry.fieldIndex
			return
		}
	}
	fieldScanCache.entries[key] = append(existing, entry)
}

func sameFieldScanFields(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func unionFieldScanFields(groups ...[]string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, 256)
	for _, group := range groups {
		for _, field := range group {
			field = strings.TrimSpace(field)
			if field == "" {
				continue
			}
			if _, ok := seen[field]; ok {
				continue
			}
			seen[field] = struct{}{}
			out = append(out, field)
		}
	}
	return out
}

func sortConversationBuckets(input map[string]conversationCount) []model.AnalysisConversation {
	items := make([]model.AnalysisConversation, 0, len(input))
	for _, item := range input {
		items = append(items, model.AnalysisConversation{
			Label:    item.Label,
			Protocol: item.Protocol,
			Count:    item.Count,
		})
	}
	for i := 0; i < len(items); i++ {
		for j := i + 1; j < len(items); j++ {
			if items[j].Count > items[i].Count || (items[j].Count == items[i].Count && items[j].Label < items[i].Label) {
				items[i], items[j] = items[j], items[i]
			}
		}
	}
	return items
}

func formatHex(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(raw), "0x") {
		return strings.ToUpper(raw)
	}
	value := parseInt(raw)
	if value <= 0 {
		return raw
	}
	return fmt.Sprintf("0x%X", value)
}

func parseFlexibleInt(raw string) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	if value, err := strconv.Atoi(raw); err == nil {
		return value
	}
	if strings.HasPrefix(strings.ToLower(raw), "0x") {
		if value, err := strconv.ParseInt(raw, 0, 64); err == nil {
			return int(value)
		}
	}
	return 0
}

func splitHexBytes(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	replacer := strings.NewReplacer(":", " ", "-", " ", ",", " ", "\t", " ")
	raw = replacer.Replace(raw)
	parts := strings.Fields(raw)
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(strings.TrimPrefix(strings.ToUpper(part), "0X"))
		if part == "" {
			continue
		}
		if len(part) == 1 {
			part = "0" + part
		}
		out = append(out, part)
	}
	return out
}

func normalizeHexBytes(raw string) string {
	parts := splitHexBytes(raw)
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " ")
}

func previewHexBytes(raw string, limit int) string {
	parts := splitHexBytes(raw)
	if len(parts) == 0 {
		return ""
	}
	if limit > 0 && len(parts) > limit {
		return strings.Join(parts[:limit], " ") + " ..."
	}
	return strings.Join(parts, " ")
}

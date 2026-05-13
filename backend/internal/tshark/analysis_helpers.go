package tshark

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
)

// Field-scan subprocess execution.
//
// This file owns the narrow responsibility of turning a (filePath, fields,
// opts) request into the rows tshark emits, gated by the field-scan cache.
// It intentionally stays short; adjacent concerns live in focused siblings:
//
//   - field_scan_plan.go        — capability planning + PlannedFieldScan
//                                 wrapper for callers that own their argv.
//   - field_scan_normalize.go   — input trimming/dedupe/padding helpers.
//   - field_scan_degradation.go — human-readable missing-optional-field notes.
//   - field_scan_warm.go        — WarmFieldScanCache / WarmSpecializedFieldCache.
//   - field_scan_cache.go       — LRU-bounded cache storage and replay.
//   - cache_key.go              — deterministic SHA-256 cache key.
//   - analysis_utils.go         — protocol-agnostic utilities (hex, flex int,
//                                 conversation bucket sort).

// fieldScanOptions selects the tshark CLI knobs that influence scan output:
// a display filter, the -E occurrence mode, and the -E aggregator. Blank
// fields receive tshark-standard defaults via normalizeFieldScanOptions.
type fieldScanOptions struct {
	DisplayFilter string
	Occurrence    string
	Aggregator    string
}

// fieldScanCacheEntry is the payload stored under a cache key: the concrete
// ordered field list, a reverse index for projection lookups, and the raw
// rows. fieldIndex lets findFieldScanCacheEntry answer superset-projection
// queries in O(requested fields) time.
type fieldScanCacheEntry struct {
	fields     []string
	fieldIndex map[string]int
	rows       [][]string
}

func scanFieldRows(filePath string, fields []string, onRow func([]string)) error {
	return scanFieldRowsWithOptions(filePath, fields, fieldScanOptions{}, onRow)
}

// ScanFieldRowsWithDisplayFilter is the exported wrapper that applies a
// display filter to an otherwise-default field scan.
func ScanFieldRowsWithDisplayFilter(filePath string, fields []string, displayFilter string, onRow func([]string)) error {
	return scanFieldRowsWithOptions(filePath, fields, fieldScanOptions{DisplayFilter: displayFilter}, onRow)
}

// ScanFieldRows is the exported no-options field-scan entry point.
func ScanFieldRows(filePath string, fields []string, onRow func([]string)) error {
	return scanFieldRows(filePath, fields, onRow)
}

// scanFieldRowsWithOptions is the single cache-aware code path that every
// field-scan flow funnels through. It normalizes inputs, consults the
// capability plan and cache, and either replays cached rows or spawns tshark
// once and stores the result for future callers.
func scanFieldRowsWithOptions(filePath string, fields []string, opts fieldScanOptions, onRow func([]string)) error {
	normalizedFields := normalizeFieldScanFields(fields)
	if len(normalizedFields) == 0 {
		return nil
	}
	plan, err := planFieldScanByCapabilities(normalizedFields)
	if err != nil {
		return err
	}
	normalizedOpts := normalizeFieldScanOptions(opts)
	cacheParams := buildFieldScanCacheParams(filePath, normalizedOpts)
	key := cacheKey(cacheParams)

	if entry, indices, ok := findFieldScanCacheEntry(key, plan.requestedFields); ok {
		replayCachedFieldRows(entry, indices, onRow)
		return nil
	}
	if len(plan.tsharkFields) == 0 {
		return nil
	}

	args := []string{
		"-n",
		"-r", cacheParams.FilePath,
	}
	if cacheParams.DisplayFilter != "" {
		args = append(args, "-Y", cacheParams.DisplayFilter)
	}
	args = append(args,
		"-T", "fields",
		"-E", "separator=\t",
		"-E", "occurrence="+cacheParams.Occurrence,
		"-E", "aggregator="+cacheParams.Aggregator,
		"-E", "quote=n",
	)
	for _, field := range plan.tsharkFields {
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
		scannedRow := normalizeFieldScanRow(strings.Split(line, "\t"), len(plan.tsharkFields))
		row := projectCapabilityFieldScanRow(scannedRow, plan)
		rows = append(rows, row)
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

	storeFieldScanCacheEntry(key, cacheParams.FilePath, plan.requestedFields, rows)
	return nil
}

// runDirectFieldScan drives a custom tshark argv (no caching, no planning)
// and invokes onRow for every parsed line. width tells the scanner how many
// fields to expect per row. Callers that already built their own -e list
// (e.g. runner.go's packet-list pipeline) use this instead of the cache-
// aware entry point.
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

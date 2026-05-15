package tshark

import (
	"bytes"
	"context"
	"log"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

type Capabilities struct {
	Version                 string   `json:"version,omitempty"`
	FieldProfile            string   `json:"field_profile,omitempty"`
	FieldCount              int      `json:"field_count,omitempty"`
	MissingRequiredFields   []string `json:"missing_required_fields,omitempty"`
	MissingOptionalFields   []string `json:"missing_optional_fields,omitempty"`
	CapabilityMessage       string   `json:"capability_message,omitempty"`
	CapabilityCheckDegraded bool     `json:"capability_check_degraded,omitempty"`
}

// FieldProfile values classify the overall health of the tshark field
// registry relative to the fields this backend needs.
//
// Severity ordinal is Full < DisplayCompat < Compat < Incompatible < Unavailable.
// "compat" (optional protocol fields missing, e.g. modbus.func_code) is more
// severe than "display-compat" (summary column fields missing) because missing
// optional protocol fields disables entire analyses, whereas missing
// display-layer fields only loses cosmetic summary columns.
const (
	FieldProfileFull          = "full"
	FieldProfileDisplayCompat = "display-compat" // display-layer fields missing only
	FieldProfileCompat        = "compat"         // optional protocol fields missing
	FieldProfileIncompatible  = "incompatible"   // required protocol-layer fields missing
	FieldProfileUnavailable   = "unavailable"    // tshark binary missing
	FieldProfileDegraded      = "degraded"       // probe failed
)

// fieldProfileSeverity returns an ordinal ranking so that callers can compare
// two profiles. Higher values mean worse tshark health.
func fieldProfileSeverity(profile string) int {
	switch profile {
	case FieldProfileFull:
		return 0
	case FieldProfileDisplayCompat:
		return 1
	case FieldProfileCompat:
		return 2
	case FieldProfileIncompatible:
		return 3
	case FieldProfileUnavailable, FieldProfileDegraded:
		return 4
	default:
		return -1
	}
}

var (
	capabilityMu         sync.RWMutex
	capabilityCache      = map[string]Capabilities{}
	capabilityFieldCache = map[string]map[string]struct{}{}
)

// tsharkCapabilityLogMu/tsharkCapabilityLogSeen deduplicate missing-optional
// field warnings so a long session does not spam the log per-row or per-plan.
// The key is scope + sorted(missingOptional) so each unique degradation state
// is reported once per scope until ClearCapabilityCache is called.
var (
	tsharkCapabilityLogMu   sync.Mutex
	tsharkCapabilityLogSeen = map[string]struct{}{}
)

var requiredCapabilityFields = []string{
	"frame.number",
	"frame.time_epoch",
	"frame.protocols",
}

// displayLayerCapabilityFields are Wireshark summary-column fields that many
// features prefer but can fall back on manual reconstruction for. Their
// absence downgrades the profile to "display-compat" rather than the stricter
// "incompatible" — they are cosmetic, not protocol-layer data.
var displayLayerCapabilityFields = []string{
	"_ws.col.Protocol",
	"_ws.col.Info",
}

var optionalCapabilityFields = []string{
	"ip.src",
	"ip.dst",
	"tcp.stream",
	"udp.stream",
	"modbus.func_code",
	"can.id",
	"uds.sid",
	"usb.capdata",
	"usbms.scsi.opcode",
}

var capabilityFieldAliases = map[string][]string{
	"_ws.col.Protocol": {"_ws.col.protocol"},
	"_ws.col.Info":     {"_ws.col.info"},
}

func CurrentCapabilities(ctx context.Context, binary string) Capabilities {
	binary = strings.TrimSpace(binary)
	if binary == "" {
		return Capabilities{
			FieldProfile:            FieldProfileUnavailable,
			CapabilityMessage:       "tshark binary is unavailable",
			CapabilityCheckDegraded: true,
		}
	}

	version := probeTSharkVersion(ctx, binary)
	cacheKey := binary + "\x00" + version
	if cached, ok := getCapabilityCache(cacheKey); ok {
		return cached
	}

	fields, err := probeTSharkFields(ctx, binary)
	if err != nil {
		capabilities := Capabilities{
			Version:                 version,
			FieldProfile:            FieldProfileDegraded,
			CapabilityMessage:       err.Error(),
			CapabilityCheckDegraded: true,
		}
		storeCapabilityCache(cacheKey, capabilities, nil)
		return capabilities
	}

	capabilities := buildCapabilities(version, fields)
	logCapabilityMissingOptionalFields(capabilities)
	storeCapabilityCache(cacheKey, capabilities, fields)
	return capabilities
}

func CurrentFieldSet(ctx context.Context, binary string) (map[string]struct{}, Capabilities, bool) {
	capabilities := CurrentCapabilities(ctx, binary)
	cacheKey := strings.TrimSpace(binary) + "\x00" + capabilities.Version
	fields, ok := getCapabilityFieldCache(cacheKey)
	return fields, capabilities, ok
}

func ClearCapabilityCache() {
	capabilityMu.Lock()
	capabilityCache = map[string]Capabilities{}
	capabilityFieldCache = map[string]map[string]struct{}{}
	capabilityMu.Unlock()

	tsharkCapabilityLogMu.Lock()
	tsharkCapabilityLogSeen = map[string]struct{}{}
	tsharkCapabilityLogMu.Unlock()
}

func getCapabilityCache(key string) (Capabilities, bool) {
	capabilityMu.RLock()
	defer capabilityMu.RUnlock()
	capabilities, ok := capabilityCache[key]
	return capabilities, ok
}

func getCapabilityFieldCache(key string) (map[string]struct{}, bool) {
	capabilityMu.RLock()
	defer capabilityMu.RUnlock()
	fields, ok := capabilityFieldCache[key]
	if !ok {
		return nil, false
	}
	out := make(map[string]struct{}, len(fields))
	for field := range fields {
		out[field] = struct{}{}
	}
	return out, true
}

func storeCapabilityCache(key string, capabilities Capabilities, fields map[string]struct{}) {
	capabilityMu.Lock()
	defer capabilityMu.Unlock()
	capabilityCache[key] = capabilities
	if fields == nil {
		delete(capabilityFieldCache, key)
		return
	}
	copied := make(map[string]struct{}, len(fields))
	for field := range fields {
		copied[field] = struct{}{}
	}
	capabilityFieldCache[key] = copied
}

func probeTSharkVersion(ctx context.Context, binary string) string {
	out, err := runTSharkProbe(ctx, binary, "-v")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
	}
	return ""
}

func probeTSharkFields(ctx context.Context, binary string) (map[string]struct{}, error) {
	out, err := runTSharkProbe(ctx, binary, "-G", "fields")
	if err != nil {
		return nil, err
	}
	fields := map[string]struct{}{}
	for _, line := range strings.Split(out, "\n") {
		if field := parseFieldRegistryName(line); field != "" {
			fields[field] = struct{}{}
		}
	}
	return fields, nil
}

func runTSharkProbe(ctx context.Context, binary string, args ...string) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(probeCtx, binary, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail != "" {
			return "", errWithDetail(err, detail)
		}
		return "", err
	}
	return string(out), nil
}

func errWithDetail(err error, detail string) error {
	return &probeError{err: err, detail: detail}
}

type probeError struct {
	err    error
	detail string
}

func (e *probeError) Error() string {
	return e.err.Error() + ": " + e.detail
}

func parseFieldRegistryName(line string) string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return ""
	}
	parts := strings.Split(line, "\t")
	if len(parts) < 3 || parts[0] != "F" {
		return ""
	}
	return strings.TrimSpace(parts[2])
}

func buildCapabilities(version string, fields map[string]struct{}) Capabilities {
	missingRequired := missingFields(fields, requiredCapabilityFields)
	missingDisplay := missingFields(fields, displayLayerCapabilityFields)
	missingOptional := missingFields(fields, optionalCapabilityFields)

	profile := FieldProfileFull
	message := "ok"
	degraded := false

	switch {
	case len(missingRequired) > 0:
		profile = FieldProfileIncompatible
		message = "missing required tshark fields"
		degraded = true
	case len(missingOptional) > 0:
		profile = FieldProfileCompat
		message = "optional tshark fields are unavailable; some analyses will degrade"
	case len(missingDisplay) > 0:
		profile = FieldProfileDisplayCompat
		message = "display-layer tshark fields are unavailable; summary columns will be reconstructed"
	}

	// All missing display-layer fields also surface in MissingOptionalFields
	// for backward compatibility with existing callers that only check that
	// slice (e.g. appendTSharkFieldDegradationNote). Keep them separate in the
	// profile classification but merge for the API surface.
	mergedMissing := append([]string(nil), missingOptional...)
	mergedMissing = append(mergedMissing, missingDisplay...)
	sort.Strings(mergedMissing)

	return Capabilities{
		Version:                 version,
		FieldProfile:            profile,
		FieldCount:              len(fields),
		MissingRequiredFields:   missingRequired,
		MissingOptionalFields:   mergedMissing,
		CapabilityMessage:       message,
		CapabilityCheckDegraded: degraded,
	}
}

func missingFields(fields map[string]struct{}, names []string) []string {
	out := []string{}
	for _, name := range names {
		if _, ok := resolveCapabilityField(fields, name); !ok {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func resolveCapabilityField(fields map[string]struct{}, requested string) (string, bool) {
	if _, ok := fields[requested]; ok {
		return requested, true
	}
	for _, alias := range capabilityFieldAliases[requested] {
		if _, ok := fields[alias]; ok {
			return alias, true
		}
	}
	return "", false
}

// logTSharkMissingOptionalOnce emits a single log line for the given scope and
// the sorted set of missing optional fields, deduplicating by
// scope + sorted(missing). Subsequent calls with the same (scope, missing) set
// are suppressed until ClearCapabilityCache resets the dedup table.
func logTSharkMissingOptionalOnce(scope string, missing []string) {
	if len(missing) == 0 {
		return
	}
	sorted := append([]string(nil), missing...)
	sort.Strings(sorted)
	joined := strings.Join(sorted, ",")
	key := scope + "|" + joined

	tsharkCapabilityLogMu.Lock()
	defer tsharkCapabilityLogMu.Unlock()
	if _, ok := tsharkCapabilityLogSeen[key]; ok {
		return
	}
	tsharkCapabilityLogSeen[key] = struct{}{}
	log.Printf("tshark capability degraded: %s — optional fields missing: %s (tshark remains available)", scope, strings.Join(sorted, ", "))
}

// logCapabilityMissingOptionalFields emits a single log line naming every
// optional tshark field that is unavailable for the current capability probe.
// This is called once per fresh capability computation (before caching) so the
// log does not spam on cache hits. The deduplicated helper above is used so
// that repeated fresh probes with the same missing set stay quiet.
func logCapabilityMissingOptionalFields(capabilities Capabilities) {
	if len(capabilities.MissingRequiredFields) > 0 {
		// Required fields missing: a separate degraded path is already reported
		// via CapabilityMessage; skip optional-field logging to avoid noise.
		return
	}
	if len(capabilities.MissingOptionalFields) == 0 {
		return
	}
	version := strings.TrimSpace(capabilities.Version)
	if version == "" {
		version = "unknown"
	}
	scope := "capabilities-probe (profile=" + capabilities.FieldProfile + ", version=" + version + ")"
	logTSharkMissingOptionalOnce(scope, capabilities.MissingOptionalFields)
}

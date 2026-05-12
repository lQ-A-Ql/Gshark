package tshark

import (
	"bytes"
	"context"
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

var (
	capabilityMu         sync.RWMutex
	capabilityCache      = map[string]Capabilities{}
	capabilityFieldCache = map[string]map[string]struct{}{}
)

var requiredCapabilityFields = []string{
	"frame.number",
	"frame.time_epoch",
	"frame.protocols",
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
			FieldProfile:            "unavailable",
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
			FieldProfile:            "degraded",
			CapabilityMessage:       err.Error(),
			CapabilityCheckDegraded: true,
		}
		storeCapabilityCache(cacheKey, capabilities, nil)
		return capabilities
	}

	capabilities := buildCapabilities(version, fields)
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
	defer capabilityMu.Unlock()
	capabilityCache = map[string]Capabilities{}
	capabilityFieldCache = map[string]map[string]struct{}{}
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
	missingOptional := missingFields(fields, optionalCapabilityFields)
	profile := "full"
	message := "ok"
	degraded := false
	if len(missingRequired) > 0 {
		profile = "incompatible"
		message = "missing required tshark fields"
		degraded = true
	} else if len(missingOptional) > 0 {
		profile = "compat"
		message = "optional tshark fields are unavailable; some analyses will degrade"
	}
	return Capabilities{
		Version:                 version,
		FieldProfile:            profile,
		FieldCount:              len(fields),
		MissingRequiredFields:   missingRequired,
		MissingOptionalFields:   missingOptional,
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

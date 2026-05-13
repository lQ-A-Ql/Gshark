package tshark

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// Capability-aware field-scan planning.
//
// The planner bridges the gap between what a feature asks for and what the
// currently-installed tshark can deliver. It alias-resolves requested fields
// against the tshark capability registry, drops optional fields that the
// local tshark cannot emit, and fails hard when a required-floor field is
// missing. The output is a fieldScanCapabilityPlan that downstream scan
// code uses to:
//
//   - pass the alias-resolved subset as -e arguments to tshark,
//   - project tshark's raw rows back into the caller's requested layout,
//   - surface MissingOptionalFields to HTTP callers for UI-level notes.
//
// This file owns the planning contract and the exported PlannedFieldScan
// wrapper used by bespoke callers that build their own argv. The sibling
// analysis_helpers.go keeps the tshark-subprocess execution mechanics.

// fieldScanCapabilityPlan is the bridge between the caller's requested field
// list and the subset of fields the running tshark actually supports:
//   - requestedFields is what the caller asked for, in caller order.
//   - tsharkFields is what actually gets passed to tshark, already
//     alias-resolved and with missing optional fields removed.
//   - projection[i] maps requestedFields[i] to its column in tshark's output
//     (or -1 when that request was degraded to a blank column).
//   - missingOptional lists optional fields that tshark cannot resolve.
type fieldScanCapabilityPlan struct {
	requestedFields []string
	tsharkFields    []string
	projection      []int
	missingOptional []string
}

// PlannedFieldScan is the exported handoff type for callers that assemble
// their own tshark argument list (e.g. packet-list streaming). It bundles
// the final -e arguments with enough metadata for the caller to project raw
// rows back into the requested column order.
type PlannedFieldScan struct {
	Args             []string
	RequestedFields  []string
	TSharkFields     []string
	MissingOptional  []string
	CapabilityActive bool
	plan             fieldScanCapabilityPlan
}

// planFieldScanByCapabilities consults the current tshark capability set and
// returns a plan that drops unsupported optional fields while requiring the
// required-field floor to be met. If any required field is missing the
// function returns an error so the caller can surface a hard failure; if
// only optional fields are missing the plan records them in missingOptional
// and projection so downstream code can degrade gracefully.
func planFieldScanByCapabilities(fields []string) (fieldScanCapabilityPlan, error) {
	plan := fieldScanCapabilityPlan{
		requestedFields: append([]string(nil), fields...),
		tsharkFields:    append([]string(nil), fields...),
		projection:      make([]int, len(fields)),
	}
	for idx := range plan.projection {
		plan.projection[idx] = idx
	}

	binary, err := ResolveBinary()
	if err != nil {
		return plan, nil
	}
	fieldSet, capabilities, ok := CurrentFieldSet(context.Background(), binary)
	if !ok {
		return plan, nil
	}

	tsharkFields := make([]string, 0, len(fields))
	projection := make([]int, len(fields))
	missingRequired := []string{}
	missingOptional := []string{}
	for idx, field := range fields {
		if resolvedField, exists := resolveCapabilityField(fieldSet, field); exists {
			projection[idx] = len(tsharkFields)
			tsharkFields = append(tsharkFields, resolvedField)
			continue
		}
		projection[idx] = -1
		if isRequiredCapabilityField(field) {
			missingRequired = append(missingRequired, field)
			continue
		}
		missingOptional = append(missingOptional, field)
	}
	if len(missingRequired) > 0 {
		sort.Strings(missingRequired)
		version := strings.TrimSpace(capabilities.Version)
		if version == "" {
			version = "unknown"
		}
		return plan, fmt.Errorf("tshark field capability check failed: missing required fields %s (version: %s)", strings.Join(missingRequired, ", "), version)
	}

	plan.tsharkFields = tsharkFields
	plan.projection = projection
	plan.missingOptional = missingOptional
	if len(missingOptional) > 0 {
		logTSharkMissingOptionalOnce("field-scan-plan", missingOptional)
	}
	return plan, nil
}

// projectCapabilityFieldScanRow expands a tshark-width row back into the
// caller's requestedFields layout, blanking columns whose plan.projection is
// negative (unsupported optional fields).
func projectCapabilityFieldScanRow(row []string, plan fieldScanCapabilityPlan) []string {
	out := make([]string, len(plan.requestedFields))
	for idx, projected := range plan.projection {
		if projected >= 0 && projected < len(row) {
			out[idx] = row[projected]
		}
	}
	return out
}

// isRequiredCapabilityField reports whether field is one of the
// required-floor fields. Missing required fields cause a hard planning
// failure rather than silent degradation.
func isRequiredCapabilityField(field string) bool {
	for _, required := range requiredCapabilityFields {
		if field == required {
			return true
		}
	}
	return false
}

// appendPlannedFieldArgs normalises fields, runs them through the capability
// planner, and appends the resulting -e arguments to args. It returns both
// the extended arg slice and the plan so the caller can project rows back
// to the requested layout.
func appendPlannedFieldArgs(args []string, fields []string) ([]string, fieldScanCapabilityPlan, error) {
	normalizedFields := normalizeFieldScanFields(fields)
	plan, err := planFieldScanByCapabilities(normalizedFields)
	if err != nil {
		return nil, plan, err
	}
	for _, field := range plan.tsharkFields {
		args = append(args, "-e", field)
	}
	return args, plan, nil
}

// BuildPlannedFieldArgs composes a PlannedFieldScan value that captures the
// final tshark argv, the requested/realised field lists, any missing
// optional fields, and a flag indicating whether capability-driven
// degradation is in effect.
func BuildPlannedFieldArgs(baseArgs []string, fields []string) (PlannedFieldScan, error) {
	args, plan, err := appendPlannedFieldArgs(append([]string(nil), baseArgs...), fields)
	if err != nil {
		return PlannedFieldScan{}, err
	}
	return PlannedFieldScan{
		Args:             args,
		RequestedFields:  append([]string(nil), plan.requestedFields...),
		TSharkFields:     append([]string(nil), plan.tsharkFields...),
		MissingOptional:  append([]string(nil), plan.missingOptional...),
		CapabilityActive: !sameFieldScanFields(plan.requestedFields, plan.tsharkFields) || len(plan.missingOptional) > 0,
		plan:             plan,
	}, nil
}

// ProjectRow projects an arbitrary tshark-width row back into the
// PlannedFieldScan's requested-field layout. A zero-value PlannedFieldScan
// is a pass-through so callers can use it safely before BuildPlannedFieldArgs
// has produced a real plan.
func (scan PlannedFieldScan) ProjectRow(parts []string) []string {
	if len(scan.plan.requestedFields) == 0 {
		return append([]string(nil), parts...)
	}
	return projectCapabilityFieldScanRow(normalizeFieldScanRow(parts, len(scan.plan.tsharkFields)), scan.plan)
}

// runDirectFieldScanWithPlan is the plan-aware sibling of runDirectFieldScan:
// it runs tshark with the caller's args, then projects every raw row through
// plan before invoking onRow. Used by streaming callers that want planner-
// driven graceful degradation without the shared cache path.
func runDirectFieldScanWithPlan(args []string, plan fieldScanCapabilityPlan, onRow func([]string)) error {
	if len(plan.tsharkFields) == 0 {
		return nil
	}
	return runDirectFieldScan(args, len(plan.tsharkFields), func(parts []string) {
		row := projectCapabilityFieldScanRow(parts, plan)
		if onRow != nil {
			onRow(row)
		}
	})
}

package tshark

import (
	"sort"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// Feature: iterative-dev-governance, Property 11: Tshark optional-field degradation returns partial results
//
// Validates: Requirements 4.2
//
// For any random subset of optionalCapabilityFields included alongside the
// full requiredCapabilityFields set, buildCapabilities must return a partial
// (non-empty) Capabilities result rather than failing silently:
//
//  1. The returned Capabilities has FieldCount == len(fields) (non-zero
//     because required fields are always included), a non-empty
//     FieldProfile, and a non-empty CapabilityMessage.
//  2. If any optional field is excluded, MissingOptionalFields lists exactly
//     the excluded set (order-insensitive) and FieldProfile == "compat".
//  3. If every optional field is included, MissingOptionalFields is empty
//     and FieldProfile == "full".
//  4. MissingRequiredFields is always empty, since every required field is
//     included by construction.
//
// Display-layer fields are included in the always-present baseline so this
// property isolates optional protocol-field degradation from the separate
// display-layer degradation path added for P0-3.
//
// The per-field rapid.Bool draw produces shrunk counter-examples of the form
// include_ip.src=false, include_tcp.stream=true, …, which makes degradation
// bugs easy to diagnose.
func TestBuildCapabilities_OptionalFieldDegradation(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		fields := make(map[string]struct{},
			len(requiredCapabilityFields)+len(displayLayerCapabilityFields)+len(optionalCapabilityFields))
		for _, name := range requiredCapabilityFields {
			fields[name] = struct{}{}
		}
		for _, name := range displayLayerCapabilityFields {
			fields[name] = struct{}{}
		}

		excluded := map[string]struct{}{}
		for _, name := range optionalCapabilityFields {
			if rapid.Bool().Draw(t, "include_"+name) {
				fields[name] = struct{}{}
			} else {
				excluded[name] = struct{}{}
			}
		}

		version := rapid.String().Draw(t, "version")
		capabilities := buildCapabilities(version, fields)

		// (1) Non-zero FieldCount, non-empty profile + message.
		if capabilities.FieldCount != len(fields) {
			t.Fatalf("FieldCount=%d want %d", capabilities.FieldCount, len(fields))
		}
		if capabilities.FieldCount == 0 {
			t.Fatalf("FieldCount must be non-zero when required fields are always included")
		}
		if capabilities.FieldProfile == "" {
			t.Fatalf("FieldProfile must be non-empty, got empty string")
		}
		if capabilities.CapabilityMessage == "" {
			t.Fatalf("CapabilityMessage must be non-empty, got empty string")
		}

		// (4) Required fields were all included, so MissingRequiredFields
		// must be empty regardless of the optional subset chosen.
		if len(capabilities.MissingRequiredFields) != 0 {
			t.Fatalf("MissingRequiredFields must be empty when all required fields included, got %v",
				capabilities.MissingRequiredFields)
		}

		// Set equality between MissingOptionalFields and the excluded set.
		// Display-layer fields are always present in the baseline, so the
		// merged MissingOptionalFields equals exactly the excluded optional
		// protocol-field set.
		expected := make([]string, 0, len(excluded))
		for name := range excluded {
			expected = append(expected, name)
		}
		sort.Strings(expected)
		got := append([]string(nil), capabilities.MissingOptionalFields...)
		sort.Strings(got)
		if strings.Join(got, ",") != strings.Join(expected, ",") {
			t.Fatalf("MissingOptionalFields mismatch: got=%v expected=%v", got, expected)
		}

		if len(excluded) == 0 {
			// (3) All optional included → full profile, empty missing set.
			if capabilities.FieldProfile != FieldProfileFull {
				t.Fatalf("expected FieldProfile=%q when no optional fields missing, got %q",
					FieldProfileFull, capabilities.FieldProfile)
			}
			if len(capabilities.MissingOptionalFields) != 0 {
				t.Fatalf("expected empty MissingOptionalFields when all optional included, got %v",
					capabilities.MissingOptionalFields)
			}
		} else {
			// (2) Any optional excluded → compat profile, non-empty missing set.
			if capabilities.FieldProfile != FieldProfileCompat {
				t.Fatalf("expected FieldProfile=%q when optional fields missing, got %q",
					FieldProfileCompat, capabilities.FieldProfile)
			}
			if len(capabilities.MissingOptionalFields) == 0 {
				t.Fatalf("expected non-empty MissingOptionalFields when optional fields excluded, got empty")
			}
		}
	})
}

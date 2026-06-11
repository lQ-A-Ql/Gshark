package model

import "testing"

func TestRuleVersionString(t *testing.T) {
	tests := []struct {
		version RuleVersion
		want    string
	}{
		{version: RuleVersion{Major: 1, Minor: 2, Patch: 3}, want: "v1.2.3"},
		{version: RuleVersion{Major: 10, Minor: 20, Patch: 30, Tag: "beta.1"}, want: "v10.20.30-beta.1"},
		{version: RuleVersion{Major: -1, Minor: 0, Patch: 5}, want: "v-1.0.5"},
	}
	for _, tt := range tests {
		if got := tt.version.String(); got != tt.want {
			t.Fatalf("RuleVersion.String() = %q, want %q", got, tt.want)
		}
	}
}

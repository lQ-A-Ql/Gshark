package yararules

import (
	"os"
	"testing"
)

func TestDefaultRuleSourceMatchesRuleFile(t *testing.T) {
	onDisk, err := os.ReadFile("default.yar")
	if err != nil {
		t.Fatalf("ReadFile(default.yar) error = %v", err)
	}

	if DefaultRuleSource != string(onDisk) {
		t.Fatal("embedded YARA rule source is out of sync with default.yar")
	}
}

package transport

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	_ = os.Setenv("MEOW_TRAFFIC_ALLOW_UNSIGNED_MISC", "1")
	os.Exit(m.Run())
}

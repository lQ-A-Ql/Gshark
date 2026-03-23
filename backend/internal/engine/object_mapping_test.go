package engine

import (
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestNormalizeObjectLookupKey(t *testing.T) {
	got := normalizeObjectLookupKey(`uploads\\secret (2).txt?download=1`)
	if got != "secret.txt" {
		t.Fatalf("expected normalized key secret.txt, got %q", got)
	}
}

func TestBuildPacketIDByObjectName(t *testing.T) {
	packets := []model.Packet{
		{ID: 11, Info: "GET /upload/shell.php HTTP/1.1", Payload: "", Protocol: "HTTP"},
		{ID: 22, Info: "POST /upload HTTP/1.1", Payload: "content-disposition: form-data; name=\"f\"; filename=\"secret.txt\"", Protocol: "HTTP"},
	}

	idx := buildPacketIDByObjectName(packets)
	if idx["shell.php"] != 11 {
		t.Fatalf("expected shell.php -> 11, got %d", idx["shell.php"])
	}
	if idx["secret.txt"] != 22 {
		t.Fatalf("expected secret.txt -> 22, got %d", idx["secret.txt"])
	}
}

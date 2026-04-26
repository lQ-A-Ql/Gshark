package engine

import (
	"testing"
)

func TestBuildNTLMSessionMaterialDetectsWinRMAndDirection(t *testing.T) {
	item := buildNTLMSessionMaterial(ntlmSessionScanRow{
		frameNumber:         "42",
		timestamp:           "Apr 25",
		src:                 "10.0.0.10",
		dst:                 "10.0.0.20",
		srcPort:             "50123",
		dstPort:             "5985",
		displayProtocol:     "HTTP",
		info:                "WinRM POST",
		username:            "Administrator",
		domain:              "LAB",
		challenge:           "11223344",
		ntProofStr:          "aabbccdd",
		encryptedSessionKey: "ffeeddcc",
		authHeader:          "NTLM TlRMTVNTUAAD",
	})

	if item.Protocol != "WinRM" {
		t.Fatalf("Protocol = %q, want WinRM", item.Protocol)
	}
	if item.Direction != "client -> server" {
		t.Fatalf("Direction = %q, want client -> server", item.Direction)
	}
	if item.UserDisplay != `LAB\Administrator` {
		t.Fatalf("UserDisplay = %q, want LAB\\Administrator", item.UserDisplay)
	}
	if !item.Complete {
		t.Fatal("Complete = false, want true")
	}
}

func TestBuildNTLMSessionMaterialDetectsSMB3Completeness(t *testing.T) {
	item := buildNTLMSessionMaterial(ntlmSessionScanRow{
		frameNumber:         "88",
		src:                 "10.0.0.30",
		dst:                 "10.0.0.40",
		srcPort:             "445",
		dstPort:             "51234",
		sessionID:           "0x1122334455667788",
		username:            "user1",
		domain:              "LAB",
		ntProofStr:          "001122334455",
		encryptedSessionKey: "aabbccddeeff",
	})

	if item.Protocol != "SMB3" {
		t.Fatalf("Protocol = %q, want SMB3", item.Protocol)
	}
	if item.SessionID != "0x1122334455667788" {
		t.Fatalf("SessionID = %q", item.SessionID)
	}
	if !item.Complete {
		t.Fatal("Complete = false, want true")
	}
	if item.Transport == "" {
		t.Fatal("Transport should not be empty")
	}
}

func TestBuildNTLMSessionMaterialDetectsServerChallengeDirection(t *testing.T) {
	item := buildNTLMSessionMaterial(ntlmSessionScanRow{
		frameNumber:     "7",
		src:             "10.0.0.1",
		dst:             "10.0.0.2",
		wwwAuthenticate: "NTLM TlRMTVNTUAAC",
		challenge:       "deadbeef",
	})

	if item.Protocol != "NTLM" {
		t.Fatalf("Protocol = %q, want NTLM", item.Protocol)
	}
	if item.Direction != "server -> client" {
		t.Fatalf("Direction = %q, want server -> client", item.Direction)
	}
	if item.Complete {
		t.Fatal("Complete = true, want false")
	}
}

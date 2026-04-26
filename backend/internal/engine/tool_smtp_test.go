package engine

import (
	"context"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestBuildSMTPAnalysisFromPacketsReconstructsMessage(t *testing.T) {
	packets := []model.Packet{
		{ID: 1, Protocol: "SMTP", SourceIP: "10.0.0.10", DestIP: "10.0.0.20", SourcePort: 50123, DestPort: 25, Info: "EHLO mail.example", Payload: "EHLO mail.example\r\n", StreamID: 7},
		{ID: 2, Protocol: "SMTP", SourceIP: "10.0.0.20", DestIP: "10.0.0.10", SourcePort: 25, DestPort: 50123, Info: "250-smtp ready", Payload: "250-smtp ready\r\n250 AUTH LOGIN PLAIN\r\n", StreamID: 7},
		{ID: 3, Protocol: "SMTP", SourceIP: "10.0.0.10", DestIP: "10.0.0.20", SourcePort: 50123, DestPort: 25, Info: "AUTH LOGIN", Payload: "AUTH LOGIN\r\n", StreamID: 7},
		{ID: 4, Protocol: "SMTP", SourceIP: "10.0.0.20", DestIP: "10.0.0.10", SourcePort: 25, DestPort: 50123, Info: "334", Payload: "334 VXNlcm5hbWU6\r\n", StreamID: 7},
		{ID: 5, Protocol: "SMTP", SourceIP: "10.0.0.10", DestIP: "10.0.0.20", SourcePort: 50123, DestPort: 25, Info: "username", Payload: "YWxpY2U=\r\n", StreamID: 7},
		{ID: 6, Protocol: "SMTP", SourceIP: "10.0.0.20", DestIP: "10.0.0.10", SourcePort: 25, DestPort: 50123, Info: "334", Payload: "334 UGFzc3dvcmQ6\r\n", StreamID: 7},
		{ID: 7, Protocol: "SMTP", SourceIP: "10.0.0.10", DestIP: "10.0.0.20", SourcePort: 50123, DestPort: 25, Info: "password", Payload: "c2VjcmV0\r\n", StreamID: 7},
		{ID: 8, Protocol: "SMTP", SourceIP: "10.0.0.20", DestIP: "10.0.0.10", SourcePort: 25, DestPort: 50123, Info: "235", Payload: "235 Authentication successful\r\n", StreamID: 7},
		{ID: 9, Protocol: "SMTP", SourceIP: "10.0.0.10", DestIP: "10.0.0.20", SourcePort: 50123, DestPort: 25, Info: "MAIL FROM:<alice@example.test>", Payload: "MAIL FROM:<alice@example.test>\r\n", StreamID: 7},
		{ID: 10, Protocol: "SMTP", SourceIP: "10.0.0.10", DestIP: "10.0.0.20", SourcePort: 50123, DestPort: 25, Info: "RCPT TO:<bob@example.test>", Payload: "RCPT TO:<bob@example.test>\r\n", StreamID: 7},
		{ID: 11, Protocol: "SMTP", SourceIP: "10.0.0.10", DestIP: "10.0.0.20", SourcePort: 50123, DestPort: 25, Info: "DATA", Payload: "DATA\r\n", StreamID: 7},
		{ID: 12, Protocol: "SMTP", SourceIP: "10.0.0.20", DestIP: "10.0.0.10", SourcePort: 25, DestPort: 50123, Info: "354", Payload: "354 End data with <CR><LF>.<CR><LF>\r\n", StreamID: 7},
		{ID: 13, Protocol: "SMTP", SourceIP: "10.0.0.10", DestIP: "10.0.0.20", SourcePort: 50123, DestPort: 25, Info: "message body", Payload: "From: Alice <alice@example.test>\r\nTo: Bob <bob@example.test>\r\nSubject: Demo Mail\r\nContent-Type: multipart/mixed; boundary=\"b1\"\r\n\r\nhello world\r\nContent-Disposition: attachment; filename=\"flag.txt\"\r\n\r\n.\r\n", StreamID: 7},
	}

	analysis, err := buildSMTPAnalysisFromPackets(context.Background(), packets)
	if err != nil {
		t.Fatalf("buildSMTPAnalysisFromPackets returned error: %v", err)
	}
	if analysis.SessionCount != 1 {
		t.Fatalf("expected 1 smtp session, got %d", analysis.SessionCount)
	}
	if analysis.MessageCount != 1 {
		t.Fatalf("expected 1 smtp message, got %d", analysis.MessageCount)
	}
	session := analysis.Sessions[0]
	if session.AuthUsername != "alice" {
		t.Fatalf("expected auth username alice, got %+v", session)
	}
	if !session.AuthPasswordSeen {
		t.Fatalf("expected auth password to be detected")
	}
	if session.AttachmentHints != 1 {
		t.Fatalf("expected 1 attachment hint, got %+v", session)
	}
	if len(session.Messages) != 1 || session.Messages[0].Subject != "Demo Mail" {
		t.Fatalf("unexpected messages: %+v", session.Messages)
	}
	if len(session.Messages[0].AttachmentNames) != 1 || session.Messages[0].AttachmentNames[0] != "flag.txt" {
		t.Fatalf("expected flag.txt attachment, got %+v", session.Messages[0])
	}
}

func TestBuildSMTPAnalysisFromPacketsDetectsAuthPlain(t *testing.T) {
	packets := []model.Packet{
		{ID: 1, Protocol: "SMTP", SourceIP: "10.0.0.1", DestIP: "10.0.0.2", SourcePort: 51111, DestPort: 587, Info: "AUTH PLAIN", Payload: "AUTH PLAIN AGpvaG4Ac2VjcmV0\r\n", StreamID: 9},
	}
	analysis, err := buildSMTPAnalysisFromPackets(context.Background(), packets)
	if err != nil {
		t.Fatalf("buildSMTPAnalysisFromPackets returned error: %v", err)
	}
	if analysis.AuthCount != 1 {
		t.Fatalf("expected 1 auth session, got %+v", analysis)
	}
	if analysis.Sessions[0].AuthUsername != "john" {
		t.Fatalf("expected auth username john, got %+v", analysis.Sessions[0])
	}
	if !analysis.Sessions[0].AuthPasswordSeen {
		t.Fatalf("expected auth password seen")
	}
}

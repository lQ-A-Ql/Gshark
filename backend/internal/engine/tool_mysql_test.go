package engine

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestBuildMySQLAnalysisFromPacketsReconstructsLoginAndQueries(t *testing.T) {
	handshake := makeMySQLWirePacket(buildHandshakePayload("8.0.36", 77, "caching_sha2_password"), 0)
	login := makeMySQLWirePacket(buildLoginPayload("app", "inventory", "mysql_native_password"), 1)
	ok := makeMySQLWirePacket([]byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}, 2)
	querySelect := makeMySQLWirePacket(append([]byte{mysqlCommandQuery}, []byte("SELECT * FROM users LIMIT 1")...), 0)
	resultSet := makeMySQLWirePacket([]byte{0x01}, 1)
	queryDelete := makeMySQLWirePacket(append([]byte{mysqlCommandQuery}, []byte("DELETE FROM audit_logs WHERE id = 9")...), 0)
	errPayload := []byte{0xff, 0x48, 0x04}
	errPayload = append(errPayload, []byte("#42000You have an error in your SQL syntax")...)
	err := makeMySQLWirePacket(errPayload, 1)

	packets := []model.Packet{
		{ID: 1, Protocol: "TCP", DisplayProtocol: "MySQL", SourceIP: "10.0.0.20", SourcePort: 3306, DestIP: "10.0.0.10", DestPort: 51514, StreamID: 6, Timestamp: "00:00:01", Payload: fmt.Sprintf("%x", handshake)},
		{ID: 2, Protocol: "TCP", DisplayProtocol: "MySQL", SourceIP: "10.0.0.10", SourcePort: 51514, DestIP: "10.0.0.20", DestPort: 3306, StreamID: 6, Timestamp: "00:00:02", Payload: fmt.Sprintf("%x", login)},
		{ID: 3, Protocol: "TCP", DisplayProtocol: "MySQL", SourceIP: "10.0.0.20", SourcePort: 3306, DestIP: "10.0.0.10", DestPort: 51514, StreamID: 6, Timestamp: "00:00:03", Payload: fmt.Sprintf("%x", ok)},
		{ID: 4, Protocol: "TCP", DisplayProtocol: "MySQL", SourceIP: "10.0.0.10", SourcePort: 51514, DestIP: "10.0.0.20", DestPort: 3306, StreamID: 6, Timestamp: "00:00:04", Payload: fmt.Sprintf("%x", querySelect)},
		{ID: 5, Protocol: "TCP", DisplayProtocol: "MySQL", SourceIP: "10.0.0.20", SourcePort: 3306, DestIP: "10.0.0.10", DestPort: 51514, StreamID: 6, Timestamp: "00:00:05", Payload: fmt.Sprintf("%x", resultSet)},
		{ID: 6, Protocol: "TCP", DisplayProtocol: "MySQL", SourceIP: "10.0.0.10", SourcePort: 51514, DestIP: "10.0.0.20", DestPort: 3306, StreamID: 6, Timestamp: "00:00:06", Payload: fmt.Sprintf("%x", queryDelete)},
		{ID: 7, Protocol: "TCP", DisplayProtocol: "MySQL", SourceIP: "10.0.0.20", SourcePort: 3306, DestIP: "10.0.0.10", DestPort: 51514, StreamID: 6, Timestamp: "00:00:07", Payload: fmt.Sprintf("%x", err)},
	}

	analysis, err2 := buildMySQLAnalysisFromPackets(nil, packets)
	if err2 != nil {
		t.Fatalf("buildMySQLAnalysisFromPackets returned error: %v", err2)
	}
	if analysis.SessionCount != 1 {
		t.Fatalf("expected 1 session, got %d", analysis.SessionCount)
	}
	if analysis.LoginCount != 1 {
		t.Fatalf("expected 1 login, got %d", analysis.LoginCount)
	}
	if analysis.QueryCount != 2 {
		t.Fatalf("expected 2 queries, got %d", analysis.QueryCount)
	}
	if analysis.ErrorCount != 1 {
		t.Fatalf("expected 1 error, got %d", analysis.ErrorCount)
	}
	session := analysis.Sessions[0]
	if session.ServerVersion != "8.0.36" {
		t.Fatalf("unexpected server version: %q", session.ServerVersion)
	}
	if session.ConnectionID != 77 {
		t.Fatalf("unexpected connection id: %d", session.ConnectionID)
	}
	if session.Username != "app" {
		t.Fatalf("unexpected username: %q", session.Username)
	}
	if session.Database != "inventory" {
		t.Fatalf("unexpected database: %q", session.Database)
	}
	if !session.LoginSuccess {
		t.Fatalf("expected login success")
	}
	if len(session.Queries) != 2 {
		t.Fatalf("expected 2 query records, got %d", len(session.Queries))
	}
	if session.Queries[0].ResponseKind != "RESULTSET" {
		t.Fatalf("expected first query response RESULTSET, got %q", session.Queries[0].ResponseKind)
	}
	if session.Queries[1].ResponseKind != "ERR" {
		t.Fatalf("expected second query response ERR, got %q", session.Queries[1].ResponseKind)
	}
	if session.Queries[1].ResponseCode != 1096 {
		t.Fatalf("expected error code 1096, got %d", session.Queries[1].ResponseCode)
	}
}

func TestBuildMySQLAnalysisFromPacketsParsesInitDBCommand(t *testing.T) {
	initDB := makeMySQLWirePacket(append([]byte{mysqlCommandInitDB}, []byte("analytics")...), 0)
	ok := makeMySQLWirePacket([]byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}, 1)
	packets := []model.Packet{
		{ID: 10, Protocol: "TCP", DisplayProtocol: "MySQL", SourceIP: "10.0.0.11", SourcePort: 60000, DestIP: "10.0.0.30", DestPort: 3306, StreamID: 9, Timestamp: "00:00:10", Payload: fmt.Sprintf("%x", initDB)},
		{ID: 11, Protocol: "TCP", DisplayProtocol: "MySQL", SourceIP: "10.0.0.30", SourcePort: 3306, DestIP: "10.0.0.11", DestPort: 60000, StreamID: 9, Timestamp: "00:00:11", Payload: fmt.Sprintf("%x", ok)},
	}
	analysis, err := buildMySQLAnalysisFromPackets(nil, packets)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	session := analysis.Sessions[0]
	if session.Database != "analytics" {
		t.Fatalf("expected database analytics, got %q", session.Database)
	}
	if session.Queries[0].Command != "COM_INIT_DB" {
		t.Fatalf("expected COM_INIT_DB, got %q", session.Queries[0].Command)
	}
	if session.Queries[0].ResponseKind != "OK" {
		t.Fatalf("expected OK response, got %q", session.Queries[0].ResponseKind)
	}
}

func makeMySQLWirePacket(payload []byte, sequence byte) []byte {
	buf := bytes.NewBuffer(make([]byte, 0, len(payload)+4))
	length := len(payload)
	buf.WriteByte(byte(length & 0xff))
	buf.WriteByte(byte((length >> 8) & 0xff))
	buf.WriteByte(byte((length >> 16) & 0xff))
	buf.WriteByte(sequence)
	buf.Write(payload)
	return buf.Bytes()
}

func buildHandshakePayload(version string, connID uint32, plugin string) []byte {
	buf := bytes.NewBuffer(nil)
	buf.WriteByte(0x0a)
	buf.WriteString(version)
	buf.WriteByte(0x00)
	_ = binary.Write(buf, binary.LittleEndian, connID)
	buf.WriteString("12345678")
	buf.WriteByte(0x00)
	buf.Write([]byte{0xff, 0xff})
	buf.WriteByte(0x21)
	buf.Write([]byte{0x02, 0x00})
	buf.Write([]byte{0xff, 0xff})
	buf.WriteByte(byte(len(plugin) + 1))
	buf.Write(make([]byte, 10))
	buf.WriteString("abcdefghijkl")
	buf.WriteByte(0x00)
	buf.WriteString(plugin)
	buf.WriteByte(0x00)
	return buf.Bytes()
}

func buildLoginPayload(username, databaseName, plugin string) []byte {
	flags := uint32(mysqlClientProtocol41 | mysqlClientSecureConnection | mysqlClientPluginAuth | mysqlClientConnectWithDB)
	buf := bytes.NewBuffer(nil)
	_ = binary.Write(buf, binary.LittleEndian, flags)
	_ = binary.Write(buf, binary.LittleEndian, uint32(1024*1024))
	buf.WriteByte(0x21)
	buf.Write(make([]byte, 23))
	buf.WriteString(username)
	buf.WriteByte(0x00)
	authResp := bytes.Repeat([]byte{0x11}, 20)
	buf.WriteByte(byte(len(authResp)))
	buf.Write(authResp)
	buf.WriteString(databaseName)
	buf.WriteByte(0x00)
	buf.WriteString(plugin)
	buf.WriteByte(0x00)
	return buf.Bytes()
}

package engine

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/gshark/sentinel/backend/internal/model"
)

const (
	mysqlPortDefault = 3306
	mysqlPortX       = 33060

	mysqlCommandQuit        = 0x01
	mysqlCommandInitDB      = 0x02
	mysqlCommandQuery       = 0x03
	mysqlCommandStmtPrepare = 0x16

	mysqlClientConnectWithDB          = 0x00000008
	mysqlClientProtocol41             = 0x00000200
	mysqlClientSecureConnection       = 0x00008000
	mysqlClientPluginAuth             = 0x00080000
	mysqlClientConnectAttrs           = 0x00100000
	mysqlClientPluginAuthLenencClient = 0x00200000
)

type mysqlFrame struct {
	sequence int
	payload  []byte
}

type mysqlSessionScratch struct {
	session         model.MySQLSession
	pendingLogin    bool
	pendingQueryIdx []int
}

func (s *Service) MySQLAnalysis(ctx context.Context) (model.MySQLAnalysis, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if s.CurrentCapturePath() == "" {
		return model.MySQLAnalysis{}, fmt.Errorf("当前未加载抓包，请先导入 pcapng 文件")
	}
	if s.packetStore == nil {
		return model.MySQLAnalysis{}, fmt.Errorf("当前抓包尚未建立本地数据包索引")
	}
	packets, err := s.packetStore.All(nil)
	if err != nil {
		return model.MySQLAnalysis{}, err
	}
	return buildMySQLAnalysisFromPackets(ctx, packets)
}

func buildMySQLAnalysisFromPackets(ctx context.Context, packets []model.Packet) (model.MySQLAnalysis, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	sessions := make(map[int64]*mysqlSessionScratch)
	order := make([]int64, 0, 16)

	for _, packet := range packets {
		if err := ctx.Err(); err != nil {
			return model.MySQLAnalysis{}, err
		}
		if !isMySQLPacket(packet) || packet.StreamID < 0 {
			continue
		}
		scratch := sessions[packet.StreamID]
		if scratch == nil {
			scratch = &mysqlSessionScratch{session: initMySQLSession(packet)}
			sessions[packet.StreamID] = scratch
			order = append(order, packet.StreamID)
		}
		processMySQLPacket(scratch, packet)
	}

	analysis := model.MySQLAnalysis{Sessions: []model.MySQLSession{}, Notes: []string{}}
	for _, streamID := range order {
		scratch := sessions[streamID]
		scratch.session.CommandTypes = trimStringList(scratch.session.CommandTypes, 12)
		scratch.session.ServerEvents = trimMySQLServerEvents(scratch.session.ServerEvents, 120)
		scratch.session.Queries = trimMySQLQueries(scratch.session.Queries, 120)
		scratch.session.Notes = buildMySQLSessionNotes(scratch.session)
		analysis.SessionCount++
		if scratch.session.LoginPacketID > 0 {
			analysis.LoginCount++
		}
		analysis.QueryCount += scratch.session.QueryCount
		analysis.ErrorCount += scratch.session.ErrCount
		analysis.ResultsetCount += scratch.session.ResultsetCount
		analysis.Sessions = append(analysis.Sessions, scratch.session)
	}
	sort.SliceStable(analysis.Sessions, func(i, j int) bool {
		return analysis.Sessions[i].StreamID < analysis.Sessions[j].StreamID
	})
	analysis.Notes = buildMySQLAnalysisNotes(analysis)
	return analysis, nil
}

func initMySQLSession(packet model.Packet) model.MySQLSession {
	session := model.MySQLSession{StreamID: packet.StreamID}
	if packet.SourcePort == mysqlPortDefault || packet.SourcePort == mysqlPortX {
		session.Server = packet.SourceIP
		session.ServerPort = packet.SourcePort
		session.Client = packet.DestIP
		session.ClientPort = packet.DestPort
	} else {
		session.Client = packet.SourceIP
		session.ClientPort = packet.SourcePort
		session.Server = packet.DestIP
		session.ServerPort = packet.DestPort
	}
	return session
}

func processMySQLPacket(scratch *mysqlSessionScratch, packet model.Packet) {
	if scratch == nil {
		return
	}
	direction := detectMySQLDirection(packet, scratch.session)
	frames, ok := parseMySQLFrames(packet)
	if !ok || len(frames) == 0 {
		processMySQLFallbackText(scratch, packet, direction)
		return
	}
	for _, frame := range frames {
		if direction == "server" {
			processMySQLServerFrame(scratch, packet, frame)
		} else {
			processMySQLClientFrame(scratch, packet, frame)
		}
	}
}

func isMySQLPacket(packet model.Packet) bool {
	proto := strings.ToUpper(strings.TrimSpace(packet.Protocol + " " + packet.DisplayProtocol + " " + packet.Info))
	return packet.SourcePort == mysqlPortDefault || packet.DestPort == mysqlPortDefault || packet.SourcePort == mysqlPortX || packet.DestPort == mysqlPortX || strings.Contains(proto, "MYSQL")
}

func detectMySQLDirection(packet model.Packet, session model.MySQLSession) string {
	if packet.SourcePort == mysqlPortDefault || packet.SourcePort == mysqlPortX || packet.SourceIP == session.Server {
		return "server"
	}
	return "client"
}

func parseMySQLFrames(packet model.Packet) ([]mysqlFrame, bool) {
	decoded := decodeLooseHex(packet.Payload)
	if len(decoded) == 0 {
		decoded = []byte(packet.Payload)
	}
	if len(decoded) < 5 {
		return nil, false
	}
	frames := make([]mysqlFrame, 0, 2)
	for offset := 0; offset+4 <= len(decoded); {
		length := int(decoded[offset]) | int(decoded[offset+1])<<8 | int(decoded[offset+2])<<16
		if length <= 0 || offset+4+length > len(decoded) {
			return frames, len(frames) > 0
		}
		frame := mysqlFrame{
			sequence: int(decoded[offset+3]),
			payload:  append([]byte(nil), decoded[offset+4:offset+4+length]...),
		}
		frames = append(frames, frame)
		offset += 4 + length
		if offset == len(decoded) {
			return frames, true
		}
	}
	return frames, len(frames) > 0
}

func processMySQLClientFrame(scratch *mysqlSessionScratch, packet model.Packet, frame mysqlFrame) {
	body := frame.payload
	if len(body) == 0 {
		return
	}
	if frame.sequence == 1 && looksLikeMySQLHandshakeResponse(body) {
		user, databaseName, plugin := parseMySQLLoginResponse(body)
		if user != "" {
			scratch.session.Username = user
		}
		if databaseName != "" {
			scratch.session.Database = databaseName
		}
		if plugin != "" {
			scratch.session.AuthPlugin = plugin
		}
		scratch.session.LoginPacketID = packet.ID
		scratch.pendingLogin = true
		scratch.session.CommandTypes = appendUniqueString(scratch.session.CommandTypes, "LOGIN")
		return
	}

	command := body[0]
	commandLabel := mysqlCommandLabel(command)
	scratch.session.CommandTypes = appendUniqueString(scratch.session.CommandTypes, commandLabel)
	query := model.MySQLQueryRecord{
		PacketID: packet.ID,
		Time:     packet.Timestamp,
		Command:  commandLabel,
	}
	switch command {
	case mysqlCommandQuery, mysqlCommandStmtPrepare:
		query.SQL = mysqlPrintable(body[1:])
		query.ResponseSummary = truncatePreview(query.SQL, 220)
		scratch.session.QueryCount++
	case mysqlCommandInitDB:
		query.Database = mysqlPrintable(body[1:])
		query.ResponseSummary = truncatePreview(query.Database, 120)
		if query.Database != "" {
			scratch.session.Database = query.Database
		}
	default:
		query.ResponseSummary = truncatePreview(mysqlPrintable(body[1:]), 120)
	}
	scratch.session.Queries = append(scratch.session.Queries, query)
	if command == mysqlCommandQuery || command == mysqlCommandStmtPrepare || command == mysqlCommandInitDB {
		scratch.pendingQueryIdx = append(scratch.pendingQueryIdx, len(scratch.session.Queries)-1)
	}
}

func processMySQLServerFrame(scratch *mysqlSessionScratch, packet model.Packet, frame mysqlFrame) {
	body := frame.payload
	if len(body) == 0 {
		return
	}
	if frame.sequence == 0 && body[0] == 0x0a {
		version, connID, plugin := parseMySQLHandshake(body)
		if version != "" {
			scratch.session.ServerVersion = version
		}
		if connID > 0 {
			scratch.session.ConnectionID = connID
		}
		if plugin != "" && scratch.session.AuthPlugin == "" {
			scratch.session.AuthPlugin = plugin
		}
		scratch.session.ServerEvents = append(scratch.session.ServerEvents, model.MySQLServerEvent{
			PacketID: packet.ID,
			Time:     packet.Timestamp,
			Sequence: frame.sequence,
			Kind:     "HANDSHAKE",
			Summary:  truncatePreview(version, 120),
		})
		return
	}

	kind, code, summary := classifyMySQLServerPayload(body)
	event := model.MySQLServerEvent{
		PacketID: packet.ID,
		Time:     packet.Timestamp,
		Sequence: frame.sequence,
		Kind:     kind,
		Code:     code,
		Summary:  truncatePreview(summary, 220),
	}
	scratch.session.ServerEvents = append(scratch.session.ServerEvents, event)

	switch kind {
	case "OK":
		scratch.session.OKCount++
		if scratch.pendingLogin {
			scratch.session.LoginSuccess = true
			scratch.pendingLogin = false
			return
		}
		resolveMySQLPendingQuery(scratch, packet, kind, code, summary)
	case "ERR":
		scratch.session.ErrCount++
		if scratch.pendingLogin {
			scratch.session.LoginSuccess = false
			scratch.pendingLogin = false
			return
		}
		resolveMySQLPendingQuery(scratch, packet, kind, code, summary)
	case "RESULTSET":
		scratch.session.ResultsetCount++
		resolveMySQLPendingQuery(scratch, packet, kind, code, summary)
	}
}

func processMySQLFallbackText(scratch *mysqlSessionScratch, packet model.Packet, direction string) {
	text := strings.TrimSpace(packet.Payload)
	if text == "" {
		text = strings.TrimSpace(packet.Info)
	}
	if text == "" {
		return
	}
	if direction == "client" {
		upper := strings.ToUpper(text)
		if strings.Contains(upper, "SELECT ") || strings.Contains(upper, "INSERT ") || strings.Contains(upper, "UPDATE ") || strings.Contains(upper, "DELETE ") {
			scratch.session.QueryCount++
			scratch.session.CommandTypes = appendUniqueString(scratch.session.CommandTypes, "COM_QUERY")
			scratch.session.Queries = append(scratch.session.Queries, model.MySQLQueryRecord{
				PacketID:        packet.ID,
				Time:            packet.Timestamp,
				Command:         "COM_QUERY",
				SQL:             truncatePreview(text, 220),
				ResponseSummary: truncatePreview(text, 220),
			})
		}
	}
}

func looksLikeMySQLHandshakeResponse(body []byte) bool {
	if len(body) < 36 {
		return false
	}
	flags := binary.LittleEndian.Uint32(body[:4])
	if flags == 0 {
		return false
	}
	if body[32] == 0x00 {
		return false
	}
	return true
}

func parseMySQLHandshake(body []byte) (string, int64, string) {
	if len(body) < 6 || body[0] != 0x0a {
		return "", 0, ""
	}
	pos := bytes.IndexByte(body[1:], 0x00)
	if pos < 0 {
		return "", 0, ""
	}
	serverVersion := mysqlPrintable(body[1 : 1+pos])
	offset := 1 + pos + 1
	if offset+4 > len(body) {
		return serverVersion, 0, ""
	}
	connectionID := int64(binary.LittleEndian.Uint32(body[offset : offset+4]))
	plugin := ""
	if len(body) >= 5 {
		zero := bytes.LastIndexByte(body, 0x00)
		if zero > 0 {
			candidate := mysqlPrintable(body[zero+1:])
			if candidate != "" && strings.Contains(candidate, "_") {
				plugin = candidate
			}
		}
	}
	return serverVersion, connectionID, plugin
}

func parseMySQLLoginResponse(body []byte) (string, string, string) {
	if len(body) < 36 {
		return "", "", ""
	}
	flags := binary.LittleEndian.Uint32(body[:4])
	offset := 4
	if flags&mysqlClientProtocol41 != 0 {
		offset = 4 + 4 + 1 + 23
	} else {
		offset = 5
	}
	if offset >= len(body) {
		return "", "", ""
	}
	username, next := readNULString(body, offset)
	if next <= offset {
		return mysqlPrintable([]byte(username)), "", ""
	}
	offset = next
	switch {
	case flags&mysqlClientPluginAuthLenencClient != 0:
		_, n := readLengthEncodedInt(body[offset:])
		offset += n
		if offset < len(body) {
			length, n2 := readLengthEncodedInt(body[offset:])
			offset += n2 + int(length)
		}
	case flags&mysqlClientSecureConnection != 0:
		if offset < len(body) {
			length := int(body[offset])
			offset++
			offset += length
		}
	default:
		_, offset = readNULString(body, offset)
	}
	if offset > len(body) {
		offset = len(body)
	}
	databaseName := ""
	if flags&mysqlClientConnectWithDB != 0 && offset < len(body) {
		databaseName, offset = readNULString(body, offset)
	}
	plugin := ""
	if flags&mysqlClientPluginAuth != 0 && offset < len(body) {
		plugin, offset = readNULString(body, offset)
		_ = offset
	}
	return mysqlPrintable([]byte(username)), mysqlPrintable([]byte(databaseName)), mysqlPrintable([]byte(plugin))
}

func classifyMySQLServerPayload(body []byte) (kind string, code int, summary string) {
	if len(body) == 0 {
		return "UNKNOWN", 0, "empty payload"
	}
	switch body[0] {
	case 0x00:
		return "OK", 0, mysqlPrintable(body[1:])
	case 0xff:
		if len(body) >= 3 {
			code = int(binary.LittleEndian.Uint16(body[1:3]))
		}
		return "ERR", code, mysqlPrintable(body[3:])
	case 0xfe:
		if len(body) < 9 {
			return "EOF", 0, "EOF"
		}
	}
	if columns, ok := readLengthEncodedInt(body); ok > 0 && columns > 0 && columns < 512 {
		return "RESULTSET", int(columns), fmt.Sprintf("列数 %d", columns)
	}
	return "UNKNOWN", 0, mysqlPrintable(body)
}

func resolveMySQLPendingQuery(scratch *mysqlSessionScratch, packet model.Packet, kind string, code int, summary string) {
	for len(scratch.pendingQueryIdx) > 0 {
		idx := scratch.pendingQueryIdx[0]
		scratch.pendingQueryIdx = scratch.pendingQueryIdx[1:]
		if idx < 0 || idx >= len(scratch.session.Queries) {
			continue
		}
		if scratch.session.Queries[idx].ResponseKind != "" {
			continue
		}
		scratch.session.Queries[idx].ResponsePacketID = packet.ID
		scratch.session.Queries[idx].ResponseKind = kind
		scratch.session.Queries[idx].ResponseCode = code
		scratch.session.Queries[idx].ResponseSummary = truncatePreview(summary, 220)
		return
	}
}

func mysqlCommandLabel(cmd byte) string {
	switch cmd {
	case mysqlCommandQuit:
		return "COM_QUIT"
	case mysqlCommandInitDB:
		return "COM_INIT_DB"
	case mysqlCommandQuery:
		return "COM_QUERY"
	case mysqlCommandStmtPrepare:
		return "COM_STMT_PREPARE"
	default:
		return fmt.Sprintf("COM_0x%02x", cmd)
	}
}

func mysqlPrintable(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	builder := strings.Builder{}
	builder.Grow(len(raw))
	for len(raw) > 0 {
		r, size := utf8.DecodeRune(raw)
		if r == utf8.RuneError && size == 1 {
			b := raw[0]
			if b >= 32 && b <= 126 {
				builder.WriteByte(b)
			} else if b == '\t' || b == '\n' || b == '\r' {
				builder.WriteByte(b)
			}
			raw = raw[1:]
			continue
		}
		if r >= 32 || r == '\t' || r == '\n' || r == '\r' {
			builder.WriteRune(r)
		}
		raw = raw[size:]
	}
	return strings.TrimSpace(builder.String())
}

func readNULString(raw []byte, offset int) (string, int) {
	if offset >= len(raw) {
		return "", offset
	}
	end := bytes.IndexByte(raw[offset:], 0x00)
	if end < 0 {
		return string(raw[offset:]), len(raw)
	}
	return string(raw[offset : offset+end]), offset + end + 1
}

func readLengthEncodedInt(raw []byte) (uint64, int) {
	if len(raw) == 0 {
		return 0, 0
	}
	switch raw[0] {
	case 0xfb:
		return 0, 1
	case 0xfc:
		if len(raw) < 3 {
			return 0, 0
		}
		return uint64(binary.LittleEndian.Uint16(raw[1:3])), 3
	case 0xfd:
		if len(raw) < 4 {
			return 0, 0
		}
		return uint64(raw[1]) | uint64(raw[2])<<8 | uint64(raw[3])<<16, 4
	case 0xfe:
		if len(raw) < 9 {
			return 0, 0
		}
		return binary.LittleEndian.Uint64(raw[1:9]), 9
	default:
		return uint64(raw[0]), 1
	}
}

func trimMySQLQueries(items []model.MySQLQueryRecord, limit int) []model.MySQLQueryRecord {
	if limit <= 0 || len(items) <= limit {
		return items
	}
	return append([]model.MySQLQueryRecord(nil), items[:limit]...)
}

func trimMySQLServerEvents(items []model.MySQLServerEvent, limit int) []model.MySQLServerEvent {
	if limit <= 0 || len(items) <= limit {
		return items
	}
	return append([]model.MySQLServerEvent(nil), items[:limit]...)
}

func trimStringList(items []string, limit int) []string {
	if limit <= 0 || len(items) <= limit {
		return items
	}
	return append([]string(nil), items[:limit]...)
}

func buildMySQLSessionNotes(session model.MySQLSession) []string {
	notes := make([]string, 0, 4)
	if session.Username != "" {
		notes = append(notes, fmt.Sprintf("识别到用户名 %s", session.Username))
	}
	if session.Database != "" {
		notes = append(notes, fmt.Sprintf("默认数据库 %s", session.Database))
	}
	if session.ErrCount > 0 {
		notes = append(notes, fmt.Sprintf("该会话包含 %d 条 MySQL 错误响应", session.ErrCount))
	}
	if session.ResultsetCount > 0 {
		notes = append(notes, fmt.Sprintf("检测到 %d 次结果集返回", session.ResultsetCount))
	}
	return notes
}

func buildMySQLAnalysisNotes(analysis model.MySQLAnalysis) []string {
	notes := make([]string, 0, 4)
	if analysis.SessionCount == 0 {
		return []string{"当前抓包未识别到 MySQL 会话。"}
	}
	notes = append(notes, fmt.Sprintf("共识别 %d 条 MySQL 会话，其中 %d 条含登录材料。", analysis.SessionCount, analysis.LoginCount))
	if analysis.QueryCount > 0 {
		notes = append(notes, fmt.Sprintf("共提取 %d 条查询/初始化命令。", analysis.QueryCount))
	}
	if analysis.ErrorCount > 0 {
		notes = append(notes, fmt.Sprintf("检测到 %d 条 MySQL 错误响应，可重点关注失败登录、语法错误或权限拒绝。", analysis.ErrorCount))
	}
	if analysis.ResultsetCount > 0 {
		notes = append(notes, fmt.Sprintf("检测到 %d 次结果集回传。", analysis.ResultsetCount))
	}
	return notes
}

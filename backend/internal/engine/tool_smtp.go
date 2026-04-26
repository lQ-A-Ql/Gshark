package engine

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"mime"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

var (
	smtpFilenameRE = regexp.MustCompile(`(?i)filename\*?="?([^";\r\n]+)"?`)
	smtpBoundaryRE = regexp.MustCompile(`(?i)boundary="?([^";\r\n]+)"?`)
)

type smtpSessionScratch struct {
	session             model.SMTPSession
	expectAuthLoginUser bool
	expectAuthLoginPass bool
	collectingMessage   bool
	messageBuffer       strings.Builder
	messagePacketIDs    []int64
	currentMailFrom     string
	currentRcptTo       []string
}

func (s *Service) SMTPAnalysis(ctx context.Context) (model.SMTPAnalysis, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if s.CurrentCapturePath() == "" {
		return model.SMTPAnalysis{}, fmt.Errorf("当前未加载抓包，请先导入 pcapng 文件")
	}
	if s.packetStore == nil {
		return model.SMTPAnalysis{}, fmt.Errorf("当前抓包尚未建立本地数据包索引")
	}
	packets, err := s.packetStore.All(nil)
	if err != nil {
		return model.SMTPAnalysis{}, err
	}
	return buildSMTPAnalysisFromPackets(ctx, packets)
}

func buildSMTPAnalysisFromPackets(ctx context.Context, packets []model.Packet) (model.SMTPAnalysis, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	sessions := make(map[int64]*smtpSessionScratch)
	order := make([]int64, 0, 16)

	for _, packet := range packets {
		if err := ctx.Err(); err != nil {
			return model.SMTPAnalysis{}, err
		}
		if !isSMTPPacket(packet) {
			continue
		}
		streamID := packet.StreamID
		if streamID < 0 {
			continue
		}
		scratch := sessions[streamID]
		if scratch == nil {
			scratch = &smtpSessionScratch{
				session: model.SMTPSession{
					StreamID:   streamID,
					Client:     packet.SourceIP,
					Server:     packet.DestIP,
					ClientPort: packet.SourcePort,
					ServerPort: packet.DestPort,
				},
			}
			sessions[streamID] = scratch
			order = append(order, streamID)
		}
		processSMTPPacket(scratch, packet)
	}

	analysis := model.SMTPAnalysis{
		Sessions: []model.SMTPSession{},
		Notes:    []string{},
	}
	for _, streamID := range order {
		scratch := sessions[streamID]
		finalizePendingSMTPMessage(scratch)
		scratch.session.Commands = trimSMTPCommands(scratch.session.Commands, 80)
		sort.Strings(scratch.session.MailFrom)
		sort.Strings(scratch.session.RcptTo)
		sort.Strings(scratch.session.AuthMechanisms)
		sort.Strings(scratch.session.StatusHints)
		scratch.session.MessageCount = len(scratch.session.Messages)
		analysis.SessionCount++
		analysis.MessageCount += scratch.session.MessageCount
		if scratch.session.AuthUsername != "" || len(scratch.session.AuthMechanisms) > 0 {
			analysis.AuthCount++
		}
		analysis.AttachmentHintCount += scratch.session.AttachmentHints
		analysis.Sessions = append(analysis.Sessions, scratch.session)
	}

	sort.SliceStable(analysis.Sessions, func(i, j int) bool {
		return analysis.Sessions[i].StreamID < analysis.Sessions[j].StreamID
	})
	analysis.Notes = buildSMTPNotes(analysis)
	return analysis, nil
}

func processSMTPPacket(scratch *smtpSessionScratch, packet model.Packet) {
	if scratch == nil {
		return
	}
	text := decodeSMTPPayloadText(packet.Payload)
	if strings.TrimSpace(text) == "" {
		text = packet.Info
	}
	direction := detectSMTPDirection(packet)
	updateSMTPEndpoints(&scratch.session, packet, direction)

	if scratch.collectingMessage && direction == "client" {
		scratch.messagePacketIDs = appendUniqueInt64(scratch.messagePacketIDs, packet.ID, 256)
		scratch.messageBuffer.WriteString(normalizeSMTPChunk(text))
		if containsSMTPDataTerminator(scratch.messageBuffer.String()) {
			finalizePendingSMTPMessage(scratch)
		}
		return
	}

	lines := splitSMTPLines(text)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if direction == "server" {
			processSMTPServerLine(scratch, packet, line)
			continue
		}
		processSMTPClientLine(scratch, packet, line)
	}
}

func processSMTPServerLine(scratch *smtpSessionScratch, packet model.Packet, line string) {
	code := parseSMTPStatusCode(line)
	if code > 0 {
		scratch.session.StatusHints = appendUniqueString(scratch.session.StatusHints, smtpStatusHint(code))
		scratch.session.Commands = append(scratch.session.Commands, model.SMTPCommandRecord{
			PacketID:   packet.ID,
			Time:       packet.Timestamp,
			Direction:  "server",
			StatusCode: code,
			Summary:    truncatePreview(line, 200),
		})
	}
}

func processSMTPClientLine(scratch *smtpSessionScratch, packet model.Packet, line string) {
	if scratch.expectAuthLoginUser {
		user := decodeSMTPBase64Inline(line)
		if user != "" {
			scratch.session.AuthUsername = user
		}
		scratch.expectAuthLoginUser = false
		scratch.expectAuthLoginPass = true
		return
	}
	if scratch.expectAuthLoginPass {
		if decodeSMTPBase64Inline(line) != "" {
			scratch.session.AuthPasswordSeen = true
		}
		scratch.expectAuthLoginPass = false
		return
	}

	command, arg := parseSMTPCommand(line)
	if command == "" {
		return
	}
	scratch.session.CommandCount++
	scratch.session.Commands = append(scratch.session.Commands, model.SMTPCommandRecord{
		PacketID:  packet.ID,
		Time:      packet.Timestamp,
		Direction: "client",
		Command:   command,
		Argument:  truncatePreview(arg, 200),
		Summary:   truncatePreview(line, 220),
	})

	switch command {
	case "EHLO", "HELO":
		scratch.session.Helo = arg
		scratch.session.PossibleCleartext = true
	case "AUTH":
		scratch.session.PossibleCleartext = true
		handleSMTPAuthLine(scratch, arg)
	case "MAIL":
		if value := extractSMTPAddress(arg); value != "" {
			scratch.currentMailFrom = value
			scratch.session.MailFrom = appendUniqueString(scratch.session.MailFrom, value)
		}
	case "RCPT":
		if value := extractSMTPAddress(arg); value != "" {
			scratch.currentRcptTo = appendUniqueString(scratch.currentRcptTo, value)
			scratch.session.RcptTo = appendUniqueString(scratch.session.RcptTo, value)
		}
	case "DATA":
		scratch.collectingMessage = true
		scratch.messagePacketIDs = appendUniqueInt64(nil, packet.ID, 256)
		scratch.messageBuffer.Reset()
	case "STARTTLS":
		scratch.session.StatusHints = appendUniqueString(scratch.session.StatusHints, "STARTTLS")
	}
}

func handleSMTPAuthLine(scratch *smtpSessionScratch, arg string) {
	fields := strings.Fields(strings.TrimSpace(arg))
	if len(fields) == 0 {
		return
	}
	mech := strings.ToUpper(strings.TrimSpace(fields[0]))
	scratch.session.AuthMechanisms = appendUniqueString(scratch.session.AuthMechanisms, mech)
	switch mech {
	case "PLAIN":
		if len(fields) >= 2 {
			user, passwordSeen := decodeSMTPAuthPlain(fields[1])
			if user != "" {
				scratch.session.AuthUsername = user
			}
			if passwordSeen {
				scratch.session.AuthPasswordSeen = true
			}
		}
	case "LOGIN":
		if len(fields) >= 2 {
			user := decodeSMTPBase64Inline(fields[1])
			if user != "" {
				scratch.session.AuthUsername = user
				scratch.expectAuthLoginPass = true
				return
			}
		}
		scratch.expectAuthLoginUser = true
	}
}

func finalizePendingSMTPMessage(scratch *smtpSessionScratch) {
	if scratch == nil || !scratch.collectingMessage {
		return
	}
	scratch.collectingMessage = false
	raw := normalizeSMTPDataMessage(scratch.messageBuffer.String())
	scratch.messageBuffer.Reset()
	if strings.TrimSpace(raw) == "" {
		scratch.messagePacketIDs = nil
		scratch.currentMailFrom = ""
		scratch.currentRcptTo = nil
		return
	}
	message := parseSMTPMessage(raw)
	message.Sequence = len(scratch.session.Messages) + 1
	message.PacketIDs = append([]int64(nil), scratch.messagePacketIDs...)
	if message.MailFrom == "" {
		message.MailFrom = scratch.currentMailFrom
	}
	if len(message.RcptTo) == 0 {
		message.RcptTo = append([]string(nil), scratch.currentRcptTo...)
	}
	if len(message.AttachmentNames) > 0 {
		scratch.session.AttachmentHints += len(message.AttachmentNames)
	}
	scratch.session.Messages = append(scratch.session.Messages, message)
	scratch.messagePacketIDs = nil
	scratch.currentMailFrom = ""
	scratch.currentRcptTo = nil
}

func parseSMTPMessage(raw string) model.SMTPMessage {
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	headers := make(map[string]string)
	bodyIndex := 0
	for idx, line := range lines {
		if strings.TrimSpace(line) == "" {
			bodyIndex = idx + 1
			break
		}
		if name, value, ok := cutSMTPHeader(line); ok {
			headers[name] = value
		}
	}
	bodyPreview := truncatePreview(strings.Join(lines[bodyIndex:], "\n"), 320)
	contentType := headers["Content-Type"]
	boundary := ""
	if match := smtpBoundaryRE.FindStringSubmatch(contentType); len(match) == 2 {
		boundary = strings.TrimSpace(match[1])
	}
	attachmentNames := smtpAttachmentNames(raw)
	return model.SMTPMessage{
		MailFrom:        headers["Return-Path"],
		RcptTo:          splitSMTPAddressHeader(headers["To"]),
		Subject:         decodeSMTPHeader(headers["Subject"]),
		From:            decodeSMTPHeader(headers["From"]),
		To:              decodeSMTPHeader(headers["To"]),
		Date:            headers["Date"],
		ContentType:     contentType,
		Boundary:        boundary,
		AttachmentNames: attachmentNames,
		BodyPreview:     bodyPreview,
	}
}

func smtpAttachmentNames(raw string) []string {
	matches := smtpFilenameRE.FindAllStringSubmatch(raw, -1)
	out := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		name := strings.TrimSpace(match[1])
		name = strings.Trim(name, `"`)
		if name == "" {
			continue
		}
		out = appendUniqueString(out, name)
	}
	return out
}

func cutSMTPHeader(line string) (string, string, bool) {
	left, right, ok := strings.Cut(line, ":")
	if !ok {
		return "", "", false
	}
	return strings.TrimSpace(left), strings.TrimSpace(right), true
}

func splitSMTPAddressHeader(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return out
}

func decodeSMTPHeader(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	decoder := new(mime.WordDecoder)
	decoded, err := decoder.DecodeHeader(raw)
	if err != nil {
		return raw
	}
	return decoded
}

func isSMTPPacket(packet model.Packet) bool {
	proto := strings.ToUpper(strings.TrimSpace(packet.Protocol))
	if proto == "SMTP" {
		return true
	}
	if packet.SourcePort == 25 || packet.SourcePort == 465 || packet.SourcePort == 587 || packet.DestPort == 25 || packet.DestPort == 465 || packet.DestPort == 587 {
		return true
	}
	info := strings.ToUpper(strings.TrimSpace(packet.Info))
	if strings.Contains(info, "SMTP") || strings.HasPrefix(info, "EHLO ") || strings.HasPrefix(info, "HELO ") || strings.HasPrefix(info, "MAIL FROM:") || strings.HasPrefix(info, "RCPT TO:") {
		return true
	}
	payload := strings.ToUpper(strings.TrimSpace(packet.Payload))
	return strings.HasPrefix(payload, "45:48:4C:4F") || strings.HasPrefix(payload, "48:45:4C:4F") || strings.HasPrefix(payload, "4D:41:49:4C:20:46:52:4F:4D")
}

func detectSMTPDirection(packet model.Packet) string {
	if packet.DestPort == 25 || packet.DestPort == 465 || packet.DestPort == 587 {
		return "client"
	}
	if packet.SourcePort == 25 || packet.SourcePort == 465 || packet.SourcePort == 587 {
		return "server"
	}
	line := firstSMTPLine(packet)
	if parseSMTPStatusCode(line) > 0 {
		return "server"
	}
	return "client"
}

func firstSMTPLine(packet model.Packet) string {
	text := decodeSMTPPayloadText(packet.Payload)
	if strings.TrimSpace(text) == "" {
		text = packet.Info
	}
	lines := splitSMTPLines(text)
	if len(lines) == 0 {
		return ""
	}
	return lines[0]
}

func updateSMTPEndpoints(session *model.SMTPSession, packet model.Packet, direction string) {
	if session == nil {
		return
	}
	if direction == "client" {
		session.Client = packet.SourceIP
		session.Server = packet.DestIP
		session.ClientPort = packet.SourcePort
		session.ServerPort = packet.DestPort
		return
	}
	session.Client = packet.DestIP
	session.Server = packet.SourceIP
	session.ClientPort = packet.DestPort
	session.ServerPort = packet.SourcePort
}

func decodeSMTPPayloadText(payload string) string {
	raw := strings.TrimSpace(payload)
	if raw == "" {
		return ""
	}
	if decoded := decodeLooseHex(raw); len(decoded) > 0 {
		return string(bytes.Trim(decoded, "\x00"))
	}
	return payload
}

func splitSMTPLines(raw string) []string {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	raw = strings.ReplaceAll(raw, "\r", "\n")
	lines := strings.Split(raw, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		out = append(out, line)
	}
	return out
}

func parseSMTPStatusCode(line string) int {
	if len(line) < 3 {
		return 0
	}
	code, err := strconv.Atoi(line[:3])
	if err != nil {
		return 0
	}
	return code
}

func parseSMTPCommand(line string) (string, string) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) == 0 {
		return "", ""
	}
	command := strings.ToUpper(fields[0])
	switch command {
	case "EHLO", "HELO", "MAIL", "RCPT", "DATA", "AUTH", "QUIT", "RSET", "NOOP", "STARTTLS":
		return command, strings.TrimSpace(strings.TrimPrefix(line, fields[0]))
	default:
		return "", ""
	}
}

func extractSMTPAddress(raw string) string {
	raw = strings.TrimSpace(raw)
	if idx := strings.Index(raw, "<"); idx >= 0 {
		if end := strings.Index(raw[idx+1:], ">"); end >= 0 {
			return strings.TrimSpace(raw[idx+1 : idx+1+end])
		}
	}
	raw = strings.TrimPrefix(strings.TrimPrefix(strings.ToUpper(raw), "FROM:"), "TO:")
	return strings.TrimSpace(raw)
}

func decodeSMTPBase64Inline(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(bytes.Trim(decoded, "\x00")))
}

func decodeSMTPAuthPlain(raw string) (string, bool) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil {
		return "", false
	}
	parts := bytes.Split(decoded, []byte{0})
	if len(parts) >= 3 {
		return strings.TrimSpace(string(parts[len(parts)-2])), len(parts[len(parts)-1]) > 0
	}
	return "", len(decoded) > 0
}

func normalizeSMTPChunk(raw string) string {
	if raw == "" {
		return raw
	}
	if strings.HasSuffix(raw, "\n") {
		return raw
	}
	return raw + "\n"
}

func containsSMTPDataTerminator(raw string) bool {
	normalized := strings.ReplaceAll(raw, "\r\n", "\n")
	return strings.Contains(normalized, "\n.\n") || strings.HasSuffix(normalized, "\n.")
}

func normalizeSMTPDataMessage(raw string) string {
	normalized := strings.ReplaceAll(raw, "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")
	if idx := strings.Index(normalized, "\n.\n"); idx >= 0 {
		normalized = normalized[:idx]
	}
	normalized = strings.TrimSpace(normalized)
	return strings.ReplaceAll(normalized, "\n", "\r\n")
}

func smtpStatusHint(code int) string {
	switch code {
	case 220:
		return "server-ready"
	case 235:
		return "auth-success"
	case 250:
		return "ok"
	case 334:
		return "auth-challenge"
	case 354:
		return "data-start"
	case 421:
		return "service-unavailable"
	case 450, 451, 452:
		return "transient-failure"
	case 500, 501, 502, 503, 504:
		return "command-error"
	case 530:
		return "auth-required"
	case 535:
		return "auth-failed"
	case 550, 551, 552, 553, 554:
		return "delivery-failed"
	default:
		if code >= 200 && code < 400 {
			return "success-ish"
		}
		if code >= 400 && code < 600 {
			return "failure-ish"
		}
		return fmt.Sprintf("code-%d", code)
	}
}

func appendUniqueString(items []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return items
	}
	for _, item := range items {
		if item == value {
			return items
		}
	}
	return append(items, value)
}

func trimSMTPCommands(items []model.SMTPCommandRecord, limit int) []model.SMTPCommandRecord {
	if limit <= 0 || len(items) <= limit {
		return items
	}
	return append([]model.SMTPCommandRecord(nil), items[:limit]...)
}

func buildSMTPNotes(analysis model.SMTPAnalysis) []string {
	notes := make([]string, 0, 4)
	if analysis.SessionCount == 0 {
		return []string{"当前抓包中未识别到可重建的 SMTP 会话。"}
	}
	notes = append(notes, fmt.Sprintf("共识别 %d 条 SMTP 会话，提取出 %d 封邮件。", analysis.SessionCount, analysis.MessageCount))
	if analysis.AuthCount > 0 {
		notes = append(notes, fmt.Sprintf("其中 %d 条会话出现了 SMTP AUTH 认证痕迹，可继续关注用户名、认证方式与明文传输风险。", analysis.AuthCount))
	}
	if analysis.AttachmentHintCount > 0 {
		notes = append(notes, fmt.Sprintf("共发现 %d 个附件线索，建议结合文件名、MIME 边界和对象导出继续取证。", analysis.AttachmentHintCount))
	}
	return notes
}

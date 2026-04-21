package engine

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gshark/sentinel/backend/internal/model"
	"github.com/gshark/sentinel/backend/internal/tshark"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

var scanWinRMRowsWithDisplayFilter = tshark.ScanFieldRowsWithDisplayFilter

const defaultWinRMPreviewLines = 200

type winrmDecryptOptions struct {
	includeErrorFrames   bool
	extractCommandOutput bool
}

type winrmDecryptReport struct {
	text                string
	frameCount          int
	errorFrameCount     int
	extractedFrameCount int
}

type winrmExportRecord struct {
	filePath string
	name     string
}

type winrmMessageRow struct {
	frameNumber string
	timestamp   string
	src         string
	dst         string
	srcPort     string
	dstPort     string
	authHeader  string
	wwwAuth     string
	mimeData    string
}

type winrmSecurityContext struct {
	port               int
	ntHash             []byte
	complete           bool
	sessionKey         []byte
	keyExch            bool
	signKeyInitiate    []byte
	signKeyAccept      []byte
	sealCipherInitiate *rc4.Cipher
	sealCipherAccept   *rc4.Cipher
	initiateSeqNo      uint32
	acceptSeqNo        uint32
}

var (
	winrmExportMu      sync.Mutex
	winrmExportRecords = map[string]winrmExportRecord{}
)

func (s *Service) CurrentCapturePath() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return strings.TrimSpace(s.pcap)
}

func (s *Service) RunWinRMDecrypt(req model.WinRMDecryptRequest) (model.WinRMDecryptResult, error) {
	capturePath := s.CurrentCapturePath()
	if capturePath == "" {
		return model.WinRMDecryptResult{}, fmt.Errorf("当前未加载抓包，请先导入 pcapng 文件")
	}
	if req.Port <= 0 || req.Port > 65535 {
		return model.WinRMDecryptResult{}, fmt.Errorf("port 非法")
	}
	authMode := strings.ToLower(strings.TrimSpace(req.AuthMode))
	if authMode != "password" && authMode != "nt_hash" {
		return model.WinRMDecryptResult{}, fmt.Errorf("auth_mode 仅支持 password 或 nt_hash")
	}
	var ntHash []byte
	var err error
	if authMode == "password" {
		password := strings.TrimSpace(req.Password)
		if password == "" {
			return model.WinRMDecryptResult{}, fmt.Errorf("password 不能为空")
		}
		ntHash = ntowfv1(password)
	} else {
		ntHash, err = decodeHexField("nt_hash", req.NTHash)
		if err != nil {
			return model.WinRMDecryptResult{}, err
		}
	}
	previewLines := req.PreviewLines
	if previewLines <= 0 {
		previewLines = defaultWinRMPreviewLines
	}

	rows, err := scanWinRMRows(capturePath, req.Port)
	if err != nil {
		return model.WinRMDecryptResult{}, err
	}
	report, err := decryptWinRMMessages(rows, req.Port, ntHash, winrmDecryptOptions{
		includeErrorFrames:   req.IncludeErrorFrames,
		extractCommandOutput: req.ExtractCommandOutput,
	})
	if err != nil {
		return model.WinRMDecryptResult{}, err
	}
	fullText := report.text
	if strings.TrimSpace(fullText) == "" {
		return model.WinRMDecryptResult{}, fmt.Errorf("未提取到可预览的 WinRM 明文")
	}

	lines := splitNonEmptyLines(fullText)
	previewText, previewTruncated := previewTextByLines(lines, previewLines)
	resultID := fmt.Sprintf("winrm-%d", time.Now().UnixNano())
	filename := fmt.Sprintf("winrm-decrypt-%s.txt", time.Now().Format("20060102-150405"))
	if _, err := persistWinRMExport(resultID, filename, fullText); err != nil {
		return model.WinRMDecryptResult{}, err
	}

	return model.WinRMDecryptResult{
		ResultID:            resultID,
		CaptureName:         filepath.Base(capturePath),
		Port:                req.Port,
		AuthMode:            authMode,
		PreviewText:         previewText,
		PreviewTruncated:    previewTruncated,
		LineCount:           len(lines),
		FrameCount:          report.frameCount,
		ErrorFrameCount:     report.errorFrameCount,
		ExtractedFrameCount: report.extractedFrameCount,
		ExportFilename:      filename,
		Message:             "ok",
	}, nil
}

func (s *Service) WinRMExportFile(resultID string) (string, string, error) {
	winrmExportMu.Lock()
	defer winrmExportMu.Unlock()
	record, ok := winrmExportRecords[strings.TrimSpace(resultID)]
	if !ok {
		return "", "", fmt.Errorf("WinRM 导出结果不存在")
	}
	return record.filePath, record.name, nil
}

func scanWinRMRows(capturePath string, port int) ([]winrmMessageRow, error) {
	filter := fmt.Sprintf("http && tcp.port == %d", port)
	fieldSets := [][]string{
		{
			"frame.number",
			"frame.time",
			"ip.src",
			"ip.dst",
			"tcp.srcport",
			"tcp.dstport",
			"http.authorization",
			"http.www_authenticate",
			"mime_multipart.data",
		},
		{
			"frame.number",
			"frame.time",
			"ip.src",
			"ip.dst",
			"tcp.srcport",
			"tcp.dstport",
			"http.authorization",
			"http.www_authenticate",
			"http.file_data",
		},
		{
			"frame.number",
			"frame.time",
			"ip.src",
			"ip.dst",
			"tcp.srcport",
			"tcp.dstport",
			"http.authorization",
			"http.www_authenticate",
			"data.data",
		},
	}
	var lastErr error
	for index, fields := range fieldSets {
		rows := make([]winrmMessageRow, 0, 64)
		err := scanWinRMRowsWithDisplayFilter(capturePath, fields, filter, func(parts []string) {
			if len(parts) < len(fields) {
				return
			}
			rows = append(rows, winrmMessageRow{
				frameNumber: parts[0],
				timestamp:   parts[1],
				src:         parts[2],
				dst:         parts[3],
				srcPort:     parts[4],
				dstPort:     parts[5],
				authHeader:  parts[6],
				wwwAuth:     parts[7],
				mimeData:    parts[8],
			})
		})
		if err == nil {
			return rows, nil
		}
		lastErr = err
		if index < len(fieldSets)-1 && isWinRMFieldCompatibilityError(err) {
			continue
		}
		break
	}
	return nil, fmt.Errorf("扫描 WinRM 字段失败: %s", explainWinRMScanError(lastErr))
}

func isWinRMFieldCompatibilityError(err error) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	return strings.Contains(message, "Some fields aren't valid") && strings.Contains(message, "mime_multipart.data")
}

func explainWinRMScanError(err error) string {
	if err == nil {
		return "unknown error"
	}
	message := err.Error()
	if strings.Contains(message, "smb2_seskey_list") || strings.Contains(message, "Secret session key to use for decryption") {
		return "本机 tshark/Wireshark 配置中的 SMB2 Secret Session Key 表格式错误（通常是粘贴了包含异常字符的密钥条目），请检查后重试。原始错误: " + message
	}
	return message
}

func decodeWinRMCiphertext(raw string) ([]byte, error) {
	for _, candidate := range strings.Split(raw, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		decoded, err := decodeHexField("winrm_payload", candidate)
		if err == nil {
			return decoded, nil
		}
	}
	return decodeHexField("winrm_payload", raw)
}

func extractWinRMMessageBodies(raw string) [][]byte {
	if decoded, err := decodeWinRMCiphertext(raw); err == nil {
		if bodies, ok := unpackWinRMMultipartBodies(decoded); ok {
			return bodies
		}
		return [][]byte{decoded}
	}

	sources := [][]byte{[]byte(raw)}
	if decodedRaw, err := decodeHexField("winrm_payload", raw); err == nil {
		sources = append(sources, decodedRaw)
	}

	for _, source := range sources {
		if bodies, ok := unpackWinRMMultipartBodies(source); ok {
			return bodies
		}
	}
	return nil
}

func unpackWinRMMultipartBodies(data []byte) ([][]byte, bool) {
	if !bytes.Contains(data, []byte("Encrypted Boundary")) {
		return nil, false
	}

	rawParts := bytes.Split(data, []byte("--Encrypted Boundary"))
	parts := make([][]byte, 0, len(rawParts))
	for _, part := range rawParts {
		trimmed := bytes.Trim(part, "\r\n")
		if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("--")) {
			continue
		}
		parts = append(parts, trimmed)
	}

	bodies := make([][]byte, 0, len(parts)/2)
	for i := 0; i+1 < len(parts); i += 2 {
		header := parts[i]
		if !bytes.Contains(header, []byte("Length=")) {
			continue
		}

		payload := bytes.Trim(parts[i+1], "\r\n")
		payload = bytes.TrimSuffix(payload, []byte("--"))
		payload = bytes.TrimPrefix(payload, []byte("Content-Type: application/octet-stream\r\n"))
		payload = bytes.TrimPrefix(payload, []byte("Content-Type: application/octet-stream\n"))
		payload = bytes.Trim(payload, "\r\n")
		if len(payload) == 0 {
			continue
		}
		bodies = append(bodies, append([]byte(nil), payload...))
	}

	return bodies, len(bodies) > 0
}

func decryptWinRMRows(rows []winrmMessageRow, winrmPort int, ntHash []byte) (string, int, error) {
	report, err := decryptWinRMMessages(rows, winrmPort, ntHash, winrmDecryptOptions{})
	return report.text, report.frameCount, err
}

func decryptWinRMMessages(rows []winrmMessageRow, winrmPort int, ntHash []byte, opts winrmDecryptOptions) (winrmDecryptReport, error) {
	contexts := []*winrmSecurityContext{}
	blocks := make([]string, 0, 16)
	report := winrmDecryptReport{}
	for _, row := range rows {
		sourcePort := parseIntSafe(row.srcPort)
		destPort := parseIntSafe(row.dstPort)
		uniquePort := sourcePort
		if uniquePort == winrmPort {
			uniquePort = destPort
		}

		authToken := parseHTTPAuthToken(row.authHeader)
		if authToken == nil {
			authToken = parseHTTPAuthToken(row.wwwAuth)
		}

		var context *winrmSecurityContext
		if len(authToken) > 0 {
			switch {
			case hasNTLMType(authToken, 1):
				context = &winrmSecurityContext{port: uniquePort, ntHash: append([]byte(nil), ntHash...)}
				contexts = append(contexts, context)
			case hasNTLMType(authToken, 2), hasNTLMType(authToken, 3):
				context = findWinRMContext(contexts, uniquePort)
				if context != nil {
					if err := context.addToken(authToken); err != nil {
						report.errorFrameCount++
						if opts.includeErrorFrames {
							blocks = append(blocks, fmt.Sprintf("No: %s | Time: %s | Source: %s | Destination: %s\n[error] %v\n", row.frameNumber, row.timestamp, row.src, row.dst, err))
						}
					}
				}
			}
		}

		if strings.TrimSpace(row.mimeData) == "" {
			continue
		}
		if context == nil {
			context = findWinRMContext(contexts, uniquePort)
		}
		if context == nil || !context.complete {
			continue
		}
		ciphertexts := extractWinRMMessageBodies(row.mimeData)
		if len(ciphertexts) == 0 {
			continue
		}

		decrypted := make([]string, 0, len(ciphertexts))
		var decryptErr error
		for _, ciphertext := range ciphertexts {
			var (
				plain []byte
				err   error
			)
			if sourcePort == winrmPort {
				plain, err = context.unwrapAccept(ciphertext)
			} else {
				plain, err = context.unwrapInitiate(ciphertext)
			}
			if err != nil {
				decryptErr = err
				break
			}
			decrypted = append(decrypted, prettyXMLOrRaw(plain))
		}
		if decryptErr != nil {
			report.errorFrameCount++
			if opts.includeErrorFrames {
				blocks = append(blocks, fmt.Sprintf("No: %s | Time: %s | Source: %s | Destination: %s\n[error] %v\n", row.frameNumber, row.timestamp, row.src, row.dst, decryptErr))
			}
			continue
		}
		if len(decrypted) == 0 {
			continue
		}
		report.frameCount++
		if opts.extractCommandOutput {
			decorated := make([]string, 0, len(decrypted))
			for _, message := range decrypted {
				block, extracted := appendWinRMExtraction(message)
				if extracted {
					report.extractedFrameCount++
				}
				decorated = append(decorated, block)
			}
			decrypted = decorated
		}
		blocks = append(blocks, fmt.Sprintf("No: %s | Time: %s | Source: %s | Destination: %s\n%s\n", row.frameNumber, row.timestamp, row.src, row.dst, strings.Join(decrypted, "\n")))
	}
	report.text = strings.Join(blocks, "\n")
	return report, nil
}

func parseHTTPAuthToken(headerValue string) []byte {
	for _, chunk := range strings.Split(headerValue, ",") {
		part := strings.TrimSpace(chunk)
		if part == "" {
			continue
		}
		pieces := strings.SplitN(part, " ", 2)
		if len(pieces) != 2 {
			continue
		}
		scheme := strings.ToLower(strings.TrimSpace(pieces[0]))
		if scheme != "ntlm" && scheme != "negotiate" {
			continue
		}
		token, err := base64.StdEncoding.DecodeString(strings.TrimSpace(pieces[1]))
		if err == nil && len(token) >= 8 && string(token[:8]) == "NTLMSSP\x00" {
			return token
		}
	}
	return nil
}

func hasNTLMType(token []byte, messageType byte) bool {
	return len(token) > 8 && string(token[:8]) == "NTLMSSP\x00" && token[8] == messageType
}

func findWinRMContext(contexts []*winrmSecurityContext, port int) *winrmSecurityContext {
	for i := len(contexts) - 1; i >= 0; i-- {
		if contexts[i].port == port {
			return contexts[i]
		}
	}
	return nil
}

func (c *winrmSecurityContext) addToken(token []byte) error {
	if !hasNTLMType(token, 3) {
		return nil
	}
	if len(token) < 64 {
		return fmt.Errorf("NTLM Type3 消息过短")
	}
	ntChallenge := getNTLMField(20, token)
	bDomain := getNTLMField(28, token)
	bUsername := getNTLMField(36, token)
	encryptedRandomSessionKey := getNTLMField(52, token)
	if len(ntChallenge) < 16 {
		return fmt.Errorf("NTLM challenge 长度非法")
	}
	flags := binary.LittleEndian.Uint32(token[60:64])
	encoding := "windows-1252"
	if flags&0x00000001 != 0 {
		encoding = "utf-16le"
	}
	domain := decodeNTLMText(bDomain, encoding)
	username := decodeNTLMText(bUsername, encoding)
	responseKeyNT := hmacMD5(c.ntHash, utf16LE(strings.ToUpper(username)+domain))
	ntProofStr := ntChallenge[:16]
	keyExchangeKey := hmacMD5(responseKeyNT, ntProofStr)
	c.keyExch = flags&0x40000000 != 0
	if c.keyExch && len(encryptedRandomSessionKey) > 0 {
		cipher, err := rc4.NewCipher(keyExchangeKey)
		if err != nil {
			return err
		}
		c.sessionKey = make([]byte, len(encryptedRandomSessionKey))
		cipher.XORKeyStream(c.sessionKey, encryptedRandomSessionKey)
	} else {
		c.sessionKey = append([]byte(nil), keyExchangeKey...)
	}
	c.signKeyInitiate = signKey(c.sessionKey, true)
	c.signKeyAccept = signKey(c.sessionKey, false)
	sealKeyInitiate := sealKey(c.sessionKey, true)
	sealKeyAccept := sealKey(c.sessionKey, false)
	var err error
	c.sealCipherInitiate, err = rc4.NewCipher(sealKeyInitiate)
	if err != nil {
		return err
	}
	c.sealCipherAccept, err = rc4.NewCipher(sealKeyAccept)
	if err != nil {
		return err
	}
	c.complete = true
	return nil
}

func (c *winrmSecurityContext) unwrapInitiate(data []byte) ([]byte, error) {
	plain, err := c.unwrap(c.sealCipherInitiate, c.signKeyInitiate, c.initiateSeqNo, data)
	c.initiateSeqNo++
	return plain, err
}

func (c *winrmSecurityContext) unwrapAccept(data []byte) ([]byte, error) {
	plain, err := c.unwrap(c.sealCipherAccept, c.signKeyAccept, c.acceptSeqNo, data)
	c.acceptSeqNo++
	return plain, err
}

func (c *winrmSecurityContext) unwrap(cipher *rc4.Cipher, signKey []byte, seqNo uint32, data []byte) ([]byte, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("加密消息长度非法")
	}
	header := data[4:20]
	encData := data[20:]
	plain := make([]byte, len(encData))
	cipher.XORKeyStream(plain, encData)
	seqBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(seqBytes, seqNo)
	checksum := hmacMD5(signKey, append(seqBytes, plain...))[:8]
	if c.keyExch {
		cipher.XORKeyStream(checksum, checksum)
	}
	expected := append([]byte{0x01, 0x00, 0x00, 0x00}, append(checksum, seqBytes...)...)
	if len(header) == len(expected) && !bytes.Equal(header, expected) {
		return plain, fmt.Errorf("签名校验失败")
	}
	return plain, nil
}

func getNTLMField(offset int, token []byte) []byte {
	if len(token) < offset+8 {
		return nil
	}
	fieldLen := int(binary.LittleEndian.Uint16(token[offset : offset+2]))
	fieldOffset := int(binary.LittleEndian.Uint32(token[offset+4 : offset+8]))
	if fieldLen <= 0 || fieldOffset < 0 || fieldOffset+fieldLen > len(token) {
		return nil
	}
	return token[fieldOffset : fieldOffset+fieldLen]
}

func decodeNTLMText(raw []byte, encoding string) string {
	if len(raw) == 0 {
		return ""
	}
	if encoding == "utf-16le" {
		runes := make([]rune, 0, len(raw)/2)
		for i := 0; i+1 < len(raw); i += 2 {
			runes = append(runes, rune(binary.LittleEndian.Uint16(raw[i:i+2])))
		}
		return string(runes)
	}
	return string(raw)
}

func utf16LE(raw string) []byte {
	out := make([]byte, 0, len(raw)*2)
	for _, r := range raw {
		buf := make([]byte, 2)
		binary.LittleEndian.PutUint16(buf, uint16(r))
		out = append(out, buf...)
	}
	return out
}

func hmacMD5(key, data []byte) []byte {
	mac := hmac.New(md5.New, key)
	_, _ = mac.Write(data)
	return mac.Sum(nil)
}

func sealKey(sessionKey []byte, initiate bool) []byte {
	direction := "client-to-server"
	if !initiate {
		direction = "server-to-client"
	}
	return md5Buffer(append(append([]byte{}, sessionKey...), []byte("session key to "+direction+" sealing key magic constant\x00")...))
}

func signKey(sessionKey []byte, initiate bool) []byte {
	direction := "client-to-server"
	if !initiate {
		direction = "server-to-client"
	}
	return md5Buffer(append(append([]byte{}, sessionKey...), []byte("session key to "+direction+" signing key magic constant\x00")...))
}

func md5Buffer(data []byte) []byte {
	sum := md5.Sum(data)
	return sum[:]
}

func prettyXMLOrRaw(data []byte) string {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return "[empty message]"
	}
	return trimmed
}

func appendWinRMExtraction(raw string) (string, bool) {
	extracted := extractWinRMCommandOutput(raw)
	if strings.TrimSpace(extracted) == "" {
		return raw, false
	}
	return raw + "\n\n[extract]\n" + extracted, true
}

func extractWinRMCommandOutput(raw string) string {
	decoder := xml.NewDecoder(strings.NewReader(raw))
	path := make([]string, 0, 8)
	var (
		commandBuilder strings.Builder
		stdinBytes     []byte
		stdoutBytes    []byte
		stderrBytes    []byte
		currentStream  string
		streamText     strings.Builder
	)

	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}

		switch element := token.(type) {
		case xml.StartElement:
			path = append(path, element.Name.Local)
			if element.Name.Local == "Stream" {
				currentStream = ""
				streamText.Reset()
				for _, attr := range element.Attr {
					if attr.Name.Local == "Name" {
						currentStream = strings.ToLower(strings.TrimSpace(attr.Value))
						break
					}
				}
			}
		case xml.CharData:
			value := string(element)
			if currentStream != "" {
				streamText.WriteString(value)
			}
			if len(path) >= 2 && path[len(path)-1] == "Command" && path[len(path)-2] == "CommandLine" {
				commandBuilder.WriteString(value)
			}
		case xml.EndElement:
			if element.Name.Local == "Stream" && currentStream != "" {
				if decoded := decodeWinRMBase64Text(streamText.String()); len(decoded) > 0 {
					switch currentStream {
					case "stdin":
						stdinBytes = append(stdinBytes, decoded...)
					case "stdout":
						stdoutBytes = append(stdoutBytes, decoded...)
					case "stderr":
						stderrBytes = append(stderrBytes, decoded...)
					}
				}
				currentStream = ""
				streamText.Reset()
			}
			if len(path) > 0 {
				path = path[:len(path)-1]
			}
		}
	}

	sections := make([]string, 0, 4)
	if command := strings.TrimSpace(commandBuilder.String()); command != "" {
		sections = append(sections, "command:\n"+indentWinRMText(command))
	}
	if stdin := strings.TrimRight(decodeWinRMOutputText(stdinBytes), "\r\n"); stdin != "" {
		sections = append(sections, "stdin:\n"+indentWinRMText(stdin))
	}
	if stdout := strings.TrimRight(decodeWinRMOutputText(stdoutBytes), "\r\n"); stdout != "" {
		sections = append(sections, "stdout:\n"+indentWinRMText(stdout))
	}
	if stderr := strings.TrimRight(decodeWinRMOutputText(stderrBytes), "\r\n"); stderr != "" {
		sections = append(sections, "stderr:\n"+indentWinRMText(stderr))
	}
	return strings.Join(sections, "\n")
}

func decodeWinRMBase64Text(raw string) []byte {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil
	}
	decoded, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		return nil
	}
	return decoded
}

func decodeWinRMOutputText(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	if utf8.Valid(raw) {
		return string(raw)
	}
	decoded, _, err := transform.Bytes(simplifiedchinese.GB18030.NewDecoder(), raw)
	if err == nil && utf8.Valid(decoded) {
		return string(decoded)
	}
	return string(raw)
}

func indentWinRMText(raw string) string {
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	for index, line := range lines {
		lines[index] = "  " + line
	}
	return strings.Join(lines, "\n")
}

func parseIntSafe(raw string) int {
	value, _ := strconv.Atoi(strings.TrimSpace(raw))
	return value
}

func splitNonEmptyLines(text string) []string {
	rawLines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	lines := make([]string, 0, len(rawLines))
	for _, line := range rawLines {
		lines = append(lines, line)
	}
	return lines
}

func previewTextByLines(lines []string, limit int) (string, bool) {
	if limit <= 0 || len(lines) <= limit {
		return strings.Join(lines, "\n"), false
	}
	return strings.Join(lines[:limit], "\n"), true
}

func persistWinRMExport(resultID, filename, content string) (string, error) {
	dir, err := os.MkdirTemp("", "gshark-winrm-*")
	if err != nil {
		return "", fmt.Errorf("创建 WinRM 导出目录失败: %w", err)
	}
	filePath := filepath.Join(dir, filename)
	if err := os.WriteFile(filePath, []byte(content), 0o644); err != nil {
		return "", fmt.Errorf("写入 WinRM 导出文件失败: %w", err)
	}
	winrmExportMu.Lock()
	winrmExportRecords[resultID] = winrmExportRecord{filePath: filePath, name: filename}
	winrmExportMu.Unlock()
	return filePath, nil
}

func ntowfv1(password string) []byte {
	return md4Sum(utf16LE(password))
}

func md4Sum(data []byte) []byte {
	msg := append([]byte(nil), data...)
	bitLen := uint64(len(msg)) * 8
	msg = append(msg, 0x80)
	for len(msg)%64 != 56 {
		msg = append(msg, 0x00)
	}
	lenBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(lenBytes, bitLen)
	msg = append(msg, lenBytes...)

	a0 := uint32(0x67452301)
	b0 := uint32(0xefcdab89)
	c0 := uint32(0x98badcfe)
	d0 := uint32(0x10325476)

	for i := 0; i < len(msg); i += 64 {
		var x [16]uint32
		for j := 0; j < 16; j++ {
			x[j] = binary.LittleEndian.Uint32(msg[i+j*4 : i+j*4+4])
		}
		a, b, c, d := a0, b0, c0, d0

		ff := func(a, b, c, d, xk, s uint32) uint32 {
			return bitsRotateLeft32(a+((b&c)|(^b&d))+xk, s)
		}
		gg := func(a, b, c, d, xk, s uint32) uint32 {
			return bitsRotateLeft32(a+((b&c)|(b&d)|(c&d))+xk+0x5a827999, s)
		}
		hh := func(a, b, c, d, xk, s uint32) uint32 {
			return bitsRotateLeft32(a+(b^c^d)+xk+0x6ed9eba1, s)
		}

		a = ff(a, b, c, d, x[0], 3)
		d = ff(d, a, b, c, x[1], 7)
		c = ff(c, d, a, b, x[2], 11)
		b = ff(b, c, d, a, x[3], 19)
		a = ff(a, b, c, d, x[4], 3)
		d = ff(d, a, b, c, x[5], 7)
		c = ff(c, d, a, b, x[6], 11)
		b = ff(b, c, d, a, x[7], 19)
		a = ff(a, b, c, d, x[8], 3)
		d = ff(d, a, b, c, x[9], 7)
		c = ff(c, d, a, b, x[10], 11)
		b = ff(b, c, d, a, x[11], 19)
		a = ff(a, b, c, d, x[12], 3)
		d = ff(d, a, b, c, x[13], 7)
		c = ff(c, d, a, b, x[14], 11)
		b = ff(b, c, d, a, x[15], 19)

		a = gg(a, b, c, d, x[0], 3)
		d = gg(d, a, b, c, x[4], 5)
		c = gg(c, d, a, b, x[8], 9)
		b = gg(b, c, d, a, x[12], 13)
		a = gg(a, b, c, d, x[1], 3)
		d = gg(d, a, b, c, x[5], 5)
		c = gg(c, d, a, b, x[9], 9)
		b = gg(b, c, d, a, x[13], 13)
		a = gg(a, b, c, d, x[2], 3)
		d = gg(d, a, b, c, x[6], 5)
		c = gg(c, d, a, b, x[10], 9)
		b = gg(b, c, d, a, x[14], 13)
		a = gg(a, b, c, d, x[3], 3)
		d = gg(d, a, b, c, x[7], 5)
		c = gg(c, d, a, b, x[11], 9)
		b = gg(b, c, d, a, x[15], 13)

		a = hh(a, b, c, d, x[0], 3)
		d = hh(d, a, b, c, x[8], 9)
		c = hh(c, d, a, b, x[4], 11)
		b = hh(b, c, d, a, x[12], 15)
		a = hh(a, b, c, d, x[2], 3)
		d = hh(d, a, b, c, x[10], 9)
		c = hh(c, d, a, b, x[6], 11)
		b = hh(b, c, d, a, x[14], 15)
		a = hh(a, b, c, d, x[1], 3)
		d = hh(d, a, b, c, x[9], 9)
		c = hh(c, d, a, b, x[5], 11)
		b = hh(b, c, d, a, x[13], 15)
		a = hh(a, b, c, d, x[3], 3)
		d = hh(d, a, b, c, x[11], 9)
		c = hh(c, d, a, b, x[7], 11)
		b = hh(b, c, d, a, x[15], 15)

		a0 += a
		b0 += b
		c0 += c
		d0 += d
	}

	out := make([]byte, 16)
	binary.LittleEndian.PutUint32(out[0:4], a0)
	binary.LittleEndian.PutUint32(out[4:8], b0)
	binary.LittleEndian.PutUint32(out[8:12], c0)
	binary.LittleEndian.PutUint32(out[12:16], d0)
	return out
}

func bitsRotateLeft32(x uint32, s uint32) uint32 {
	return (x << s) | (x >> (32 - s))
}

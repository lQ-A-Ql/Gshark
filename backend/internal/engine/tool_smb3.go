package engine

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/gshark/sentinel/backend/internal/model"
	"github.com/gshark/sentinel/backend/internal/tshark"
)

var scanSMB3SessionRowsWithDisplayFilter = tshark.ScanFieldRowsWithDisplayFilter

type smb3SessionScanRow struct {
	frameNumber         string
	timestamp           string
	src                 string
	dst                 string
	msgID               string
	sessionID           string
	isResponse          bool
	username            string
	domain              string
	ntProofStr          string
	encryptedSessionKey string
}

func normalizeHexInput(raw string) string {
	trimmed := strings.TrimSpace(raw)
	trimmed = strings.TrimPrefix(strings.TrimPrefix(trimmed, "0x"), "0X")
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) || r == ':' || r == '-' {
			return -1
		}
		return r
	}, trimmed)
}

func (s *Service) ListSMB3SessionCandidates() ([]model.SMB3SessionCandidate, error) {
	capturePath := s.CurrentCapturePath()
	if capturePath == "" {
		return nil, fmt.Errorf("当前未加载抓包，请先导入 pcapng 文件")
	}
	rows, err := scanSMB3SessionCandidates(capturePath)
	if err != nil {
		return nil, err
	}
	return rows, nil
}

func decodeHexField(name, raw string) ([]byte, error) {
	cleaned := normalizeHexInput(raw)
	if cleaned == "" {
		return nil, fmt.Errorf("%s 不能为空", name)
	}
	if len(cleaned)%2 != 0 {
		return nil, fmt.Errorf("%s 长度非法", name)
	}
	decoded, err := hex.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("%s 不是有效十六进制", name)
	}
	return decoded, nil
}

func (s *Service) GenerateSMB3RandomSessionKey(req model.SMB3RandomSessionKeyRequest) (model.SMB3RandomSessionKeyResult, error) {
	username := strings.ToUpper(strings.TrimSpace(req.Username))
	domain := normalizeSMB3Domain(req.Domain)
	if username == "" {
		return model.SMB3RandomSessionKeyResult{}, fmt.Errorf("username 不能为空")
	}

	ntlmHash, err := decodeHexField("ntlm_hash", req.NTLMHash)
	if err != nil {
		return model.SMB3RandomSessionKeyResult{}, err
	}
	ntProofStr, err := decodeHexField("nt_proof_str", req.NTProofStr)
	if err != nil {
		return model.SMB3RandomSessionKeyResult{}, err
	}
	encryptedSessionKey, err := decodeHexField("encrypted_session_key", req.EncryptedSessionKey)
	if err != nil {
		return model.SMB3RandomSessionKeyResult{}, err
	}

	userDomain := []byte(username + domain)
	utf16Payload := encodeUTF16LE(userDomain)

	respNTKeyMac := hmac.New(md5.New, ntlmHash)
	_, _ = respNTKeyMac.Write(utf16Payload)
	responseNTKey := respNTKeyMac.Sum(nil)

	keyExchMac := hmac.New(md5.New, responseNTKey)
	_, _ = keyExchMac.Write(ntProofStr)
	keyExchangeKey := keyExchMac.Sum(nil)

	rc4Cipher, err := rc4.NewCipher(keyExchangeKey)
	if err != nil {
		return model.SMB3RandomSessionKeyResult{}, fmt.Errorf("初始化 RC4 失败: %w", err)
	}
	randomSessionKey := make([]byte, len(encryptedSessionKey))
	rc4Cipher.XORKeyStream(randomSessionKey, encryptedSessionKey)

	return model.SMB3RandomSessionKeyResult{
		RandomSessionKey: hex.EncodeToString(randomSessionKey),
		Message:          "ok",
	}, nil
}

func encodeUTF16LE(raw []byte) []byte {
	out := make([]byte, 0, len(raw)*2)
	for _, b := range raw {
		out = append(out, b, 0)
	}
	return out
}

func scanSMB3SessionCandidates(capturePath string) ([]model.SMB3SessionCandidate, error) {
	fields := []string{
		"frame.number",
		"frame.time",
		"ip.src",
		"ipv6.src",
		"ip.dst",
		"ipv6.dst",
		"smb2.msg_id",
		"smb2.sesid",
		"smb2.flags.response",
		"ntlmssp.auth.username",
		"ntlmssp.auth.domain",
		"ntlmssp.ntlmv2_response.ntproofstr",
		"ntlmssp.auth.sesskey",
	}
	filter := "smb2 && smb2.cmd == 1"

	scanRows := make([]smb3SessionScanRow, 0, 32)
	err := scanSMB3SessionRowsWithDisplayFilter(capturePath, fields, filter, func(parts []string) {
		if len(parts) < len(fields) {
			return
		}
		src := firstNonEmpty(parts[2], parts[3])
		dst := firstNonEmpty(parts[4], parts[5])
		scanRows = append(scanRows, smb3SessionScanRow{
			frameNumber:         strings.TrimSpace(parts[0]),
			timestamp:           strings.TrimSpace(parts[1]),
			src:                 strings.TrimSpace(src),
			dst:                 strings.TrimSpace(dst),
			msgID:               strings.TrimSpace(parts[6]),
			sessionID:           normalizeSessionID(parts[7]),
			isResponse:          parseTSharkBool(parts[8]),
			username:            strings.TrimSpace(parts[9]),
			domain:              normalizeSMB3Domain(parts[10]),
			ntProofStr:          normalizeHexInput(parts[11]),
			encryptedSessionKey: normalizeHexInput(parts[12]),
		})
	})
	if err != nil {
		return nil, fmt.Errorf("扫描 SMB3 Session 候选失败: %s", explainWinRMScanError(err))
	}

	pending := map[string]int{}
	candidates := make([]model.SMB3SessionCandidate, 0, len(scanRows))
	for _, row := range scanRows {
		if hasSMB3AuthMaterial(row) {
			candidate := buildSMB3SessionCandidate(row)
			candidates = append(candidates, candidate)
			if candidate.SessionID == "" && row.msgID != "" {
				pending[buildSMB3SessionPendingKey(row.msgID, row.src, row.dst)] = len(candidates) - 1
			}
		}

		if row.isResponse && row.msgID != "" && !isZeroSessionID(row.sessionID) {
			key := buildSMB3SessionPendingKey(row.msgID, row.dst, row.src)
			index, ok := pending[key]
			if !ok {
				continue
			}
			candidates[index].SessionID = row.sessionID
			candidates[index].DisplayLabel = formatSMB3SessionDisplayLabel(candidates[index])
			delete(pending, key)
		}
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		left := candidates[i]
		right := candidates[j]
		if left.Complete != right.Complete {
			return left.Complete && !right.Complete
		}
		if left.SessionID != right.SessionID {
			if left.SessionID == "" {
				return false
			}
			if right.SessionID == "" {
				return true
			}
			return left.SessionID < right.SessionID
		}
		return compareFrameNumber(left.FrameNumber, right.FrameNumber)
	})

	return candidates, nil
}

func hasSMB3AuthMaterial(row smb3SessionScanRow) bool {
	return row.username != "" || row.domain != "" || row.ntProofStr != "" || row.encryptedSessionKey != ""
}

func buildSMB3SessionCandidate(row smb3SessionScanRow) model.SMB3SessionCandidate {
	candidate := model.SMB3SessionCandidate{
		SessionID:           normalizedNonZeroSessionID(row.sessionID),
		Username:            row.username,
		Domain:              row.domain,
		NTProofStr:          row.ntProofStr,
		EncryptedSessionKey: row.encryptedSessionKey,
		Src:                 row.src,
		Dst:                 row.dst,
		FrameNumber:         row.frameNumber,
		Timestamp:           row.timestamp,
		Complete:            row.username != "" && row.ntProofStr != "" && row.encryptedSessionKey != "",
	}
	candidate.DisplayLabel = formatSMB3SessionDisplayLabel(candidate)
	return candidate
}

func formatSMB3SessionDisplayLabel(candidate model.SMB3SessionCandidate) string {
	sessionLabel := candidate.SessionID
	if sessionLabel == "" {
		sessionLabel = "未知 SessionId"
	}

	userLabel := candidate.Username
	if candidate.Domain != "" {
		if userLabel != "" {
			userLabel = candidate.Domain + `\` + userLabel
		} else {
			userLabel = candidate.Domain
		}
	}
	if userLabel == "" {
		userLabel = "未知用户"
	}

	src := firstNonEmpty(candidate.Src, "?")
	dst := firstNonEmpty(candidate.Dst, "?")
	frame := firstNonEmpty(candidate.FrameNumber, "?")

	return fmt.Sprintf("%s | %s | %s -> %s | 帧 #%s", sessionLabel, userLabel, src, dst, frame)
}

func buildSMB3SessionPendingKey(msgID, src, dst string) string {
	return strings.TrimSpace(msgID) + "|" + strings.TrimSpace(src) + "|" + strings.TrimSpace(dst)
}

func normalizeSessionID(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	value, ok := parseUintString(trimmed)
	if !ok {
		return trimmed
	}
	return fmt.Sprintf("0x%016x", value)
}

func normalizedNonZeroSessionID(sessionID string) string {
	if isZeroSessionID(sessionID) {
		return ""
	}
	return strings.TrimSpace(sessionID)
}

func isZeroSessionID(sessionID string) bool {
	trimmed := strings.TrimSpace(sessionID)
	if trimmed == "" {
		return true
	}
	value, ok := parseUintString(trimmed)
	if ok {
		return value == 0
	}
	cleaned := strings.TrimLeft(strings.TrimPrefix(strings.TrimPrefix(trimmed, "0x"), "0X"), "0")
	return cleaned == ""
}

func parseUintString(raw string) (uint64, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, false
	}
	value, err := strconv.ParseUint(trimmed, 0, 64)
	if err == nil {
		return value, true
	}
	cleaned := normalizeHexInput(trimmed)
	if cleaned == "" {
		return 0, false
	}
	value, err = strconv.ParseUint(cleaned, 16, 64)
	if err != nil {
		return 0, false
	}
	return value, true
}

func parseTSharkBool(raw string) bool {
	trimmed := strings.TrimSpace(strings.ToLower(raw))
	return trimmed == "1" || trimmed == "true" || trimmed == "yes"
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func compareFrameNumber(left, right string) bool {
	leftValue, leftOK := strconv.ParseInt(strings.TrimSpace(left), 10, 64)
	rightValue, rightOK := strconv.ParseInt(strings.TrimSpace(right), 10, 64)
	if leftOK == nil && rightOK == nil {
		return leftValue < rightValue
	}
	return strings.TrimSpace(left) < strings.TrimSpace(right)
}

func normalizeSMB3Domain(raw string) string {
	trimmed := strings.TrimSpace(raw)
	switch strings.ToLower(trimmed) {
	case "", "null", "(null)", "<null>":
		return ""
	default:
		return trimmed
	}
}

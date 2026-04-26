package engine

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
	"github.com/gshark/sentinel/backend/internal/tshark"
)

var scanNTLMSessionRowsWithDisplayFilter = tshark.ScanFieldRowsWithDisplayFilter

type ntlmSessionScanRow struct {
	frameNumber         string
	timestamp           string
	src                 string
	dst                 string
	srcPort             string
	dstPort             string
	displayProtocol     string
	info                string
	sessionID           string
	authHeader          string
	wwwAuthenticate     string
	username            string
	domain              string
	challenge           string
	ntProofStr          string
	encryptedSessionKey string
}

func (s *Service) ListNTLMSessionMaterials() ([]model.NTLMSessionMaterial, error) {
	capturePath := s.CurrentCapturePath()
	if capturePath == "" {
		return nil, fmt.Errorf("当前未加载抓包，请先导入 pcapng 文件")
	}
	return scanNTLMSessionMaterials(capturePath)
}

func scanNTLMSessionMaterials(capturePath string) ([]model.NTLMSessionMaterial, error) {
	fieldSets := [][]string{
		{
			"frame.number",
			"frame.time",
			"ip.src",
			"ipv6.src",
			"ip.dst",
			"ipv6.dst",
			"tcp.srcport",
			"tcp.dstport",
			"_ws.col.Protocol",
			"_ws.col.Info",
			"smb2.sesid",
			"http.authorization",
			"http.www_authenticate",
			"ntlmssp.auth.username",
			"ntlmssp.auth.domain",
			"ntlmssp.ntlmserverchallenge",
			"ntlmssp.ntlmv2_response.ntproofstr",
			"ntlmssp.auth.sesskey",
		},
		{
			"frame.number",
			"frame.time",
			"ip.src",
			"ipv6.src",
			"ip.dst",
			"ipv6.dst",
			"tcp.srcport",
			"tcp.dstport",
			"_ws.col.Protocol",
			"_ws.col.Info",
			"smb2.sesid",
			"http.authorization",
			"http.www_authenticate",
			"ntlmssp.auth.username",
			"ntlmssp.auth.domain",
			"ntlmssp.ntlmv2_response.ntproofstr",
			"ntlmssp.auth.sesskey",
		},
	}

	var lastErr error
	var rows []ntlmSessionScanRow
	for _, fields := range fieldSets {
		rows = rows[:0]
		err := scanNTLMSessionRowsWithDisplayFilter(capturePath, fields, "ntlmssp", func(parts []string) {
			if len(parts) < len(fields) {
				return
			}
			row := ntlmSessionScanRow{
				frameNumber:     strings.TrimSpace(parts[0]),
				timestamp:       strings.TrimSpace(parts[1]),
				src:             strings.TrimSpace(firstNonEmpty(parts[2], parts[3])),
				dst:             strings.TrimSpace(firstNonEmpty(parts[4], parts[5])),
				srcPort:         strings.TrimSpace(parts[6]),
				dstPort:         strings.TrimSpace(parts[7]),
				displayProtocol: strings.TrimSpace(parts[8]),
				info:            strings.TrimSpace(parts[9]),
				sessionID:       normalizeSessionID(strings.TrimSpace(parts[10])),
				authHeader:      strings.TrimSpace(parts[11]),
				wwwAuthenticate: strings.TrimSpace(parts[12]),
				username:        strings.TrimSpace(parts[13]),
				domain:          strings.TrimSpace(parts[14]),
			}
			if len(parts) >= 18 {
				row.challenge = normalizeHexInput(parts[15])
				row.ntProofStr = normalizeHexInput(parts[16])
				row.encryptedSessionKey = normalizeHexInput(parts[17])
			} else if len(parts) >= 17 {
				row.ntProofStr = normalizeHexInput(parts[15])
				row.encryptedSessionKey = normalizeHexInput(parts[16])
			}
			rows = append(rows, row)
		})
		if err == nil {
			break
		}
		lastErr = err
	}
	if lastErr != nil && len(rows) == 0 {
		return nil, fmt.Errorf("扫描 NTLM 会话材料失败: %s", explainWinRMScanError(lastErr))
	}

	result := make([]model.NTLMSessionMaterial, 0, len(rows))
	for _, row := range rows {
		result = append(result, buildNTLMSessionMaterial(row))
	}

	sort.SliceStable(result, func(i, j int) bool {
		if result[i].Protocol != result[j].Protocol {
			return result[i].Protocol < result[j].Protocol
		}
		return compareFrameNumber(result[i].FrameNumber, result[j].FrameNumber)
	})
	return result, nil
}

func buildNTLMSessionMaterial(row ntlmSessionScanRow) model.NTLMSessionMaterial {
	protocol := detectNTLMProtocol(row)
	userDisplay := formatNTLMUser(row.username, row.domain)
	direction := detectNTLMDirection(row)
	complete := row.username != "" && row.ntProofStr != ""
	if protocol == "SMB3" {
		complete = complete && row.encryptedSessionKey != ""
	}
	transport := joinNonEmpty(" / ",
		buildNTLMTransportLabel(row.srcPort, row.dstPort),
		normalizedNonZeroSessionID(row.sessionID),
	)
	item := model.NTLMSessionMaterial{
		Protocol:            protocol,
		Transport:           transport,
		FrameNumber:         row.frameNumber,
		Timestamp:           row.timestamp,
		Src:                 row.src,
		Dst:                 row.dst,
		SrcPort:             row.srcPort,
		DstPort:             row.dstPort,
		Direction:           direction,
		Username:            row.username,
		Domain:              row.domain,
		UserDisplay:         userDisplay,
		Challenge:           row.challenge,
		NTProofStr:          row.ntProofStr,
		EncryptedSessionKey: row.encryptedSessionKey,
		SessionID:           normalizedNonZeroSessionID(row.sessionID),
		AuthHeader:          row.authHeader,
		WWWAuthenticate:     row.wwwAuthenticate,
		Info:                row.info,
		Complete:            complete,
	}
	item.DisplayLabel = formatNTLMSessionDisplayLabel(item)
	return item
}

func detectNTLMProtocol(row ntlmSessionScanRow) string {
	display := strings.ToLower(strings.TrimSpace(row.displayProtocol + " " + row.info))
	switch {
	case row.sessionID != "" && row.sessionID != "0x0":
		return "SMB3"
	case row.srcPort == "5985" || row.dstPort == "5985" || row.srcPort == "5986" || row.dstPort == "5986":
		return "WinRM"
	case strings.Contains(display, "winrm"):
		return "WinRM"
	case strings.Contains(display, "http"):
		return "HTTP"
	default:
		return "NTLM"
	}
}

func detectNTLMDirection(row ntlmSessionScanRow) string {
	if row.username != "" || row.ntProofStr != "" || row.encryptedSessionKey != "" || row.authHeader != "" {
		return "client -> server"
	}
	if row.challenge != "" || row.wwwAuthenticate != "" {
		return "server -> client"
	}
	return ""
}

func formatNTLMUser(username, domain string) string {
	username = strings.TrimSpace(username)
	domain = strings.TrimSpace(domain)
	switch {
	case username != "" && domain != "":
		return domain + `\` + username
	case username != "":
		return username
	case domain != "":
		return domain
	default:
		return ""
	}
}

func formatNTLMSessionDisplayLabel(item model.NTLMSessionMaterial) string {
	parts := []string{item.Protocol}
	if item.UserDisplay != "" {
		parts = append(parts, item.UserDisplay)
	}
	if item.Src != "" || item.Dst != "" {
		parts = append(parts, firstNonEmpty(item.Src, "?")+" -> "+firstNonEmpty(item.Dst, "?"))
	}
	if item.FrameNumber != "" {
		parts = append(parts, "帧 #"+item.FrameNumber)
	}
	return strings.Join(parts, " | ")
}

func buildNTLMTransportLabel(srcPort, dstPort string) string {
	srcPort = strings.TrimSpace(srcPort)
	dstPort = strings.TrimSpace(dstPort)
	if srcPort == "" && dstPort == "" {
		return ""
	}
	return "tcp " + firstNonEmpty(srcPort, "?") + "→" + firstNonEmpty(dstPort, "?")
}

func joinNonEmpty(sep string, values ...string) string {
	filtered := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		filtered = append(filtered, value)
	}
	return strings.Join(filtered, sep)
}

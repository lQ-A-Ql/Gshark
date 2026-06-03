package tshark

import (
	"strconv"
	"strings"
)

func hasNonEmpty(values ...string) bool {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return true
		}
	}
	return false
}

func parseTruthy(values ...string) bool {
	for _, raw := range values {
		v := strings.ToLower(strings.TrimSpace(raw))
		if v == "" {
			continue
		}
		if v == "0" || v == "false" || v == "no" || v == "none" {
			continue
		}
		return true
	}
	return false
}

func isBadStatus(raw string) bool {
	v := strings.ToLower(strings.TrimSpace(raw))
	return strings.Contains(v, "bad") || strings.Contains(v, "invalid")
}

func hasBadChecksum(node map[string]any, layers map[string]any) bool {
	fields := []string{
		findStringByPath(node, "layers.eth.eth_fcs_status"),
		findStringByPath(node, "layers.ip.ip_checksum_status"),
		findStringByPath(node, "layers.tcp.tcp_checksum_status"),
		findStringByPath(node, "layers.udp.udp_checksum_status"),
		findStringByPath(node, "layers.sctp.sctp_checksum_status"),
		findStringByPath(node, "layers.mstp.mstp_checksum_status"),
		findStringByPath(node, "layers.cdp.cdp_checksum_status"),
		findStringByPath(node, "layers.edp.edp_checksum_status"),
		findStringByPath(node, "layers.wlan.wlan_fcs_status"),
		findStringByPath(node, "layers.stt.stt_checksum_status"),
		findBySuffix(layers, "ethfcsstatus"),
		findBySuffix(layers, "ipchecksumstatus"),
		findBySuffix(layers, "tcpchecksumstatus"),
		findBySuffix(layers, "udpchecksumstatus"),
		findBySuffix(layers, "sctpchecksumstatus"),
		findBySuffix(layers, "mstpchecksumstatus"),
		findBySuffix(layers, "cdpchecksumstatus"),
		findBySuffix(layers, "edpchecksumstatus"),
		findBySuffix(layers, "wlanfcsstatus"),
		findBySuffix(layers, "sttchecksumstatus"),
	}
	for _, f := range fields {
		if isBadStatus(f) {
			return true
		}
	}
	return false
}

func parseInt(raw string) int {
	if v, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil {
		return v
	}
	return 0
}

func parseInt64(raw string) int64 {
	if v, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64); err == nil {
		return v
	}
	return 0
}

func FirstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

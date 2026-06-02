package tshark

import (
	"strconv"
	"strings"
	"time"
)

func normalizeProto(proto string) string {
	p := strings.ToLower(proto)
	switch {
	case strings.Contains(p, "websocket"):
		return "WebSocket"
	case strings.Contains(p, "http"):
		return "HTTP"
	case strings.Contains(p, "usb"):
		return "USB"
	case strings.Contains(p, "icmpv6"):
		return "ICMPV6"
	case strings.Contains(p, "icmp"):
		return "ICMP"
	case strings.Contains(p, "arp"):
		return "ARP"
	case strings.Contains(p, "tls"):
		return "TLS"
	case strings.Contains(p, "dns"):
		return "DNS"
	case strings.Contains(p, "ssh"):
		return "SSHv2"
	case strings.Contains(p, "udp"):
		return "UDP"
	case strings.Contains(p, "tcp"):
		return "TCP"
	default:
		return "OTHER"
	}
}

func resolveDisplayProtocol(displayProtocol string, fallback string) string {
	if trimmed := strings.TrimSpace(displayProtocol); trimmed != "" {
		return trimmed
	}
	if normalized := normalizeProto(fallback); normalized != "OTHER" {
		return normalized
	}
	return "OTHER"
}

func normalizeTimestamp(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return t.Format("15:04:05.000000")
	}

	if ms, err := strconv.ParseInt(raw, 10, 64); err == nil {
		if len(raw) >= 13 {
			return time.UnixMilli(ms).UTC().Format("15:04:05.000")
		}
		return time.Unix(ms, 0).UTC().Format("15:04:05")
	}

	if sec, err := strconv.ParseFloat(raw, 64); err == nil {
		whole := int64(sec)
		ns := int64((sec - float64(whole)) * float64(time.Second))
		if ns < 0 {
			ns = 0
		}
		return time.Unix(whole, ns).UTC().Format("15:04:05.000000")
	}

	return raw
}

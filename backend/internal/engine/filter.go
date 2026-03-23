package engine

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

type packetPredicate func(model.Packet) bool

var (
	packetFilterOrRE          = regexp.MustCompile(`(?i)\s+or\s+`)
	packetFilterAndRE         = regexp.MustCompile(`(?i)\s+and\s+`)
	packetFilterCompareRE     = regexp.MustCompile(`^\s*(.+?)\s*(==|!=|>=|<=|>|<)\s*(.+?)\s*$`)
	httpStatusPrefixRE        = regexp.MustCompile(`^\s*(\d{3})\b`)
	quotedPacketFilterValueRE = regexp.MustCompile(`^["'](.*)["']$`)
)

func compilePacketFilter(filter string) packetPredicate {
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return nil
	}

	orParts := splitFilter(packetFilterOrRE, filter)
	return func(packet model.Packet) bool {
		for _, orPart := range orParts {
			andParts := splitFilter(packetFilterAndRE, orPart)
			matched := true
			for _, token := range andParts {
				negated := false
				token = strings.TrimSpace(token)
				if strings.HasPrefix(strings.ToLower(token), "not ") {
					negated = true
					token = strings.TrimSpace(token[4:])
				}
				ok := matchPacketToken(packet, token)
				if negated {
					ok = !ok
				}
				if !ok {
					matched = false
					break
				}
			}
			if matched {
				return true
			}
		}
		return false
	}
}

func splitFilter(re *regexp.Regexp, input string) []string {
	parts := re.Split(input, -1)
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func matchPacketToken(packet model.Packet, token string) bool {
	token = strings.TrimSpace(token)
	if token == "" {
		return true
	}

	lower := strings.ToLower(token)
	if strings.Contains(lower, " contains ") {
		parts := strings.SplitN(token, " contains ", 2)
		if len(parts) != 2 {
			parts = strings.SplitN(lower, " contains ", 2)
		}
		if len(parts) == 2 {
			field := strings.TrimSpace(strings.ToLower(parts[0]))
			value := normalizePacketFilterValue(parts[1])
			return packetFieldContains(packet, field, value)
		}
	}

	if match := packetFilterCompareRE.FindStringSubmatch(token); len(match) == 4 {
		field := strings.TrimSpace(strings.ToLower(match[1]))
		op := match[2]
		value := normalizePacketFilterValue(match[3])
		return comparePacketField(packet, field, op, value)
	}

	switch lower {
	case "http":
		return packet.Protocol == "HTTP"
	case "tcp":
		return packet.Protocol == "TCP"
	case "udp":
		return packet.Protocol == "UDP"
	case "dns":
		return packet.Protocol == "DNS"
	case "tls", "https":
		return packet.Protocol == "TLS" || packet.Protocol == "HTTPS"
	case "arp":
		return packet.Protocol == "ARP"
	case "icmp":
		return packet.Protocol == "ICMP" || packet.Protocol == "ICMPV6"
	case "ip", "ipv6":
		return packet.SourceIP != "" || packet.DestIP != ""
	}

	return packetFieldContains(packet, "", normalizePacketFilterValue(token))
}

func normalizePacketFilterValue(value string) string {
	value = strings.TrimSpace(value)
	if match := quotedPacketFilterValueRE.FindStringSubmatch(value); len(match) == 2 {
		return match[1]
	}
	return value
}

func packetFieldContains(packet model.Packet, field string, value string) bool {
	valueLower := strings.ToLower(value)
	switch field {
	case "", "frame", "info", "payload", "http.host", "http.request.uri", "http.request", "http.response":
		return strings.Contains(strings.ToLower(packet.Info), valueLower) || strings.Contains(strings.ToLower(packet.Payload), valueLower)
	case "ip.src":
		return strings.Contains(strings.ToLower(packet.SourceIP), valueLower)
	case "ip.dst":
		return strings.Contains(strings.ToLower(packet.DestIP), valueLower)
	case "ip.addr":
		return strings.Contains(strings.ToLower(packet.SourceIP), valueLower) || strings.Contains(strings.ToLower(packet.DestIP), valueLower)
	case "protocol", "_ws.col.protocol":
		return strings.Contains(strings.ToLower(packet.Protocol), valueLower) ||
			strings.Contains(strings.ToLower(packet.DisplayProtocol), valueLower)
	case "http.request.method":
		return strings.Contains(strings.ToLower(httpMethod(packet)), valueLower)
	default:
		return strings.Contains(strings.ToLower(packet.Info), valueLower) ||
			strings.Contains(strings.ToLower(packet.Payload), valueLower) ||
			strings.Contains(strings.ToLower(packet.SourceIP), valueLower) ||
			strings.Contains(strings.ToLower(packet.DestIP), valueLower) ||
			strings.Contains(strings.ToLower(packet.Protocol), valueLower) ||
			strings.Contains(strings.ToLower(packet.DisplayProtocol), valueLower)
	}
}

func comparePacketField(packet model.Packet, field string, op string, value string) bool {
	switch field {
	case "ip.src":
		return compareString(packet.SourceIP, op, value)
	case "ip.dst":
		return compareString(packet.DestIP, op, value)
	case "ip.addr":
		return compareString(packet.SourceIP, op, value) || compareString(packet.DestIP, op, value)
	case "http.request.method":
		return compareString(httpMethod(packet), op, strings.ToUpper(value))
	case "http.response.code":
		return compareInt(httpStatusCode(packet), op, parseFilterInt(value))
	case "frame.len":
		return compareInt(packet.Length, op, parseFilterInt(value))
	case "frame.number":
		return compareInt64(packet.ID, op, parseFilterInt64(value))
	case "tcp.port", "udp.port", "port":
		valueInt := parseFilterInt(value)
		return compareInt(packet.SourcePort, op, valueInt) || compareInt(packet.DestPort, op, valueInt)
	default:
		return compareString(packet.Info, op, value) || compareString(packet.Payload, op, value)
	}
}

func compareString(actual string, op string, expected string) bool {
	switch op {
	case "==":
		return strings.EqualFold(strings.TrimSpace(actual), strings.TrimSpace(expected))
	case "!=":
		return !strings.EqualFold(strings.TrimSpace(actual), strings.TrimSpace(expected))
	default:
		return false
	}
}

func compareInt(actual int, op string, expected int) bool {
	switch op {
	case "==":
		return actual == expected
	case "!=":
		return actual != expected
	case ">":
		return actual > expected
	case "<":
		return actual < expected
	case ">=":
		return actual >= expected
	case "<=":
		return actual <= expected
	default:
		return false
	}
}

func compareInt64(actual int64, op string, expected int64) bool {
	switch op {
	case "==":
		return actual == expected
	case "!=":
		return actual != expected
	case ">":
		return actual > expected
	case "<":
		return actual < expected
	case ">=":
		return actual >= expected
	case "<=":
		return actual <= expected
	default:
		return false
	}
}

func parseFilterInt(raw string) int {
	v, _ := strconv.Atoi(strings.TrimSpace(raw))
	return v
}

func parseFilterInt64(raw string) int64 {
	v, _ := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	return v
}

func httpMethod(packet model.Packet) string {
	info := strings.TrimSpace(packet.Info)
	if info == "" {
		return ""
	}
	first := strings.Fields(info)
	if len(first) == 0 {
		return ""
	}
	method := strings.ToUpper(strings.TrimSpace(first[0]))
	switch method {
	case "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH":
		return method
	default:
		return ""
	}
}

func httpStatusCode(packet model.Packet) int {
	match := httpStatusPrefixRE.FindStringSubmatch(strings.TrimSpace(packet.Info))
	if len(match) != 2 {
		return 0
	}
	v, _ := strconv.Atoi(match[1])
	return v
}

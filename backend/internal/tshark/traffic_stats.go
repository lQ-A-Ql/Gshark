package tshark

import (
	"bufio"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gshark/sentinel/backend/internal/model"
)

func BuildGlobalTrafficStatsFromFile(filePath string) (model.GlobalTrafficStats, error) {
	stats := model.GlobalTrafficStats{}

	args := []string{
		"-n",
		"-r", filePath,
		"-T", "fields",
		"-E", "separator=\t",
		"-E", "occurrence=f",
		"-E", "quote=n",
		"-e", "frame.time_epoch",
		"-e", "_ws.col.Protocol",
		"-e", "ip.src",
		"-e", "ipv6.src",
		"-e", "arp.src.proto_ipv4",
		"-e", "ip.dst",
		"-e", "ipv6.dst",
		"-e", "arp.dst.proto_ipv4",
		"-e", "http.host",
		"-e", "tls.handshake.extensions_server_name",
		"-e", "dns.qry.name",
		"-e", "nbns.name",
		"-e", "nbns.netbios_name",
		"-e", "dhcp.option.hostname",
		"-e", "browser.server",
		"-e", "browser.response_computer_name",
		"-e", "browser.backup.server",
		"-e", "smb_netlogon.computer_name",
		"-e", "smb_netlogon.unicode_computer_name",
		"-e", "netlogon.secchan.nl_auth_message.nb_host",
		"-e", "netlogon.secchan.nl_auth_message.nb_host_utf8",
		"-e", "tcp.dstport",
		"-e", "udp.dstport",
		"-e", "tcp.srcport",
		"-e", "udp.srcport",
	}

	cmd, err := Command(args...)
	if err != nil {
		return stats, fmt.Errorf("resolve tshark: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return stats, fmt.Errorf("create stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return stats, fmt.Errorf("start tshark: %w", err)
	}

	timelineMap := make(map[string]int)
	protocolMap := make(map[string]int)
	talkerMap := make(map[string]int)
	domainMap := make(map[string]int)
	srcIPMap := make(map[string]int)
	dstIPMap := make(map[string]int)
	computerNameMap := make(map[string]int)
	destPortMap := make(map[string]int)
	srcPortMap := make(map[string]int)

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		parts := strings.Split(line, "\t")
		if len(parts) < 2 {
			continue
		}

		stats.TotalPackets++

		epochText := strings.TrimSpace(parts[0])
		if secLabel := toSecondLabel(epochText); secLabel != "" {
			timelineMap[secLabel]++
		}

		protocol := strings.ToUpper(strings.TrimSpace(parts[1]))
		if protocol == "" {
			protocol = "OTHER"
		}
		protocolMap[protocol]++

		src := FirstNonEmpty(safeTrim(parts, 2), safeTrim(parts, 3), safeTrim(parts, 4))
		dst := FirstNonEmpty(safeTrim(parts, 5), safeTrim(parts, 6), safeTrim(parts, 7))
		if src == "" && dst == "" {
			talkerMap["unknown"]++
		} else {
			if src != "" {
				talkerMap[src]++
			}
			if dst != "" {
				talkerMap[dst]++
			}
		}
		if src != "" {
			srcIPMap[src]++
		}
		if dst != "" {
			dstIPMap[dst]++
		}

		// 收集域名 (HTTP Host, TLS SNI, DNS Query)
		domain := normalizeDomain(FirstNonEmpty(
			safeTrim(parts, 8),  // http.host
			safeTrim(parts, 9),  // tls.handshake.extensions_server_name
			safeTrim(parts, 10), // dns.qry.name
		))
		if domain != "" {
			domainMap[domain]++
		}

		computerName := normalizeComputerName(FirstNonEmpty(
			safeTrim(parts, 11), // nbns.name
			safeTrim(parts, 12), // nbns.netbios_name
			safeTrim(parts, 13), // dhcp.option.hostname
			safeTrim(parts, 14), // browser.server
			safeTrim(parts, 15), // browser.response_computer_name
			safeTrim(parts, 16), // browser.backup.server
			safeTrim(parts, 17), // smb_netlogon.computer_name
			safeTrim(parts, 18), // smb_netlogon.unicode_computer_name
			safeTrim(parts, 19), // netlogon.secchan.nl_auth_message.nb_host
			safeTrim(parts, 20), // netlogon.secchan.nl_auth_message.nb_host_utf8
		))
		if computerName != "" {
			computerNameMap[computerName]++
		}

		// 收集目标端口
		dstPort := safeTrim(parts, 21) // tcp.dstport
		if dstPort == "" {
			dstPort = safeTrim(parts, 22) // udp.dstport
		}
		if dstPort != "" {
			destPortMap[dstPort]++
		}

		// 收集源端口
		srcPort := safeTrim(parts, 23) // tcp.srcport
		if srcPort == "" {
			srcPort = safeTrim(parts, 24) // udp.srcport
		}
		if srcPort != "" {
			srcPortMap[srcPort]++
		}
	}

	if err := scanner.Err(); err != nil {
		_ = cmd.Wait()
		return stats, fmt.Errorf("scan tshark output: %w", err)
	}

	if err := cmd.Wait(); err != nil {
		return stats, fmt.Errorf("wait tshark: %w", err)
	}

	stats.ProtocolKinds = len(protocolMap)
	stats.Timeline = sortTimelineBuckets(timelineMap, 0)
	stats.ProtocolDist = topBuckets(protocolMap, 0)
	stats.TopTalkers = topBuckets(talkerMap, 0)
	stats.TopHostnames = topBuckets(domainMap, 0)
	stats.TopDomains = topBuckets(domainMap, 0)
	stats.TopSrcIPs = topBuckets(srcIPMap, 0)
	stats.TopDstIPs = topBuckets(dstIPMap, 0)
	stats.TopComputerNames = topBuckets(computerNameMap, 0)
	stats.TopDestPorts = topBuckets(destPortMap, 0)
	stats.TopSrcPorts = topBuckets(srcPortMap, 0)
	return stats, nil
}

func toSecondLabel(epochText string) string {
	if epochText == "" {
		return ""
	}
	v, err := strconv.ParseFloat(epochText, 64)
	if err != nil {
		return ""
	}
	sec := int64(v)
	return time.Unix(sec, 0).UTC().Format("15:04:05")
}

func sortTimelineBuckets(input map[string]int, tail int) []model.TrafficBucket {
	items := make([]model.TrafficBucket, 0, len(input))
	for label, count := range input {
		items = append(items, model.TrafficBucket{Label: label, Count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].Label < items[j].Label
	})
	if tail > 0 && len(items) > tail {
		return items[len(items)-tail:]
	}
	return items
}

func topBuckets(input map[string]int, limit int) []model.TrafficBucket {
	items := make([]model.TrafficBucket, 0, len(input))
	for label, count := range input {
		items = append(items, model.TrafficBucket{Label: label, Count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count == items[j].Count {
			return items[i].Label < items[j].Label
		}
		return items[i].Count > items[j].Count
	})
	if limit > 0 && len(items) > limit {
		return items[:limit]
	}
	return items
}

func safeTrim(parts []string, idx int) string {
	if idx < 0 || idx >= len(parts) {
		return ""
	}
	return strings.TrimSpace(parts[idx])
}

func normalizeDomain(value string) string {
	value = strings.TrimSpace(strings.TrimSuffix(value, "."))
	if value == "" {
		return ""
	}
	return strings.ToLower(value)
}

func normalizeComputerName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if idx := strings.Index(value, "<"); idx > 0 && strings.HasSuffix(value, ">") {
		value = strings.TrimSpace(value[:idx])
	}
	value = strings.Trim(value, "\x00 ")
	if value == "" {
		return ""
	}
	return strings.ToUpper(value)
}

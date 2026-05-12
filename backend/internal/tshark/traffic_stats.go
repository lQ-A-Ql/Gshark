package tshark

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gshark/sentinel/backend/internal/model"
)

var globalTrafficStatsFields = []string{
	"frame.time_epoch",
	"_ws.col.Protocol",
	"ip.src",
	"ipv6.src",
	"arp.src.proto_ipv4",
	"ip.dst",
	"ipv6.dst",
	"arp.dst.proto_ipv4",
	"http.host",
	"tls.handshake.extensions_server_name",
	"dns.qry.name",
	"nbns.name",
	"nbns.netbios_name",
	"dhcp.option.hostname",
	"browser.server",
	"browser.response_computer_name",
	"browser.backup.server",
	"smb_netlogon.computer_name",
	"smb_netlogon.unicode_computer_name",
	"netlogon.secchan.nl_auth_message.nb_host",
	"netlogon.secchan.nl_auth_message.nb_host_utf8",
	"tcp.dstport",
	"udp.dstport",
	"tcp.srcport",
	"udp.srcport",
}

type globalTrafficStatsAccumulator struct {
	stats           model.GlobalTrafficStats
	timelineMap     map[string]int
	protocolMap     map[string]int
	talkerMap       map[string]int
	domainMap       map[string]int
	srcIPMap        map[string]int
	dstIPMap        map[string]int
	computerNameMap map[string]int
	destPortMap     map[string]int
	srcPortMap      map[string]int
}

func BuildGlobalTrafficStatsFromFile(filePath string) (model.GlobalTrafficStats, error) {
	acc := newGlobalTrafficStatsAccumulator()
	err := scanFieldRows(filePath, globalTrafficStatsFields, acc.consumeRow)
	if err != nil {
		return model.GlobalTrafficStats{}, err
	}
	return acc.finish(), nil
}

func newGlobalTrafficStatsAccumulator() *globalTrafficStatsAccumulator {
	return &globalTrafficStatsAccumulator{
		timelineMap:     map[string]int{},
		protocolMap:     map[string]int{},
		talkerMap:       map[string]int{},
		domainMap:       map[string]int{},
		srcIPMap:        map[string]int{},
		dstIPMap:        map[string]int{},
		computerNameMap: map[string]int{},
		destPortMap:     map[string]int{},
		srcPortMap:      map[string]int{},
	}
}

func (a *globalTrafficStatsAccumulator) consumeRow(parts []string) {
	if len(parts) < 2 {
		return
	}
	a.stats.TotalPackets++

	epochText := strings.TrimSpace(parts[0])
	if secLabel := toSecondLabel(epochText); secLabel != "" {
		a.timelineMap[secLabel]++
	}

	protocol := strings.ToUpper(strings.TrimSpace(parts[1]))
	if protocol == "" {
		protocol = "OTHER"
	}
	a.protocolMap[protocol]++

	src := FirstNonEmpty(safeTrim(parts, 2), safeTrim(parts, 3), safeTrim(parts, 4))
	dst := FirstNonEmpty(safeTrim(parts, 5), safeTrim(parts, 6), safeTrim(parts, 7))
	if src == "" && dst == "" {
		a.talkerMap["unknown"]++
	} else {
		if src != "" {
			a.talkerMap[src]++
		}
		if dst != "" {
			a.talkerMap[dst]++
		}
	}
	if src != "" {
		a.srcIPMap[src]++
	}
	if dst != "" {
		a.dstIPMap[dst]++
	}

	domain := normalizeDomain(FirstNonEmpty(
		safeTrim(parts, 8),
		safeTrim(parts, 9),
		safeTrim(parts, 10),
	))
	if domain != "" {
		a.domainMap[domain]++
	}

	computerName := normalizeComputerName(FirstNonEmpty(
		safeTrim(parts, 11),
		safeTrim(parts, 12),
		safeTrim(parts, 13),
		safeTrim(parts, 14),
		safeTrim(parts, 15),
		safeTrim(parts, 16),
		safeTrim(parts, 17),
		safeTrim(parts, 18),
		safeTrim(parts, 19),
		safeTrim(parts, 20),
	))
	if computerName != "" {
		a.computerNameMap[computerName]++
	}

	dstPort := FirstNonEmpty(safeTrim(parts, 21), safeTrim(parts, 22))
	if dstPort != "" {
		a.destPortMap[dstPort]++
	}

	srcPort := FirstNonEmpty(safeTrim(parts, 23), safeTrim(parts, 24))
	if srcPort != "" {
		a.srcPortMap[srcPort]++
	}
}

func (a *globalTrafficStatsAccumulator) finish() model.GlobalTrafficStats {
	stats := a.stats
	stats.ProtocolKinds = len(a.protocolMap)
	stats.Timeline = sortTimelineBuckets(a.timelineMap, 0)
	stats.ProtocolDist = topBuckets(a.protocolMap, 0)
	stats.TopTalkers = topBuckets(a.talkerMap, 0)
	stats.TopHostnames = topBuckets(a.domainMap, 0)
	stats.TopDomains = topBuckets(a.domainMap, 0)
	stats.TopSrcIPs = topBuckets(a.srcIPMap, 0)
	stats.TopDstIPs = topBuckets(a.dstIPMap, 0)
	stats.TopComputerNames = topBuckets(a.computerNameMap, 0)
	stats.TopDestPorts = topBuckets(a.destPortMap, 0)
	stats.TopSrcPorts = topBuckets(a.srcPortMap, 0)
	return stats
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

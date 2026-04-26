package tshark

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

var knownModbusFunctionCodes = map[int]bool{
	1:  true,
	2:  true,
	3:  true,
	4:  true,
	5:  true,
	6:  true,
	15: true,
	16: true,
	22: true,
	23: true,
	43: true,
}

func buildIndustrialRuleHits(stats model.IndustrialAnalysis) []model.IndustrialRuleHit {
	hits := make([]model.IndustrialRuleHit, 0, 16)
	hits = append(hits, buildModbusRoleRuleHits(stats.Modbus.Transactions)...)
	hits = append(hits, buildModbusFunctionMutationRuleHits(stats.Modbus.Transactions)...)
	hits = append(hits, buildModbusFunctionCodeRuleHits(stats.Modbus.Transactions)...)
	hits = append(hits, buildModbusExceptionRuleHits(stats.Modbus.Transactions)...)
	hits = append(hits, buildModbusQuantityRuleHits(stats.Modbus.Transactions)...)
	hits = append(hits, buildModbusBitLengthRuleHits(stats.Modbus.Transactions)...)
	hits = append(hits, buildModbusWriteBurstRuleHits(stats.SuspiciousWrites)...)
	sort.SliceStable(hits, func(i, j int) bool {
		left := industrialRuleLevelWeight(hits[i].Level)
		right := industrialRuleLevelWeight(hits[j].Level)
		if left != right {
			return left > right
		}
		if hits[i].PacketID != hits[j].PacketID {
			return hits[i].PacketID < hits[j].PacketID
		}
		return hits[i].Rule < hits[j].Rule
	})
	return hits
}

func buildModbusFunctionMutationRuleHits(transactions []model.ModbusTransaction) []model.IndustrialRuleHit {
	type mutationWindow struct {
		lastFunctionCode int
		lastFunctionName string
		lastPacketID     int64
		lastTime         string
		lastTarget       string
		lastSource       string
		mutationCount    int
	}

	if len(transactions) == 0 {
		return nil
	}

	windows := make(map[string]mutationWindow)
	hits := make([]model.IndustrialRuleHit, 0, 8)
	for _, tx := range transactions {
		if tx.Kind != "request" || tx.FunctionCode <= 0 {
			continue
		}
		endpoint := strings.TrimSpace(tx.Source)
		target := strings.TrimSpace(FirstNonEmpty(tx.Destination, tx.Reference))
		if endpoint == "" || target == "" {
			continue
		}
		key := endpoint + "|" + target
		window := windows[key]
		if window.lastFunctionCode > 0 && window.lastFunctionCode != tx.FunctionCode {
			window.mutationCount++
			level := "warning"
			if window.mutationCount >= 2 {
				level = "high"
			}
			hits = append(hits, model.IndustrialRuleHit{
				Rule:         "功能码突变",
				Level:        level,
				PacketID:     tx.PacketID,
				Time:         tx.Time,
				Source:       tx.Source,
				Destination:  tx.Destination,
				FunctionCode: tx.FunctionCode,
				FunctionName: tx.FunctionName,
				Target:       tx.Reference,
				Evidence: joinRuleEvidence(
					fmt.Sprintf("上一个请求 #%d %s(%d)", window.lastPacketID, FirstNonEmpty(window.lastFunctionName, "unknown"), window.lastFunctionCode),
					fmt.Sprintf("当前请求 #%d %s(%d)", tx.PacketID, FirstNonEmpty(tx.FunctionName, "unknown"), tx.FunctionCode),
				),
				Summary: fmt.Sprintf("源 %s 对目标 %s 的 Modbus 请求功能码在短序列内发生切换，可能对应扫描阶段转写入阶段、探测后利用或控制策略突变。", endpoint, target),
			})
		}
		windows[key] = mutationWindow{
			lastFunctionCode: tx.FunctionCode,
			lastFunctionName: tx.FunctionName,
			lastPacketID:     tx.PacketID,
			lastTime:         tx.Time,
			lastTarget:       tx.Reference,
			lastSource:       tx.Source,
			mutationCount:    window.mutationCount,
		}
	}
	return hits
}

func buildModbusRoleRuleHits(transactions []model.ModbusTransaction) []model.IndustrialRuleHit {
	if len(transactions) == 0 {
		return nil
	}
	masterCounts := make(map[string]int)
	slaveCounts := make(map[string]int)
	targetMasters := make(map[string]map[string]int)

	for _, tx := range transactions {
		if tx.Kind != "request" {
			continue
		}
		if strings.TrimSpace(tx.Source) != "" {
			masterCounts[tx.Source]++
		}
		if strings.TrimSpace(tx.Destination) != "" {
			slaveCounts[tx.Destination]++
		}
		target := FirstNonEmpty(strings.TrimSpace(tx.Destination), strings.TrimSpace(tx.Reference))
		if target == "" || strings.TrimSpace(tx.Source) == "" {
			continue
		}
		if targetMasters[target] == nil {
			targetMasters[target] = map[string]int{}
		}
		targetMasters[target][tx.Source]++
	}

	hits := make([]model.IndustrialRuleHit, 0, 4)
	topMaster, topMasterCount := topStringCount(masterCounts)
	topSlave, topSlaveCount := topStringCount(slaveCounts)
	if topMaster != "" || topSlave != "" {
		hits = append(hits, model.IndustrialRuleHit{
			Rule:   "主从角色推断",
			Level:  "info",
			Source: topMaster,
			Target: topSlave,
			Evidence: joinRuleEvidence(
				fmt.Sprintf("主站候选 %s (%d 次请求)", FirstNonEmpty(topMaster, "unknown"), topMasterCount),
				fmt.Sprintf("从站候选 %s (%d 次被访问)", FirstNonEmpty(topSlave, "unknown"), topSlaveCount),
			),
			Summary: "已根据 Modbus 请求方向推断主从角色，可据此快速定位控制端和被控设备。",
		})
	}

	for target, masters := range targetMasters {
		if len(masters) <= 1 {
			continue
		}
		participants := make([]string, 0, len(masters))
		for master, count := range masters {
			participants = append(participants, fmt.Sprintf("%s(%d)", master, count))
		}
		sort.Strings(participants)
		hits = append(hits, model.IndustrialRuleHit{
			Rule:     "多主站竞争",
			Level:    "warning",
			Target:   target,
			Evidence: "命中主站: " + strings.Join(participants, ", "),
			Summary:  fmt.Sprintf("同一目标 %s 被多个源主机发起 Modbus 请求，可能存在主站冲突、接管或伪造控制。", target),
		})
	}

	return hits
}

func buildModbusFunctionCodeRuleHits(transactions []model.ModbusTransaction) []model.IndustrialRuleHit {
	hits := make([]model.IndustrialRuleHit, 0, 8)
	for _, tx := range transactions {
		if tx.FunctionCode <= 0 {
			continue
		}
		if knownModbusFunctionCodes[tx.FunctionCode] {
			continue
		}
		hits = append(hits, model.IndustrialRuleHit{
			Rule:         "未知功能码",
			Level:        "high",
			PacketID:     tx.PacketID,
			Time:         tx.Time,
			Source:       tx.Source,
			Destination:  tx.Destination,
			FunctionCode: tx.FunctionCode,
			FunctionName: tx.FunctionName,
			Target:       tx.Reference,
			Evidence:     FirstNonEmpty(tx.Summary, fmt.Sprintf("FC %d", tx.FunctionCode)),
			Summary:      fmt.Sprintf("包 #%d 使用非常见 Modbus 功能码 %d，建议优先核对是否为厂商私有扩展、混淆数据或异常命令。", tx.PacketID, tx.FunctionCode),
		})
	}
	return hits
}

func buildModbusExceptionRuleHits(transactions []model.ModbusTransaction) []model.IndustrialRuleHit {
	hits := make([]model.IndustrialRuleHit, 0, 8)
	for _, tx := range transactions {
		if tx.Kind != "exception" {
			continue
		}
		level := "warning"
		if tx.ExceptionCode == 1 || tx.ExceptionCode == 2 || tx.ExceptionCode == 3 || tx.ExceptionCode == 4 {
			level = "high"
		}
		hits = append(hits, model.IndustrialRuleHit{
			Rule:         "异常响应",
			Level:        level,
			PacketID:     tx.PacketID,
			Time:         tx.Time,
			Source:       tx.Source,
			Destination:  tx.Destination,
			FunctionCode: tx.FunctionCode,
			FunctionName: tx.FunctionName,
			Target:       tx.Reference,
			Evidence:     fmt.Sprintf("异常码 0x%02X (%s)", tx.ExceptionCode, modbusExceptionName(tx.ExceptionCode)),
			Summary:      fmt.Sprintf("包 #%d 返回 Modbus 异常响应，可能表示非法功能、越界地址或异常控制链路。", tx.PacketID),
		})
	}
	return hits
}

func buildModbusQuantityRuleHits(transactions []model.ModbusTransaction) []model.IndustrialRuleHit {
	hits := make([]model.IndustrialRuleHit, 0, 8)
	for _, tx := range transactions {
		quantity, ok := parseOptionalFlexibleInt(tx.Quantity)
		if !ok {
			continue
		}
		if quantity <= 0 {
			hits = append(hits, model.IndustrialRuleHit{
				Rule:         "非法数量字段",
				Level:        "warning",
				PacketID:     tx.PacketID,
				Time:         tx.Time,
				Source:       tx.Source,
				Destination:  tx.Destination,
				FunctionCode: tx.FunctionCode,
				FunctionName: tx.FunctionName,
				Target:       tx.Reference,
				Evidence:     "quantity=" + tx.Quantity,
				Summary:      fmt.Sprintf("包 #%d 的 Modbus 数量字段异常，可能存在构造错误、越界读写或工具伪造。", tx.PacketID),
			})
			continue
		}
		limit, hasLimit := expectedModbusQuantityLimit(tx.FunctionCode)
		if !hasLimit || quantity <= limit {
			continue
		}
		hits = append(hits, model.IndustrialRuleHit{
			Rule:         "数量越界",
			Level:        "high",
			PacketID:     tx.PacketID,
			Time:         tx.Time,
			Source:       tx.Source,
			Destination:  tx.Destination,
			FunctionCode: tx.FunctionCode,
			FunctionName: tx.FunctionName,
			Target:       tx.Reference,
			Evidence:     fmt.Sprintf("quantity=%d, 常见上限=%d", quantity, limit),
			Summary:      fmt.Sprintf("包 #%d 的 Modbus 数量字段超过常见协议上限，疑似越界扫描、畸形报文或异常写入。", tx.PacketID),
		})
	}
	return hits
}

func buildModbusBitLengthRuleHits(transactions []model.ModbusTransaction) []model.IndustrialRuleHit {
	hits := make([]model.IndustrialRuleHit, 0, 8)
	for _, tx := range transactions {
		if tx.BitRange == nil || tx.BitRange.Count == nil {
			continue
		}
		quantity, ok := parseOptionalFlexibleInt(tx.Quantity)
		if !ok || quantity <= 0 {
			continue
		}
		if *tx.BitRange.Count == quantity {
			continue
		}
		hits = append(hits, model.IndustrialRuleHit{
			Rule:         "长度不一致",
			Level:        "warning",
			PacketID:     tx.PacketID,
			Time:         tx.Time,
			Source:       tx.Source,
			Destination:  tx.Destination,
			FunctionCode: tx.FunctionCode,
			FunctionName: tx.FunctionName,
			Target:       tx.Reference,
			Evidence:     fmt.Sprintf("quantity=%d, bit_count=%d", quantity, *tx.BitRange.Count),
			Summary:      fmt.Sprintf("包 #%d 的 Modbus 数量字段与实际位值长度不一致，需关注是否存在拆包、截断或构造异常。", tx.PacketID),
		})
	}
	return hits
}

func buildModbusWriteBurstRuleHits(writes []model.ModbusSuspiciousWrite) []model.IndustrialRuleHit {
	hits := make([]model.IndustrialRuleHit, 0, len(writes))
	for _, write := range writes {
		if write.WriteCount < 3 {
			continue
		}
		level := "warning"
		if write.WriteCount >= 8 {
			level = "high"
		}
		hits = append(hits, model.IndustrialRuleHit{
			Rule:         "高频写入",
			Level:        level,
			PacketID:     write.SamplePacketID,
			FunctionCode: write.FunctionCode,
			FunctionName: write.FunctionName,
			Target:       write.Target,
			Source:       strings.Join(write.Sources, ", "),
			Time:         FirstNonEmpty(write.FirstTime, write.LastTime),
			Evidence:     fmt.Sprintf("写入 %d 次，时间窗口 %s ~ %s", write.WriteCount, FirstNonEmpty(write.FirstTime, "--"), FirstNonEmpty(write.LastTime, "--")),
			Summary:      fmt.Sprintf("目标 %s 存在高频 Modbus 写入，可能对应自动控制切换、寄存器爆破或异常脚本重放。", write.Target),
		})
	}
	return hits
}

func expectedModbusQuantityLimit(functionCode int) (int, bool) {
	switch functionCode {
	case 1, 2:
		return 2000, true
	case 3, 4:
		return 125, true
	case 15:
		return 1968, true
	case 16, 23:
		return 123, true
	default:
		return 0, false
	}
}

func industrialRuleLevelWeight(level string) int {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "warning":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

func topStringCount(items map[string]int) (string, int) {
	bestLabel := ""
	bestCount := 0
	for label, count := range items {
		if count > bestCount || (count == bestCount && bestLabel == "") {
			bestLabel = label
			bestCount = count
		}
	}
	return bestLabel, bestCount
}

func joinRuleEvidence(values ...string) string {
	filtered := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		filtered = append(filtered, value)
	}
	return strings.Join(filtered, "；")
}

package engine

import "github.com/gshark/sentinel/backend/internal/model"

type reportRuleMetadata struct {
	RuleID            string
	Reason            string
	DefaultConfidence int
	Caveats           []string
}

var reportRuleRegistry = map[string]reportRuleMetadata{
	"usb.mass_storage.write.failed": {
		RuleID:            "usb.mass_storage.write.failed",
		Reason:            "USB Mass Storage 写操作存在失败状态或非零 Data Residue，需要回到 packet 复核写入是否成功。",
		DefaultConfidence: 60,
		Caveats:           []string{"普通挂载流量也可能出现写类操作，需结合状态码、残留长度和上下文判断。"},
	},
	"c2.cs.high_confidence": {
		RuleID:            "c2.cs.high_confidence",
		Reason:            "C2 候选由 family-specific 规则、通信形态或解密结果聚合产生，需回到 packet/stream 复核。",
		DefaultConfidence: 70,
		Caveats:           []string{"CS raw key 通常不能仅从 PCAP 推出；解密结论需结合 TeamServer key 或 RSA 私钥来源。"},
	},
	"c2.vshell.decrypt.hit": {
		RuleID:            "c2.vshell.decrypt.hit",
		Reason:            "C2 候选由 family-specific 规则、通信形态或解密结果聚合产生，需回到 packet/stream 复核。",
		DefaultConfidence: 70,
		Caveats:           []string{"VShell 弱信号和解密命中仍需结合密钥来源、stream 方向和明文语义复核。"},
	},
	"c2.family.candidate": {
		RuleID:            "c2.family.candidate",
		Reason:            "C2 候选由 family-specific 规则、通信形态或解密结果聚合产生，需回到 packet/stream 复核。",
		DefaultConfidence: 45,
		Caveats:           []string{"未知 C2 family 候选需要结合通信上下文和样本侧线索复核。"},
	},
	"industrial.rule.hit": {
		RuleID:            "industrial.rule.hit",
		Reason:            "工控规则命中来自协议字段、操作类型或异常响应组合，需结合原始协议帧复核。",
		DefaultConfidence: 58,
		Caveats:           []string{"教学或基线流量可能存在协议操作，不应仅凭单条规则命中判定入侵。"},
	},
	"industrial.modbus.write": {
		RuleID:            "industrial.modbus.write",
		Reason:            "Modbus 写类功能码集中出现，优先复核目标寄存器、来源主机和时间窗口。",
		DefaultConfidence: 58,
		Caveats:           []string{"普通控制任务也可能包含写操作，需结合业务时段和资产角色判断。"},
	},
	"vehicle.uds.security_access": {
		RuleID:            "vehicle.uds.security_access",
		Reason:            "UDS 诊断事务触发安全访问、负响应或高风险服务，需结合请求/响应 packet 复核。",
		DefaultConfidence: 60,
		Caveats:           []string{"车机诊断流量在维修或测试场景中可能正常出现，不能脱离场景直接定性。"},
	},
}

func withReportRuleID(item model.InvestigationReportItem, ruleID string, confidence int) model.InvestigationReportItem {
	meta, ok := reportRuleRegistry[ruleID]
	if !ok {
		return withReportRule(item, ruleID, "", confidence)
	}
	if confidence <= 0 {
		confidence = meta.DefaultConfidence
	}
	return withReportRule(item, meta.RuleID, meta.Reason, confidence, meta.Caveats...)
}

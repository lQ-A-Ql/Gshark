package report

import (
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

type RuleMetadata struct {
	RuleID            string
	Reason            string
	DefaultConfidence int
	Caveats           []string
}

var RuleRegistry = map[string]RuleMetadata{
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
	"http.login.bruteforce": {
		RuleID:            "http.login.bruteforce",
		Reason:            "同一登录端点出现多次失败、用户名变体或密码尝试，需回到 HTTP 请求/响应确认是否为爆破。",
		DefaultConfidence: 75,
		Caveats:           []string{"登录失败也可能来自正常用户重试，需结合时间窗口、来源主机和验证码/限速字段判断。"},
	},
	"http.login.uncertain": {
		RuleID:            "http.login.uncertain",
		Reason:            "登录响应缺少明确成功/失败判据，需要结合同一 stream 前后跳转、Set-Cookie 和 token 下发复核。",
		DefaultConfidence: 50,
		Caveats:           []string{"异步登录、二次验证或前端跳转可能导致响应判定不完整。"},
	},
	"http.login.failure": {
		RuleID:            "http.login.failure",
		Reason:            "登录端点出现连续失败响应，可作为认证异常或爆破前置线索。",
		DefaultConfidence: 42,
		Caveats:           []string{"低频失败通常不足以单独定性，需要结合来源、用户名和时间分布复核。"},
	},
	"smtp.auth.cleartext": {
		RuleID:            "smtp.auth.cleartext",
		Reason:            "SMTP 会话出现明文认证材料或可见密码阶段，需回到 stream 确认账号与投递链。",
		DefaultConfidence: 82,
		Caveats:           []string{"部分测试环境会使用明文 SMTP，仍需结合资产角色和外联方向判断风险。"},
	},
	"smtp.attachment.hint": {
		RuleID:            "smtp.attachment.hint",
		Reason:            "SMTP DATA 或 MIME 边界中出现附件线索，需复核正文、文件名和收件人。",
		DefaultConfidence: 55,
		Caveats:           []string{"附件本身不代表恶意，需结合文件类型、收件人和上下文进一步判断。"},
	},
	"mysql.query.risky": {
		RuleID:            "mysql.query.risky",
		Reason:            "MySQL 查询包含文件写出、账号管理或全局配置等高风险 SQL，需结合响应包确认是否执行成功。",
		DefaultConfidence: 76,
		Caveats:           []string{"管理维护场景也可能出现高权限 SQL，需结合来源主机、账号和业务窗口判断。"},
	},
	"mysql.error.response": {
		RuleID:            "mysql.error.response",
		Reason:            "MySQL 会话返回错误响应，可能对应探测、权限拒绝或高风险 SQL 失败。",
		DefaultConfidence: 52,
		Caveats:           []string{"普通应用错误也会产生 ERR 响应，需要回到对应查询包复核。"},
	},
	"shiro.rememberme.key_hit": {
		RuleID:            "shiro.rememberme.key_hit",
		Reason:            "Shiro rememberMe Cookie 命中候选密钥，说明样本可被已知/输入密钥解密。",
		DefaultConfidence: 88,
		Caveats:           []string{"密钥命中需结合 Cookie 来源、后续会话行为和应用版本确认真实风险。"},
	},
	"shiro.rememberme.deleteme": {
		RuleID:            "shiro.rememberme.deleteme",
		Reason:            "rememberMe 出现 deleteMe 回收痕迹，可能说明服务端拒绝或清理了异常 Cookie。",
		DefaultConfidence: 58,
		Caveats:           []string{"deleteMe 也可能来自正常退出或 Cookie 过期流程，需结合请求上下文复核。"},
	},
	"shiro.rememberme.decoded": {
		RuleID:            "shiro.rememberme.decoded",
		Reason:            "rememberMe Cookie 结构可解码但未命中密钥，仍可作为潜在 Shiro 样本线索。",
		DefaultConfidence: 45,
		Caveats:           []string{"可解码不等于可利用，需补充密钥来源或应用指纹确认。"},
	},
	"iec104.cmd.unauthorized": {
		RuleID:            "iec104.cmd.unauthorized",
		Reason:            "IEC 104 控制方向出现激活命令（COT=act），需回到 packet 复核命令类型、目标地址和操作上下文。",
		DefaultConfidence: 75,
		Caveats:           []string{"正常控制任务也会产生激活命令，需结合业务时段、操作站角色和 SCADA 上下文判断。"},
	},
	"iec104.cmd.deactivation": {
		RuleID:            "iec104.cmd.deactivation",
		Reason:            "IEC 104 控制方向出现去激活命令（COT=deact），可能指示异常停止或服务中断。",
		DefaultConfidence: 58,
		Caveats:           []string{"维护操作也可能触发去激活命令，需结合来源和时间窗口复核。"},
	},
	"iec104.cmd.reset_process": {
		RuleID:            "iec104.cmd.reset_process",
		Reason:            "IEC 104 检测到进程复位命令（C_RP_NA_1），可能用于清除设备状态或规避监控。",
		DefaultConfidence: 78,
		Caveats:           []string{"复位命令在设备维护或固件升级后可能正常出现。"},
	},
	"iec104.cmd.clock_sync": {
		RuleID:            "iec104.cmd.clock_sync",
		Reason:            "IEC 104 检测到时钟同步命令（C_CS_NA_1），可用于篡改事件时间线。",
		DefaultConfidence: 42,
		Caveats:           []string{"时钟同步是正常的 IEC 104 维护操作，需结合来源和频率判断。"},
	},
	"iec104.cot.init": {
		RuleID:            "iec104.cot.init",
		Reason:            "IEC 104 收到初始化原因传输（COT=init），可能指示设备重启或重新上线。",
		DefaultConfidence: 45,
		Caveats:           []string{"设备启动或网络恢复后初始化是正常行为。"},
	},
	"iec104.cot.abnormal": {
		RuleID:            "iec104.cot.abnormal",
		Reason:            "IEC 104 收到异常原因传输值（COT>=44），可能指示协议错误或未知响应。",
		DefaultConfidence: 52,
		Caveats:           []string{"部分设备实现可能使用非标准 COT 值，需结合设备型号和固件版本判断。"},
	},
	"iec104.seq.tx_gap": {
		RuleID:            "iec104.seq.tx_gap",
		Reason:            "IEC 104 发送序列号不连续，可能指示丢包、重传或异常流量注入。",
		DefaultConfidence: 55,
		Caveats:           []string{"网络抖动或 TCP 重传也可能导致序列号跳跃。"},
	},
	"iec104.seq.rx_mismatch": {
		RuleID:            "iec104.seq.rx_mismatch",
		Reason:            "IEC 104 接收序列号与预期不一致，可能指示双向通信异常。",
		DefaultConfidence: 40,
		Caveats:           []string{"初始连接阶段或连接重置后序列号可能不匹配。"},
	},
	"iec104.anomaly": {
		RuleID:            "iec104.anomaly",
		Reason:            "IEC 104 协议检测到通用异常，需回到 packet 复核具体上下文。",
		DefaultConfidence: 35,
		Caveats:           []string{"通用异常需要结合具体规则和协议上下文进一步判断。"},
	},
}

func ApplyRule(item model.InvestigationReportItem, ruleID string, confidence int) model.InvestigationReportItem {
	meta, ok := RuleRegistry[ruleID]
	if !ok {
		if confidence <= 0 {
			confidence = 1
		}
		return applyRuleFields(
			item,
			ruleID,
			"报告规则未登记到 registry，需补充 rule metadata 后再依赖该结论。",
			confidence,
			"unknown report rule metadata; treat as low-confidence until registry is updated",
		)
	}
	if confidence <= 0 {
		confidence = meta.DefaultConfidence
	}
	return applyRuleFields(item, meta.RuleID, meta.Reason, confidence, meta.Caveats...)
}

func applyRuleFields(item model.InvestigationReportItem, ruleID, reason string, confidence int, caveats ...string) model.InvestigationReportItem {
	item.RuleID = strings.TrimSpace(ruleID)
	item.Reason = strings.TrimSpace(reason)
	if confidence > 0 {
		item.Confidence = clampConfidence(confidence)
	}
	item.Caveats = dedupeNonEmpty(caveats)
	return item
}

func clampConfidence(value int) int {
	switch {
	case value < 0:
		return 0
	case value > 100:
		return 100
	default:
		return value
	}
}

func dedupeNonEmpty(items []string) []string {
	out := []string{}
	seen := map[string]struct{}{}
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

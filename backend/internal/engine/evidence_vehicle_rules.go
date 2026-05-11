package engine

import (
	"fmt"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

func vehicleEvidenceConfidence(tx model.UDSTransaction) (int, bool) {
	serviceID := normalizeServiceID(tx.ServiceID)
	base, riskyService := udsServiceEvidenceBase(serviceID)
	status := strings.ToLower(strings.TrimSpace(tx.Status))

	if tx.NegativeCode != "" {
		if base == 0 {
			base = 66
		}
		if riskyService {
			base += 6
		}
		return clampConfidence(base), true
	}

	switch status {
	case "orphan-response":
		if base == 0 {
			base = 55
		}
		return clampConfidence(base), true
	case "request-only":
		if base == 0 {
			base = 58
		}
		return clampConfidence(base), true
	case "positive":
		if riskyService {
			if base == 0 {
				base = 68
			}
			return clampConfidence(base), true
		}
		return 0, false
	default:
		if base == 0 {
			base = 52
		}
		return clampConfidence(base), true
	}
}

func udsServiceEvidenceBase(serviceID string) (int, bool) {
	switch normalizeServiceID(serviceID) {
	case "0x27":
		return 82, true
	case "0x2e", "0x2f":
		return 80, true
	case "0x34", "0x36":
		return 85, true
	case "0x37":
		return 76, true
	case "0x31":
		return 74, true
	case "0x10":
		return 60, true
	default:
		return 0, false
	}
}

func buildUDSEvidenceSummary(tx model.UDSTransaction) string {
	serviceLabel := strings.TrimSpace(joinNonEmpty(" ", tx.ServiceID, tx.ServiceName))
	if serviceLabel == "" {
		serviceLabel = "UDS"
	}

	status := strings.ToLower(strings.TrimSpace(tx.Status))
	switch {
	case tx.NegativeCode != "":
		return fmt.Sprintf("UDS 负响应: %s / %s", serviceLabel, udsNegativeResponseLabel(tx.NegativeCode))
	case status == "orphan-response":
		return fmt.Sprintf("UDS 孤立响应: %s", serviceLabel)
	case status == "request-only":
		return fmt.Sprintf("UDS 请求未配对: %s", serviceLabel)
	default:
		return fmt.Sprintf("UDS 高价值事务: %s", serviceLabel)
	}
}

func udsNegativeResponseLabel(code string) string {
	switch strings.ToLower(strings.TrimSpace(code)) {
	case "0x10":
		return "一般拒绝"
	case "0x11":
		return "服务不支持"
	case "0x12":
		return "子功能不支持"
	case "0x13":
		return "消息长度错误"
	case "0x22":
		return "条件不满足"
	case "0x24":
		return "请求序列错误"
	case "0x31":
		return "请求超出范围"
	case "0x33":
		return "安全访问被拒"
	case "0x35":
		return "密钥无效"
	case "0x36":
		return "尝试次数超限"
	case "0x37":
		return "延时未到"
	case "0x70":
		return "上传下载不接受"
	case "0x71":
		return "传输数据暂停"
	case "0x72":
		return "一般编程失败"
	case "0x73":
		return "错误的区块序列"
	case "0x78":
		return "响应挂起"
	case "0x7e":
		return "会话不支持子功能"
	case "0x7f":
		return "会话不支持服务"
	default:
		if strings.TrimSpace(code) == "" {
			return "负响应"
		}
		return code
	}
}

import type { AnalysisTone } from "../../components/analysis/AnalysisPrimitives";
import type { MiscModuleManifest, StreamPayloadSource } from "../../core/types";
import { getPayloadWebShellLocationLabel, getPayloadWebShellMethodLabel } from "./PayloadWebShellSourceUtils";

export interface PayloadWebShellMiniStat {
  title: string;
  value: string;
  tone: AnalysisTone;
}

export interface PayloadWebShellModuleBadge {
  key: string;
  label: string;
  tone: AnalysisTone;
}

export const PAYLOAD_WEBSHELL_INPUT_DESCRIPTION =
  "手动粘贴 HTTP 报文、body、form 参数、multipart、Base64、Hex 或单个可疑参数值。非 Base64 家族解码会显示置信度与失败阶段，结果仅用于分析，不写回抓包。";

export const PAYLOAD_WEBSHELL_TEXTAREA_PLACEHOLDER =
  "POST /shell.php HTTP/1.1\r\nHost: target\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\npass=...";

export const PAYLOAD_WEBSHELL_REVIEW_BADGE = "候选可疑与低置信结果需要人工确认";

export const PAYLOAD_WEBSHELL_MINI_STATS: PayloadWebShellMiniStat[] = [
  { title: "HTTP 报文", value: "Request / Response", tone: "cyan" },
  { title: "参数来源", value: "Query / Form / Multipart", tone: "emerald" },
  { title: "结构化输入", value: "JSON / Body / 单参数", tone: "blue" },
  { title: "包裹编码", value: "Base64url / Hex / URL 多轮", tone: "amber" },
];

export function getPayloadWebShellPanelTitle(module: MiscModuleManifest, embedded: boolean) {
  return embedded ? "手动 Payload 输入" : module.title;
}

export function getPayloadWebShellModuleBadges(module: MiscModuleManifest): PayloadWebShellModuleBadge[] {
  const badges: PayloadWebShellModuleBadge[] = [];

  if (!module.requiresCapture) {
    badges.push({ key: "capture", label: "无需抓包", tone: "emerald" });
  }
  if (module.cancellable) {
    badges.push({ key: "cancel", label: "可取消", tone: "cyan" });
  }
  if (module.supportsExport) {
    badges.push({ key: "export", label: "支持导出", tone: "blue" });
  }
  badges.push({ key: "experimental", label: "实验性", tone: "amber" });

  return badges;
}

export function formatPayloadWebShellSelectedSource(source: StreamPayloadSource) {
  const streamText = source.streamId ? ` / stream ${source.streamId}` : "";
  return `当前输入来自 packet #${source.packetId}${streamText} · ${getPayloadWebShellMethodLabel(source)} ${getPayloadWebShellLocationLabel(source)}`;
}

export function formatPayloadWebShellInputCounts(draftLength: number, payloadLength: number) {
  return `当前输入 ${draftLength.toLocaleString()} 字符，已提交分析 ${payloadLength.toLocaleString()} 字符。`;
}

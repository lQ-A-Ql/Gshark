import type { HTTPLoginAnalysis, HTTPLoginEndpoint } from "../../core/types";
import { renderInvestigationReportText } from "./investigationReportText";

export type HTTPLoginResultFilter = "ALL" | "SUCCESS" | "FAILURE" | "UNCERTAIN";

export const HTTP_LOGIN_RESULT_FILTERS: HTTPLoginResultFilter[] = ["ALL", "SUCCESS", "FAILURE", "UNCERTAIN"];

export function filterHTTPLoginEndpoints(
  endpoints: HTTPLoginEndpoint[],
  resultFilter: HTTPLoginResultFilter,
  query: string,
) {
  const keyword = query.trim().toLowerCase();
  return endpoints.filter((item) => {
    if (resultFilter === "SUCCESS" && item.successCount <= 0) return false;
    if (resultFilter === "FAILURE" && item.failureCount <= 0) return false;
    if (resultFilter === "UNCERTAIN" && item.uncertainCount <= 0) return false;
    if (!keyword) return true;
    return getHTTPLoginEndpointSearchText(item).includes(keyword);
  });
}

export function selectHTTPLoginEndpoint(
  endpoints: HTTPLoginEndpoint[],
  selectedEndpointKey: string,
): HTTPLoginEndpoint | null {
  return endpoints.find((item) => item.key === selectedEndpointKey) ?? endpoints[0] ?? null;
}

export function filterHTTPLoginAttemptsForEndpoint(
  attempts: HTTPLoginAnalysis["attempts"],
  selectedEndpoint: HTTPLoginEndpoint | null,
) {
  if (!selectedEndpoint) return [];
  return attempts.filter((item) => endpointKeyForHTTPLoginAttempt(item) === selectedEndpoint.key);
}

export function endpointKeyForHTTPLoginAttempt(item: HTTPLoginAnalysis["attempts"][number]) {
  return `${String(item.method ?? "")
    .trim()
    .toUpperCase()}|${String(item.host ?? "").trim()}|${String(item.path ?? "").trim()}`;
}

export function renderHTTPLoginEndpointTitle(item: HTTPLoginEndpoint) {
  const base = item.host ? `${item.host}${item.path || "/"}` : item.path || "/";
  return `${item.method || "HTTP"} ${base}`;
}

export function renderHTTPLoginAnalysisText(analysis: HTTPLoginAnalysis) {
  const lines: string[] = [
    "HTTP 登录行为分析",
    `总尝试: ${analysis.totalAttempts}`,
    `候选端点: ${analysis.candidateEndpoints}`,
    `成功: ${analysis.successCount}`,
    `失败: ${analysis.failureCount}`,
    `待确认: ${analysis.uncertainCount}`,
    `疑似爆破: ${analysis.bruteforceCount}`,
    "",
    "端点详情:",
  ];
  for (const endpoint of analysis.endpoints) {
    lines.push(`- ${renderHTTPLoginEndpointTitle(endpoint)}`);
    lines.push(
      `  尝试 ${endpoint.attemptCount} / 成功 ${endpoint.successCount} / 失败 ${endpoint.failureCount} / 待确认 ${endpoint.uncertainCount}`,
    );
    if (endpoint.possibleBruteforce) {
      lines.push("  标记: 疑似爆破");
    }
    if ((endpoint.requestKeys?.length ?? 0) > 0) {
      lines.push(`  请求键: ${endpoint.requestKeys!.join(", ")}`);
    }
    if ((endpoint.responseIndicators?.length ?? 0) > 0) {
      lines.push(`  响应信号: ${endpoint.responseIndicators!.join(", ")}`);
    }
  }
  const reportText = renderInvestigationReportText(analysis.report);
  if (reportText) {
    lines.push("");
    lines.push(reportText);
  }
  return lines.join("\n");
}

function getHTTPLoginEndpointSearchText(item: HTTPLoginEndpoint) {
  return [
    item.key,
    item.method,
    item.host,
    item.path,
    item.requestKeys?.join(" "),
    item.responseIndicators?.join(" "),
    item.notes?.join(" "),
  ]
    .join(" ")
    .toLowerCase();
}

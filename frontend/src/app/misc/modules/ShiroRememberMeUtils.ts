import type { ShiroRememberMeAnalysis, ShiroRememberMeCandidate } from "../../core/types";
import { renderInvestigationReportText } from "./investigationReportText";

export type ShiroRememberMeCandidateFilter = "ALL" | "HIT" | "DELETEME";

export const shiroFilterOptions: ShiroRememberMeCandidateFilter[] = ["ALL", "HIT", "DELETEME"];

export function getShiroFilterLabel(filter: ShiroRememberMeCandidateFilter) {
  if (filter === "HIT") return "命中";
  if (filter === "DELETEME") return "deleteMe";
  return "全部";
}

export function parseShiroCustomKeyLines(customKeys: string) {
  return customKeys
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
}

export function isShiroDeleteMeCandidate(candidate: ShiroRememberMeCandidate) {
  return (candidate.notes ?? []).some((note) => note.toLowerCase().includes("deleteme"));
}

export function filterShiroCandidates(
  candidates: ShiroRememberMeCandidate[],
  candidateFilter: ShiroRememberMeCandidateFilter,
) {
  return candidates.filter((item) => {
    if (candidateFilter === "HIT") return (item.hitCount ?? 0) > 0;
    if (candidateFilter === "DELETEME") return isShiroDeleteMeCandidate(item);
    return true;
  });
}

export function selectShiroCandidate(candidates: ShiroRememberMeCandidate[], selectedPacketId: number) {
  return candidates.find((item) => item.packetId === selectedPacketId) ?? candidates[0] ?? null;
}

export function shouldPreserveShiroSelection(candidates: ShiroRememberMeCandidate[], selectedPacketId: number) {
  return Boolean(selectedPacketId && candidates.some((item) => item.packetId === selectedPacketId));
}

export function renderShiroCandidateTitle(candidate: ShiroRememberMeCandidate) {
  const location = candidate.host ? `${candidate.host}${candidate.path || "/"}` : candidate.path || "/";
  return `${candidate.cookieName || "rememberMe"} @ ${location}`;
}

export function renderShiroKeyResultLine(result: NonNullable<ShiroRememberMeCandidate["keyResults"]>[number]) {
  return `  Key ${result.label}: ${result.hit ? "HIT" : "MISS"} ${result.algorithm || ""} ${
    result.payloadClass || result.reason || ""
  }`.trim();
}

export function renderShiroAnalysisText(analysis: ShiroRememberMeAnalysis) {
  const lines = [
    "Shiro rememberMe 分析",
    `候选: ${analysis.candidateCount}`,
    `密钥命中: ${analysis.hitCount}`,
    "",
    "候选详情:",
  ];
  for (const candidate of analysis.candidates) {
    lines.push(`- #${candidate.packetId} ${renderShiroCandidateTitle(candidate)}`);
    lines.push(
      `  来源: ${candidate.sourceHeader || "Cookie"} / stream=${candidate.streamId ?? "--"} / hit=${
        candidate.hitCount ?? 0
      }`,
    );
    if ((candidate.notes?.length ?? 0) > 0) {
      lines.push(`  备注: ${candidate.notes!.join("; ")}`);
    }
    for (const result of candidate.keyResults ?? []) {
      lines.push(renderShiroKeyResultLine(result));
    }
  }
  const reportText = renderInvestigationReportText(analysis.report);
  if (reportText) {
    lines.push("", reportText);
  }
  return lines.join("\n");
}

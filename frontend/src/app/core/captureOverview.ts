import { buildCaptureOverviewCounts } from "./captureOverviewCounts";
import { buildQuickFilters } from "./captureOverviewQuickFilters";
import { buildRecommendations } from "./captureOverviewRecommendations";
import { pickTopProtocols } from "./captureOverviewProtocols";
import { pickSuspiciousHits } from "./captureOverviewThreat";
import type {
  CaptureOverviewCounts,
  CaptureOverviewInput,
  CaptureOverviewSnapshot,
  CaptureRecommendation,
} from "./captureOverviewTypes";

export type {
  CaptureModuleKey,
  CaptureOverviewInput,
  CaptureOverviewSnapshot,
  CaptureQuickFilter,
  CaptureRecommendation,
} from "./captureOverviewTypes";

export function buildCaptureOverview(input: CaptureOverviewInput): CaptureOverviewSnapshot {
  const topProtocols = pickTopProtocols(input.stats, input.packets);
  const suspiciousHits = pickSuspiciousHits(input.threatHits);
  const counts = buildCaptureOverviewCounts(input);
  const recommendations = buildRecommendations(input, counts, topProtocols);
  const { headline, summary } = buildHeadline(counts, recommendations, topProtocols);

  return {
    headline,
    summary,
    topProtocols,
    quickFilters: buildQuickFilters(counts, topProtocols),
    recommendations,
    suspiciousHits,
  };
}

function buildHeadline(
  counts: CaptureOverviewCounts,
  recommendations: CaptureRecommendation[],
  topProtocols: CaptureOverviewSnapshot["topProtocols"],
) {
  const dominant = recommendations[0];
  const protocolSummary = topProtocols.map((item) => `${item.label} ${item.count}`).join(" / ");

  if (counts.highRisk > 0) {
    return {
      headline: `优先处理 ${counts.highRisk} 条高危命中`,
      summary: `已命中 ${counts.suspicious} 条可疑流量，建议先定位数据包，再进入对应流追踪与 payload 解码。`,
    };
  }
  if (counts.suspicious > 0) {
    return {
      headline: `已发现 ${counts.suspicious} 条可疑线索`,
      summary: "可以先打开威胁狩猎命中，再按包号回到主工作区验证上下文。",
    };
  }
  if (dominant && dominant.score >= 50) {
    return {
      headline: `当前抓包偏向${dominant.label}`,
      summary: dominant.summary,
    };
  }
  return {
    headline: "先从全局流量分布入手",
    summary: protocolSummary
      ? `当前更像通用网络流量，首屏可先看 ${protocolSummary}。`
      : "当前抓包已可进入主工作区进行协议、流和 payload 联动分析。",
  };
}

import type { C2FamilyAnalysis, C2IndicatorRecord, C2StreamAggregate } from "../../core/types";

export interface C2CapabilityCard {
  title: string;
  text: string;
}

export interface VShellEvidenceSummaryItem {
  label: string;
  value: string;
  helper: string;
  source?: string;
}

export const CS_EVIDENCE_CARDS: C2CapabilityCard[] = [
  {
    title: "HTTP/HTTPS Beacon",
    text: "聚合 GET 拉任务、POST 回传、Host/URI/UA/Header hints 与稳定间隔；静态路径只作为弱信号参与复核。",
  },
  {
    title: "Sleep / Jitter",
    text: "统计固定或近固定间隔、同端点重复通信、周期回连与 jitter，优先把单包观察升级为会话画像。",
  },
  {
    title: "DNS / SMB Channel",
    text: "聚合 DNS qname、qtype、label 长度，以及 SMB pivot / named pipe 候选；低样本量时保留为弱观察。",
  },
];

export const VSHELL_EVIDENCE_CARDS: C2CapabilityCard[] = [
  {
    title: "多 Listener 通道",
    text: "从 TCP、WebSocket、DNS/DoH/DoT 等通道中提取 listener hints、stream 聚合和 packet 定位线索。",
  },
  {
    title: "TCP 心跳画像",
    text: "识别 l64/w64 架构标记、4 字节长度前缀、短长包交替与约 10 秒心跳，按 stream 展示置信度。",
  },
  {
    title: "WebSocket 握手",
    text: "解析 /?a=&h=&t=&p= 参数形态，标记 ws_ 通道、listener port 与管理面痕迹，仍需结合上下文复核。",
  },
];

export const C2_APT_HANDOFF_NOTES = [
  "actorHints / sampleFamily / campaignStage 已作为 APT 页可消费字段；ValleyRAT、Winos 4.0、Gh0st 系证据仍需跨模块复核。",
  "transportTraits / infrastructureHints 承载 HTTPS/TCP C2、HFS 下载链、fallback C2 与周期回连线索，不单独构成强归因。",
  "端口 18856 / 9899 / 443 和 60 秒回连仅作为样本案例观察位，需要与样本、投递链和基础设施证据共同判断。",
];

export function buildVShellEvidenceSummary(family: C2FamilyAnalysis): VShellEvidenceSummaryItem[] {
  const streams = family.streamAggregates ?? [];
  const candidates = family.candidates ?? [];
  const streamCounters = {
    websocket: countWebSocketStreams(streams),
    lengthPrefix: sum(streams.map((item) => item.lengthPrefixCount)),
    archMarker: sum(streams.map((item) => item.archMarkers?.reduce((total, marker) => total + marker.count, 0) ?? 0)),
    heartbeat: streams.filter((item) => Boolean(item.heartbeatAvg)).length,
    listener: sum(streams.map((item) => item.listenerHints?.reduce((total, hint) => total + hint.count, 0) ?? 0)),
  };
  const candidateCounters = countVShellCandidateSignals(candidates);
  const candidate = strongestCandidate(candidates);
  const candidateLocation = candidate
    ? `最高置信 ${formatConfidence(candidate.confidence)} · packet #${candidate.packetId}${typeof candidate.streamId === "number" ? ` / stream ${candidate.streamId}` : ""}`
    : "当前无 candidates 候选";
  return [
    {
      label: "候选证据",
      value: String(candidates.length),
      helper: candidateLocation,
      source: "candidates",
    },
    {
      label: "WebSocket",
      value: String(streamCounters.websocket + candidateCounters.websocket),
      helper: "stream 握手 / candidates ws 参数合并计数",
      source: mergedSource(streamCounters.websocket, candidateCounters.websocket),
    },
    {
      label: "长度前缀",
      value: String(streamCounters.lengthPrefix + candidateCounters.lengthPrefix),
      helper: "4 字节长度前缀观察次数，合并 stream 与候选弱信号",
      source: mergedSource(streamCounters.lengthPrefix, candidateCounters.lengthPrefix),
    },
    {
      label: "架构标记",
      value: String(streamCounters.archMarker + candidateCounters.archMarker),
      helper: "l64/w64 等 payload marker，合并 stream 与 candidates",
      source: mergedSource(streamCounters.archMarker, candidateCounters.archMarker),
    },
    {
      label: "心跳画像",
      value: String(streamCounters.heartbeat + candidateCounters.heartbeat),
      helper: "平均心跳、短长包交替和周期弱信号合并计数",
      source: mergedSource(streamCounters.heartbeat, candidateCounters.heartbeat),
    },
    {
      label: "Listener hints",
      value: String(streamCounters.listener + candidateCounters.listener),
      helper: "端口、listener、管理面或通道提示",
      source: mergedSource(streamCounters.listener, candidateCounters.listener),
    },
    {
      label: "规则因素",
      value: String(family.matchedRuleCount),
      helper: "命中的规则 / 评分因素数量；弱信号仍需人工复核",
      source: "score",
    },
  ];
}

function countWebSocketStreams(streams: C2StreamAggregate[]) {
  return streams.filter((item) => item.hasWebSocket || Boolean(item.wsParams?.trim())).length;
}

function sum(values: number[]) {
  return values.reduce((total, value) => total + value, 0);
}

function countVShellCandidateSignals(candidates: C2IndicatorRecord[]) {
  const counters = {
    websocket: 0,
    lengthPrefix: 0,
    archMarker: 0,
    heartbeat: 0,
    listener: 0,
  };
  for (const candidate of candidates) {
    const haystack = candidateText(candidate);
    if (hasAnyTerm(haystack, ["websocket", "ws_", " ws ", "ws-"])) counters.websocket += 1;
    if (hasAnyTerm(haystack, ["length", "prefix", "length-prefix", "长度前缀"])) counters.lengthPrefix += 1;
    if (hasAnyTerm(haystack, ["l64", "w64", "arch", "架构"])) counters.archMarker += 1;
    if (hasAnyTerm(haystack, ["heartbeat", "心跳", "short-long", "短长包"])) counters.heartbeat += 1;
    if (hasAnyTerm(haystack, ["listener", "port", "管理面"])) counters.listener += 1;
  }
  return counters;
}

function strongestCandidate(candidates: C2IndicatorRecord[]) {
  return candidates.reduce<C2IndicatorRecord | undefined>((best, candidate) => {
    if (!best) return candidate;
    return (candidate.confidence ?? 0) > (best.confidence ?? 0) ? candidate : best;
  }, undefined);
}

function formatConfidence(confidence?: number) {
  if (typeof confidence !== "number" || !Number.isFinite(confidence)) return "待评估";
  return `${Math.round(confidence)}%`;
}

function mergedSource(streamCount: number, candidateCount: number) {
  if (streamCount > 0 && candidateCount > 0) return "stream + candidates";
  if (streamCount > 0) return "stream 聚合";
  if (candidateCount > 0) return "candidates";
  return "未命中";
}

function candidateText(candidate: C2IndicatorRecord) {
  return [
    candidate.indicatorType,
    candidate.indicatorValue,
    candidate.summary,
    candidate.evidence,
    candidate.channel,
    ...(candidate.tags ?? []),
    ...(candidate.transportTraits ?? []),
    ...(candidate.infrastructureHints ?? []),
    ...(candidate.ttpTags ?? []),
  ].join(" ").toLowerCase();
}

function hasAnyTerm(haystack: string, terms: string[]) {
  return terms.some((term) => haystack.includes(term.toLowerCase()));
}

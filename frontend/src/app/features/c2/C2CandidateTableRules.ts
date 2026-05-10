import type { C2IndicatorRecord } from "../../core/types";

export function candidateRowKey(item: C2IndicatorRecord, index: number) {
  return `${item.family}-${item.packetId}-${item.streamId ?? "no-stream"}-${index}`;
}

export function candidateTagValues(item: C2IndicatorRecord) {
  return uniqueValues([
    ...(item.tags ?? []),
    ...(item.actorHints ?? []),
    item.sampleFamily ?? "",
    item.campaignStage ?? "",
    ...(item.transportTraits ?? []),
    ...(item.infrastructureHints ?? []),
    ...(item.ttpTags ?? []),
  ]);
}

export function compactCandidateTags(tags: string[]) {
  if (tags.length <= 5) return tags;
  return [...tags.slice(0, 5), `+${tags.length - 5} more`];
}

export function candidatePreviewRecord(item: C2IndicatorRecord) {
  return {
    packetId: item.packetId,
    streamId: item.streamId,
    time: item.time,
    family: item.family,
    channel: item.channel,
    source: item.source,
    destination: item.destination,
    host: item.host,
    uri: item.uri,
    method: item.method,
    indicatorType: item.indicatorType,
    indicatorValue: item.indicatorValue,
    confidence: item.confidence,
    evidence: item.evidence,
    actorHints: item.actorHints,
    sampleFamily: item.sampleFamily,
    campaignStage: item.campaignStage,
    transportTraits: item.transportTraits,
    infrastructureHints: item.infrastructureHints,
    ttpTags: item.ttpTags,
  };
}

export function preferredProtocolForCandidate(item: C2IndicatorRecord): "HTTP" | "TCP" | "UDP" | undefined {
  const channel = (item.channel ?? "").toLowerCase();
  if (item.method || channel === "http" || channel === "websocket" || channel === "doh") {
    return "HTTP";
  }
  if (channel === "dns" || channel === "kcp_udp" || channel === "udp") {
    return "UDP";
  }
  if (channel === "tcp" || channel === "smb" || channel === "dot") {
    return "TCP";
  }
  return undefined;
}

function uniqueValues(values: string[]) {
  const seen = new Set<string>();
  const next: string[] = [];
  for (const value of values) {
    const normalized = value.trim();
    if (!normalized || seen.has(normalized)) continue;
    seen.add(normalized);
    next.push(normalized);
  }
  return next;
}

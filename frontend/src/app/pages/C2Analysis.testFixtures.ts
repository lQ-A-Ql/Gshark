import type { C2SampleAnalysis } from "../core/types";

export function findAncestorWithClass(node: Element, className: string) {
  let current: Element | null = node;
  while (current) {
    if (current.classList.contains(className)) return current;
    current = current.parentElement;
  }
  return null;
}

export function createAnalysis(overrides: Partial<C2SampleAnalysis> = {}): C2SampleAnalysis {
  const family = {
    candidateCount: 0,
    matchedRuleCount: 0,
    channels: [],
    indicators: [],
    conversations: [],
    beaconPatterns: [],
    hostUriAggregates: [],
    dnsAggregates: [],
    streamAggregates: [],
    candidates: [],
    notes: [],
    relatedActors: [],
    deliveryChains: [],
  };
  return {
    totalMatchedPackets: 0,
    families: [],
    conversations: [],
    cs: { ...family },
    vshell: { ...family },
    notes: [],
    ...overrides,
  };
}

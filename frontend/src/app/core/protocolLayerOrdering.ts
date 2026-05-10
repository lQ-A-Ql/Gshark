import { HIDDEN_LAYER_KEYS } from "./protocolDisplay";
import { humanizeFieldName, isRecord, stripLayerPrefix } from "./protocolLayerFormat";
import { normalizeLayerName, pickLayerValue } from "./protocolLayerSummary";

export function orderLayerEntries(layers: Record<string, unknown>): Array<[string, unknown]> {
  const filtered = Object.entries(layers).filter(([key, value]) => !shouldHideLayer(key, value));
  if (filtered.length === 0) {
    return [];
  }

  const originalIndices = new Map(filtered.map(([key], index) => [key, index]));
  const protocolOrder = extractLayerOrder(layers);
  const rank = new Map(protocolOrder.map((name, index) => [name, index]));

  return filtered.sort(([leftKey], [rightKey]) => {
    const leftRank = rank.get(normalizeLayerName(leftKey)) ?? Number.MAX_SAFE_INTEGER;
    const rightRank = rank.get(normalizeLayerName(rightKey)) ?? Number.MAX_SAFE_INTEGER;
    if (leftRank !== rightRank) {
      return leftRank - rightRank;
    }
    return (originalIndices.get(leftKey) ?? 0) - (originalIndices.get(rightKey) ?? 0);
  });
}

export function orderLayerFields(layerName: string, layer: Record<string, unknown>): Array<[string, unknown]> {
  const entries = Object.entries(layer).filter(([, value]) => value != null);
  const originalIndices = new Map(entries.map(([key], index) => [key, index]));

  return entries.sort(([leftKey], [rightKey]) => {
    const leftWeight = fieldSortWeight(layerName, leftKey);
    const rightWeight = fieldSortWeight(layerName, rightKey);
    if (leftWeight !== rightWeight) {
      return leftWeight - rightWeight;
    }
    const leftLabel = humanizeFieldName(stripLayerPrefix(leftKey, layerName));
    const rightLabel = humanizeFieldName(stripLayerPrefix(rightKey, layerName));
    if (leftLabel !== rightLabel) {
      return leftLabel.localeCompare(rightLabel);
    }
    return (originalIndices.get(leftKey) ?? 0) - (originalIndices.get(rightKey) ?? 0);
  });
}

function fieldSortWeight(layerName: string, fieldName: string): number {
  const name = stripLayerPrefix(fieldName, layerName).toLowerCase();
  if (name === "text") return -10;
  if (name.includes("number")) return -6;
  if (name.includes("time")) return -5;
  if (name.includes("version")) return -4;
  if (name.includes("src") || name.includes("dst")) return -3;
  if (name.includes("port")) return -2;
  if (name.includes("protocol")) return -1;
  return 10;
}

function extractLayerOrder(layers: Record<string, unknown>): string[] {
  const frame = Object.entries(layers).find(
    ([key, value]) => normalizeLayerName(key) === "frame" && isRecord(value),
  )?.[1];
  const protocols = frame && isRecord(frame) ? pickLayerValue(frame, ["frame_frame_protocols", "frame.protocols"]) : "";

  const seen = new Set<string>();
  const ordered: string[] = [];
  const push = (name: string) => {
    const normalized = normalizeLayerName(name);
    if (!normalized || normalized === "ethertype" || seen.has(normalized)) return;
    seen.add(normalized);
    ordered.push(normalized);
  };

  push("frame");
  for (const token of protocols.split(":")) {
    push(token);
  }
  for (const key of Object.keys(layers)) {
    push(key);
  }
  return ordered;
}

function shouldHideLayer(key: string, value: unknown): boolean {
  return HIDDEN_LAYER_KEYS.has(key) || value == null;
}

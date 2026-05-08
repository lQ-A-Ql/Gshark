import type { AnalysisTone } from "../../components/analysis/AnalysisPrimitives";
import type { StreamPayloadSource } from "../../core/types";

export interface PayloadWebShellSourceBadge {
  key: string;
  label: string;
  tone: AnalysisTone;
}

export function getPayloadWebShellSourceKey(source: StreamPayloadSource) {
  return `${source.id}-${source.packetId}`;
}

export function isPayloadWebShellSourceSelected(
  source: StreamPayloadSource,
  selectedSource: StreamPayloadSource | null,
) {
  return selectedSource?.id === source.id && selectedSource.packetId === source.packetId;
}

export function getPayloadWebShellMethodLabel(source: StreamPayloadSource) {
  return source.method || "HTTP";
}

export function getPayloadWebShellLocationLabel(source: StreamPayloadSource) {
  return `${source.host ?? ""}${source.uri ?? ""}`;
}

export function getPayloadWebShellPreviewText(source: StreamPayloadSource) {
  return source.preview || source.payload;
}

export function getPayloadWebShellConfidenceTone(confidence?: number): "emerald" | "cyan" | "amber" {
  const value = confidence ?? 0;
  if (value >= 80) return "emerald";
  if (value >= 55) return "cyan";
  return "amber";
}

export function getPayloadWebShellDecoderName(options?: Record<string, unknown>) {
  const decoder = String(options?.decoder ?? "").trim();
  return decoder || "";
}

export function getPayloadWebShellSourceBadges(source: StreamPayloadSource): PayloadWebShellSourceBadge[] {
  const badges: PayloadWebShellSourceBadge[] = [
    {
      key: "confidence",
      label: `${source.confidence ?? 0}%`,
      tone: getPayloadWebShellConfidenceTone(source.confidence),
    },
  ];

  if (source.paramName) {
    badges.push({
      key: "param",
      label: `${source.sourceType}:${source.paramName}`,
      tone: "blue",
    });
  }
  if (source.familyHint) {
    badges.push({ key: "family", label: source.familyHint, tone: "cyan" });
  }
  if (source.sourceRole) {
    badges.push({ key: "role", label: source.sourceRole, tone: "emerald" });
  }

  const decoderName = getPayloadWebShellDecoderName(source.decoderOptionsHint);
  if (decoderName) {
    badges.push({ key: "decoder", label: decoderName, tone: "amber" });
  }

  for (const hint of (source.decoderHints ?? []).slice(0, 2)) {
    badges.push({ key: `hint-${hint}`, label: hint, tone: "blue" });
  }
  if (source.occurrenceCount && source.occurrenceCount > 1) {
    badges.push({ key: "repeat", label: `重复 ${source.occurrenceCount} 次`, tone: "amber" });
  }

  return badges;
}

export function getPayloadWebShellRuleReasons(source: StreamPayloadSource) {
  return (source.ruleReasons ?? []).slice(0, 3);
}

export function getPayloadWebShellSignals(source: StreamPayloadSource) {
  return (source.signals ?? []).slice(0, 6);
}

export function formatPayloadWebShellPacketList(values?: number[], fallback?: number) {
  const packets = (values && values.length > 0 ? values : fallback ? [fallback] : []).filter(Boolean);
  if (packets.length === 0) {
    return "--";
  }
  const shown = packets.slice(0, 5).join(", ");
  return packets.length > 5 ? `${shown} +${packets.length - 5}` : shown;
}

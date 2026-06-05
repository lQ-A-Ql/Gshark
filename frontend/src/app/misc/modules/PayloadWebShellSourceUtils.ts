import type { AnalysisTone } from "../../components/analysis/AnalysisPrimitives";
import type { StreamPayloadSource } from "../../core/types";
import {
  getWebShellConfidenceTone,
  getWebShellMetadataSummary,
  isChinaChopperMetadata,
} from "../../components/webShellMetadata";

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
  return getWebShellConfidenceTone(confidence);
}

export function getPayloadWebShellDecoderName(options?: Record<string, unknown>) {
  const decoder = String(options?.decoder ?? "").trim();
  return decoder || "";
}

export function getPayloadWebShellSourceBadges(source: StreamPayloadSource): PayloadWebShellSourceBadge[] {
  const metadata = getWebShellMetadataSummary(source, source.confidence);
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
  if (metadata.familyLabel) {
    badges.push({
      key: "family",
      label: metadata.familyLabel,
      tone: isChinaChopperMetadata(source) ? "cyan" : "blue",
    });
  }
  if (metadata.roleLabel !== "未标注") {
    badges.push({ key: "role", label: metadata.roleLabel, tone: "emerald" });
  }

  if (metadata.decoderLabel !== "未提供") {
    badges.push({ key: "decoder", label: metadata.decoderLabel, tone: "amber" });
  }

  for (const hint of (source.decoderHints ?? []).slice(0, 2)) {
    if (hint === metadata.decoderLabel || hint === source.familyHint) {
      continue;
    }
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

export function getPayloadWebShellMetadata(source: StreamPayloadSource) {
  return getWebShellMetadataSummary(source, source.confidence);
}

export function formatPayloadWebShellPacketList(values?: number[], fallback?: number) {
  const packets = (values && values.length > 0 ? values : fallback ? [fallback] : []).filter(Boolean);
  if (packets.length === 0) {
    return "--";
  }
  const shown = packets.slice(0, 5).join(", ");
  return packets.length > 5 ? `${shown} +${packets.length - 5}` : shown;
}

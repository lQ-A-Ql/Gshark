import type { AnalysisTone } from "./analysis/AnalysisPrimitives";

type WebShellHintSource = {
  familyHint?: string;
  decoderHints?: string[];
  decoderOptionsHint?: Record<string, unknown>;
  sourceRole?: string;
};

export interface WebShellMetadataField {
  key: string;
  label: string;
  value: string;
  tone: AnalysisTone;
  unavailable?: boolean;
}

export interface WebShellMetadataSummary {
  familyLabel: string;
  decoderLabel: string;
  versionLabel: string;
  roleLabel: string;
  isChinaChopper: boolean;
  fields: WebShellMetadataField[];
}

const CHINA_CHOPPER_LABEL = "菜刀 / China Chopper";
const VERSION_UNAVAILABLE_LABEL = "未提供";

export function getWebShellMetadataSummary(
  source: WebShellHintSource,
  confidence?: number,
): WebShellMetadataSummary {
  const familyLabel = getWebShellFamilyLabel(source);
  const decoderLabel = getWebShellDecoderLabel(source);
  const versionLabel = getWebShellVersionLabel(source);
  const roleLabel = formatWebShellRole(source.sourceRole);
  const fields: WebShellMetadataField[] = [
    {
      key: "family",
      label: "家族",
      value: familyLabel,
      tone: isChinaChopperAlias(source.familyHint) ? "cyan" : "blue",
    },
    {
      key: "decoder",
      label: "解码提示",
      value: decoderLabel,
      tone: "amber",
    },
    {
      key: "confidence",
      label: "置信度",
      value: `${confidence ?? 0}%`,
      tone: getWebShellConfidenceTone(confidence),
    },
    {
      key: "role",
      label: "角色",
      value: roleLabel,
      tone: "emerald",
    },
    {
      key: "version",
      label: "版本",
      value: versionLabel,
      tone: versionLabel === VERSION_UNAVAILABLE_LABEL ? "slate" : "cyan",
      unavailable: versionLabel === VERSION_UNAVAILABLE_LABEL,
    },
  ];

  return {
    familyLabel,
    decoderLabel,
    versionLabel,
    roleLabel,
    isChinaChopper: isChinaChopperMetadata(source),
    fields,
  };
}

export function getWebShellFamilyLabel(source: WebShellHintSource): string {
  const alias = firstDefinedAlias([
    source.familyHint,
    readString(source.decoderOptionsHint?.family),
    readString(source.decoderOptionsHint?.familyHint),
    readString(source.decoderOptionsHint?.decoder),
    ...(source.decoderHints ?? []),
  ]);
  if (!alias) {
    return "通用 WebShell";
  }
  if (alias === "china_chopper") {
    return CHINA_CHOPPER_LABEL;
  }
  switch (alias) {
    case "antsword":
      return "AntSword";
    case "godzilla":
      return "Godzilla";
    case "behinder":
      return "Behinder-like";
    case "generic":
      return "通用 WebShell";
    default:
      return humanizeHint(alias);
  }
}

export function getWebShellDecoderLabel(source: WebShellHintSource): string {
  const decoder = firstDefinedAlias([
    readString(source.decoderOptionsHint?.decoder),
    ...(source.decoderHints ?? []),
    source.familyHint,
  ]);
  if (!decoder) {
    return "未提供";
  }
  if (decoder === "china_chopper") {
    return CHINA_CHOPPER_LABEL;
  }
  switch (decoder) {
    case "antsword":
      return "AntSword";
    case "godzilla":
      return "Godzilla";
    case "behinder":
      return "Behinder";
    case "base64":
      return "Base64";
    case "auto":
      return "自动检测";
    case "generic":
      return "通用提示";
    default:
      return humanizeHint(decoder);
  }
}

export function getWebShellVersionLabel(source: WebShellHintSource): string {
  const version = readString(source.decoderOptionsHint?.versionHint) || readString(source.decoderOptionsHint?.version);
  return version || VERSION_UNAVAILABLE_LABEL;
}

export function isChinaChopperMetadata(source: WebShellHintSource): boolean {
  return isChinaChopperAlias(source.familyHint)
    || isChinaChopperAlias(readString(source.decoderOptionsHint?.family))
    || isChinaChopperAlias(readString(source.decoderOptionsHint?.familyHint))
    || isChinaChopperAlias(readString(source.decoderOptionsHint?.decoder))
    || (source.decoderHints ?? []).some((hint) => isChinaChopperAlias(hint));
}

export function isChinaChopperAlias(value: unknown): boolean {
  const normalized = normalizeAlias(value);
  return normalized === "china_chopper";
}

export function getWebShellConfidenceTone(confidence?: number): "emerald" | "cyan" | "amber" {
  const value = confidence ?? 0;
  if (value >= 80) return "emerald";
  if (value >= 55) return "cyan";
  return "amber";
}

function formatWebShellRole(value: unknown): string {
  const raw = String(value ?? "").trim();
  if (!raw) {
    return "未标注";
  }
  return raw;
}

function firstDefinedAlias(values: unknown[]): string {
  for (const value of values) {
    const normalized = normalizeAlias(value);
    if (normalized) {
      return normalized;
    }
  }
  return "";
}

function normalizeAlias(value: unknown): string {
  const normalized = String(value ?? "")
    .trim()
    .toLowerCase()
    .replace(/[\s-]+/g, "_");
  if (!normalized) {
    return "";
  }
  if (
    normalized === "china_chopper"
    || normalized === "chopper"
    || normalized === "caidao"
    || normalized === "菜刀"
    || normalized === "chinachopper"
  ) {
    return "china_chopper";
  }
  if (normalized === "antsword" || normalized === "antsword_like") {
    return "antsword";
  }
  if (normalized === "godzilla" || normalized === "godzilla_like") {
    return "godzilla";
  }
  if (
    normalized === "behinder"
    || normalized === "aes_webshell_like"
    || normalized === "rebeyond"
    || normalized === "behinder_like"
  ) {
    return "behinder";
  }
  if (normalized === "webshell_like" || normalized === "plain" || normalized === "generic") {
    return "generic";
  }
  return normalized;
}

function readString(value: unknown): string {
  return String(value ?? "").trim();
}

function humanizeHint(value: string): string {
  return value
    .split("_")
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

import { LAYER_TITLES, TOKEN_LABELS } from "./protocolDisplay";

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function formatLeafValue(value: unknown): string {
  if (value == null) return "";
  if (typeof value === "boolean") return value ? "True" : "False";
  if (typeof value === "string") return value;
  if (typeof value === "number") return String(value);
  if (Array.isArray(value))
    return value
      .map((item) => formatLeafValue(item))
      .filter(Boolean)
      .join(", ");
  if (isRecord(value)) return "{...}";
  return String(value);
}

export function layerTitle(layerName: string): string {
  return LAYER_TITLES[layerName] ?? humanizeFieldName(layerName);
}

export function buildFieldLabel(name: string, value: string): string {
  const label = humanizeFieldName(name);
  if (!value) return label;
  return `${label}: ${value}`;
}

export function stripLayerPrefix(fieldName: string, layerName: string): string {
  let result = fieldName;
  const dottedPrefix = `${layerName}.`;
  const underscoredPrefix = `${layerName}_`;
  while (result.toLowerCase().startsWith(dottedPrefix)) {
    result = result.slice(dottedPrefix.length);
  }
  while (result.toLowerCase().startsWith(underscoredPrefix)) {
    result = result.slice(underscoredPrefix.length);
  }
  return result;
}

export function humanizeFieldName(name: string): string {
  const cleaned = name.replace(/\[(\d+)\]/g, "#$1");
  return cleaned
    .split(/[._\s]+/)
    .filter(Boolean)
    .map((part) => {
      const normalized = part.toLowerCase();
      if (TOKEN_LABELS[normalized]) return TOKEN_LABELS[normalized];
      if (/^#\d+$/.test(part)) return part;
      return part.charAt(0).toUpperCase() + part.slice(1);
    })
    .join(" ");
}

import type { StreamDecoderKind } from "../core/types";
import type { DecoderHintSource, DecoderSettings } from "./StreamDecoderTypes";

export function asKnownDecoder(value: unknown): StreamDecoderKind | null {
  switch (
    String(value ?? "")
      .trim()
      .toLowerCase()
  ) {
    case "auto":
      return "auto";
    case "base64":
      return "base64";
    case "behinder":
      return "behinder";
    case "antsword":
      return "antsword";
    case "godzilla":
      return "godzilla";
    default:
      return null;
  }
}

export function mergeDecoderHintSources(
  candidate?: DecoderHintSource | null,
  source?: DecoderHintSource,
): DecoderHintSource | undefined {
  if (!candidate) return source;
  if (!source) return candidate;
  return {
    ...candidate,
    familyHint: source.familyHint || candidate.familyHint,
    sourceRole: source.sourceRole || candidate.sourceRole,
    paramName: source.paramName || candidate.paramName,
    decoderHints: uniqueStrings([...(source.decoderHints ?? []), ...(candidate.decoderHints ?? [])]),
    decoderOptionsHint: {
      ...(candidate.decoderOptionsHint ?? {}),
      ...(source.decoderOptionsHint ?? {}),
    },
  };
}

export function decoderFromHintSource(source?: DecoderHintSource): StreamDecoderKind | null {
  const optionsDecoder = asKnownDecoder(source?.decoderOptionsHint?.decoder);
  if (optionsDecoder && optionsDecoder !== "base64" && optionsDecoder !== "auto") {
    return optionsDecoder;
  }
  for (const hint of source?.decoderHints ?? []) {
    const decoder = asKnownDecoder(hint);
    if (decoder && decoder !== "base64" && decoder !== "auto") {
      return decoder;
    }
  }
  switch (source?.familyHint) {
    case "antsword_like":
      return "antsword";
    case "godzilla_like":
      return "godzilla";
    case "aes_webshell_like":
      return "behinder";
    default:
      return null;
  }
}

export function buildDecoderOptions(
  decoder: StreamDecoderKind,
  settings: DecoderSettings,
  source?: DecoderHintSource,
): Record<string, unknown> {
  if (decoder === "base64") {
    return {};
  }
  const hintedDecoder = decoderFromHintSource(source);
  const effectiveDecoder = decoder === "auto" ? hintedDecoder : decoder;
  if (effectiveDecoder === "behinder") {
    return mergeHintOptionsForDecoder("behinder", settings.behinder, source);
  }
  if (effectiveDecoder === "antsword") {
    return mergeHintOptionsForDecoder("antsword", settings.antsword, source);
  }
  if (effectiveDecoder === "godzilla") {
    return mergeHintOptionsForDecoder("godzilla", settings.godzilla, source);
  }
  return {};
}

export function mergeHintIntoSettings(settings: DecoderSettings, source?: DecoderHintSource): DecoderSettings {
  const decoder = decoderFromHintSource(source);
  if (decoder === "behinder") {
    return {
      ...settings,
      behinder: mergeHintOptionsForDecoder("behinder", settings.behinder, source) as DecoderSettings["behinder"],
    };
  }
  if (decoder === "antsword") {
    return {
      ...settings,
      antsword: mergeHintOptionsForDecoder("antsword", settings.antsword, source) as DecoderSettings["antsword"],
    };
  }
  if (decoder === "godzilla") {
    return {
      ...settings,
      godzilla: mergeHintOptionsForDecoder("godzilla", settings.godzilla, source) as DecoderSettings["godzilla"],
    };
  }
  return settings;
}

export function candidateHintBadges(source: DecoderHintSource): string[] {
  const options = source.decoderOptionsHint ?? {};
  const badges: string[] = [];
  for (const key of ["decoder", "pass", "inputEncoding", "cipher", "cipherMode"] as const) {
    const value = options[key];
    if (value !== undefined && value !== null && String(value).trim()) {
      badges.push(`${key}:${String(value)}`);
    }
  }
  return badges;
}

function uniqueStrings(items: string[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const item of items) {
    const key = String(item ?? "").trim();
    if (!key || seen.has(key)) {
      continue;
    }
    seen.add(key);
    out.push(key);
  }
  return out;
}

function mergeHintOptionsForDecoder(
  decoder: Exclude<StreamDecoderKind, "auto" | "base64">,
  current: Record<string, unknown>,
  source?: DecoderHintSource,
): Record<string, unknown> {
  const rawHint = source?.decoderOptionsHint ?? {};
  const hintedDecoder = asKnownDecoder(rawHint.decoder) ?? decoderFromHintSource(source);
  if (hintedDecoder && hintedDecoder !== decoder) {
    return current;
  }
  const allowed = allowedHintKeysForDecoder(decoder);
  const merged: Record<string, unknown> = { ...current };
  for (const key of allowed) {
    const value = rawHint[key];
    if (value === undefined || value === null || value === "") {
      continue;
    }
    if ((decoder === "godzilla" && key === "key") || (decoder === "behinder" && (key === "key" || key === "iv"))) {
      if (String(current[key] ?? "").trim()) {
        continue;
      }
    }
    merged[key] = value;
  }
  if (source?.paramName && !String(merged.pass ?? "").trim()) {
    merged.pass = source.paramName;
  }
  return merged;
}

function allowedHintKeysForDecoder(decoder: Exclude<StreamDecoderKind, "auto" | "base64">): string[] {
  if (decoder === "antsword") {
    return ["pass", "extractParam", "urlDecodeRounds", "encoder"];
  }
  if (decoder === "godzilla") {
    return ["pass", "extractParam", "urlDecodeRounds", "inputEncoding", "cipher", "stripMarkers"];
  }
  return ["pass", "extractParam", "urlDecodeRounds", "inputEncoding", "cipherMode", "deriveKeyFromPass"];
}

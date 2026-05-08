import type { StreamDecoderKind, StreamPayloadSource } from "../core/types";

export type DecoderSettings = {
  behinder: {
    pass: string;
    key: string;
    iv: string;
    extractParam: boolean;
    deriveKeyFromPass: boolean;
    urlDecodeRounds: number;
    inputEncoding: "auto" | "base64" | "hex";
    cipherMode: "ecb" | "cbc";
  };
  antsword: {
    pass: string;
    extractParam: boolean;
    urlDecodeRounds: number;
    encoder: "" | "rot13";
  };
  godzilla: {
    pass: string;
    key: string;
    extractParam: boolean;
    stripMarkers: boolean;
    urlDecodeRounds: number;
    inputEncoding: "auto" | "base64" | "hex";
    cipher: "aes_ecb" | "aes_cbc" | "xor";
  };
};

export type BatchItem = {
  index: number;
  payload: string;
  label: string;
};

export type BatchDecodeProgress = {
  total: number;
  done: number;
  success: number;
  failed: number;
  currentLabel: string;
};

export type DecoderApplyMode = "preview" | "derived" | "overwrite";

export type DecoderHintSource = Pick<
  StreamPayloadSource,
  "familyHint" | "decoderOptionsHint" | "sourceRole" | "decoderHints" | "paramName"
>;

export const MAX_BATCH_FAILURE_DETAILS = 20;
export const EMPTY_SELECT_VALUE = "__empty__";

const SETTINGS_STORAGE_KEY = "gshark.stream-decoders.v1";

export const DEFAULT_SETTINGS: DecoderSettings = {
  behinder: {
    pass: "rebeyond",
    key: "",
    iv: "",
    extractParam: true,
    deriveKeyFromPass: true,
    urlDecodeRounds: 0,
    inputEncoding: "auto",
    cipherMode: "ecb",
  },
  antsword: {
    pass: "pass",
    extractParam: true,
    urlDecodeRounds: 1,
    encoder: "",
  },
  godzilla: {
    pass: "pass",
    key: "",
    extractParam: true,
    stripMarkers: true,
    urlDecodeRounds: 0,
    inputEncoding: "auto",
    cipher: "aes_ecb",
  },
};

export function clampBatchOrdinal(rawValue: string | number | undefined, total: number) {
  if (total <= 0) return 1;
  const parsed = Number(String(rawValue ?? "").replace(/[^0-9]/g, ""));
  if (!Number.isFinite(parsed) || parsed <= 0) return 1;
  return Math.max(1, Math.min(total, Math.floor(parsed)));
}

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

export function prepareDecoderInput(decoder: StreamDecoderKind, payload: string): string {
  if (decoder === "base64") {
    return extractBestBase64Candidate(payload);
  }
  return payload;
}

export function isAbortError(error: unknown) {
  return error instanceof DOMException && error.name === "AbortError";
}

export function normalizeTransportPayload(raw: string): string {
  const current = String(raw ?? "").trim();
  if (!current) {
    return "";
  }
  if (looksLikeHttpMessage(current)) {
    return extractHttpBody(current).trim();
  }
  return current;
}

export function readDecoderSettings(): DecoderSettings {
  if (typeof window === "undefined") return DEFAULT_SETTINGS;
  try {
    const raw = window.localStorage.getItem(SETTINGS_STORAGE_KEY);
    if (!raw) return DEFAULT_SETTINGS;
    const parsed = JSON.parse(raw);
    return {
      behinder: { ...DEFAULT_SETTINGS.behinder, ...(parsed.behinder ?? {}) },
      antsword: { ...DEFAULT_SETTINGS.antsword, ...(parsed.antsword ?? {}) },
      godzilla: { ...DEFAULT_SETTINGS.godzilla, ...(parsed.godzilla ?? {}) },
    };
  } catch {
    return DEFAULT_SETTINGS;
  }
}

export function persistDecoderSettings(settings: DecoderSettings) {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(SETTINGS_STORAGE_KEY, JSON.stringify(settings));
  } catch {
    // ignore persistence errors
  }
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

const HTTP_METHOD_PREFIXES = ["GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS ", "CONNECT ", "TRACE "];

function looksLikeHttpMessage(raw: string): boolean {
  const text = raw.trim();
  if (!text) return false;
  if (text.startsWith("HTTP/")) {
    return true;
  }
  for (const method of HTTP_METHOD_PREFIXES) {
    if (text.startsWith(method)) {
      return true;
    }
  }
  return text.includes("\nHost:") || text.includes("\r\nHost:");
}

function extractHttpBody(raw: string): string {
  const crlfIndex = raw.indexOf("\r\n\r\n");
  if (crlfIndex >= 0) return raw.slice(crlfIndex + 4);
  const lfIndex = raw.indexOf("\n\n");
  if (lfIndex >= 0) return raw.slice(lfIndex + 2);
  return raw;
}

function extractBestBase64Candidate(raw: string): string {
  return raw.trim();
}

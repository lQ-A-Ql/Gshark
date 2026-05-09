import type { StreamDecoderKind } from "../core/types";

const HTTP_METHOD_PREFIXES = ["GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS ", "CONNECT ", "TRACE "];

export function clampBatchOrdinal(rawValue: string | number | undefined, total: number) {
  if (total <= 0) return 1;
  const parsed = Number(String(rawValue ?? "").replace(/[^0-9]/g, ""));
  if (!Number.isFinite(parsed) || parsed <= 0) return 1;
  return Math.max(1, Math.min(total, Math.floor(parsed)));
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

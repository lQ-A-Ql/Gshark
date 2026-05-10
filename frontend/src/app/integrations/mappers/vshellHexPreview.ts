import {
  getVShellLowInfoControlMaxBytes,
  hasForensicTextSignal,
  hasMeaningfulVisibleText,
  normalizePreviewTextForDisplay,
} from "./vshellTextSignals";

const meaningfulVisibleSymbols = new Set([0x2e, 0x2f, 0x5f, 0x2d, 0x3a, 0x7b, 0x7d]);

export type HexPreviewBytes = {
  bytes: Uint8Array;
  truncated: boolean;
};

export function decodeBytesToUtf8(bytes: Uint8Array): string | undefined {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return undefined;
  }
}

export function extractBestEffortTextFromBytes(bytes: Uint8Array): string | undefined {
  let out = "";
  for (const byte of bytes) {
    if ((byte >= 0x20 && byte <= 0x7e) || byte === 0x09 || byte === 0x0a || byte === 0x0d || byte === 0x1b) {
      out += String.fromCharCode(byte);
    } else if (out && !out.endsWith(" ")) {
      out += " ";
    }
  }
  const normalized = normalizePreviewTextForDisplay(out).text;
  if (!hasMeaningfulVisibleText(normalized)) {
    return undefined;
  }
  if (!hasForensicTextSignal(normalized) && Array.from(normalized).filter((char) => /\S/.test(char)).length < 6) {
    return undefined;
  }
  return normalized;
}

export function parseHexPreviewBytes(preview: string, decryptedLength?: number): HexPreviewBytes | undefined {
  const normalized = preview.trim();
  if (!normalized || normalized.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(normalized)) {
    return undefined;
  }
  const byteLength = normalized.length / 2;
  const expectedLength = decryptedLength && decryptedLength > 0 ? decryptedLength : undefined;
  if (expectedLength !== undefined && byteLength > expectedLength) {
    return undefined;
  }
  const bytes = new Uint8Array(byteLength);
  for (let index = 0; index < normalized.length; index += 2) {
    bytes[index / 2] = Number.parseInt(normalized.slice(index, index + 2), 16);
  }
  return {
    bytes,
    truncated: expectedLength !== undefined && byteLength < expectedLength,
  };
}

export function isLowInfoHexPreview(preview: string, decryptedLength: number): boolean | undefined {
  const parsed = parseHexPreviewBytes(preview, decryptedLength);
  const bytes = parsed?.bytes;
  if (!bytes || bytes.length === 0 || bytes.length > getVShellLowInfoControlMaxBytes()) {
    return undefined;
  }

  const visibleAsciiBytes = Array.from(bytes).filter((byte) => byte >= 0x20 && byte <= 0x7e);
  const visibleAsciiText = String.fromCharCode(...visibleAsciiBytes);
  if (hasForensicTextSignal(visibleAsciiText)) {
    return false;
  }

  const meaningfulCount = visibleAsciiBytes.filter(isMeaningfulVisibleByte).length;
  if (meaningfulCount >= 2 && visibleAsciiBytes.length / bytes.length >= 0.35) {
    return false;
  }

  return true;
}

function isMeaningfulVisibleByte(byte: number): boolean {
  if (meaningfulVisibleSymbols.has(byte)) return true;
  return (byte >= 0x30 && byte <= 0x39) || (byte >= 0x41 && byte <= 0x5a) || (byte >= 0x61 && byte <= 0x7a);
}

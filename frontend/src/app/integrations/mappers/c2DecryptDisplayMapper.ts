import type { C2DecryptedRecord, C2DecryptResult } from "../../core/types";

const vshellLowInfoControlMaxBytes = 24;

type C2PreviewNormalization = {
  record: C2DecryptedRecord;
  converted: boolean;
  bestEffortConverted?: boolean;
  truncatedHexPreview?: boolean;
  ansiStripped?: boolean;
  hiddenReason?: "utf8-invisible" | "timestamp-only";
};

type HexPreviewBytes = {
  bytes: Uint8Array;
  truncated: boolean;
};

export function normalizeC2DecryptResultForDisplay(result: C2DecryptResult): C2DecryptResult {
  if (result.family !== "vshell" || result.records.length === 0) {
    return result;
  }

  let convertedCount = 0;
  let bestEffortConvertedCount = 0;
  let truncatedHexPreviewCount = 0;
  let ansiStrippedCount = 0;
  let invisibleDecodedCount = 0;
  let timestampOnlyCount = 0;
  let shortBinaryControlCount = 0;
  const normalizedRecords = result.records.map((record) => {
    const normalized = normalizeC2DecryptedRecordPreview(record);
    if (normalized.converted) {
      convertedCount += 1;
    }
    if (normalized.bestEffortConverted) {
      bestEffortConvertedCount += 1;
    }
    if (normalized.truncatedHexPreview) {
      truncatedHexPreviewCount += 1;
    }
    if (normalized.ansiStripped) {
      ansiStrippedCount += 1;
    }
    if (normalized.hiddenReason === "utf8-invisible") {
      invisibleDecodedCount += 1;
    }
    if (normalized.hiddenReason === "timestamp-only") {
      timestampOnlyCount += 1;
    }
    return normalized;
  });

  const visibleRecords: C2DecryptedRecord[] = [];
  for (const item of normalizedRecords) {
    if (item.hiddenReason) {
      continue;
    }
    if (isLikelyVShellLowInfoControlRecord(item.record)) {
      shortBinaryControlCount += 1;
      continue;
    }
    visibleRecords.push(item.record);
  }

  const hiddenCount = result.records.length - visibleRecords.length;
  if (
    hiddenCount <= 0 &&
    convertedCount <= 0 &&
    bestEffortConvertedCount <= 0 &&
    truncatedHexPreviewCount <= 0 &&
    ansiStrippedCount <= 0
  ) {
    return result;
  }

  const notes = [...result.notes];
  if (convertedCount > 0) {
    notes.push(`前端接口层已将 ${convertedCount} 条 VShell hex preview 转为 UTF-8 文本。`);
  }
  if (bestEffortConvertedCount > 0) {
    notes.push(`前端接口层已从 ${bestEffortConvertedCount} 条 VShell hex preview 中提取可读文本。`);
  }
  if (truncatedHexPreviewCount > 0) {
    notes.push(`前端接口层已从 ${truncatedHexPreviewCount} 条后端截断的 VShell hex preview 中提取可读文本。`);
  }
  if (ansiStrippedCount > 0) {
    notes.push(`前端接口层已清理 ${ansiStrippedCount} 条 VShell 记录中的 ANSI/VT100 终端控制序列。`);
  }
  if (invisibleDecodedCount > 0) {
    notes.push(`前端接口层已隐藏 ${invisibleDecodedCount} 条 UTF-8 解码后无可见字符的 VShell 记录。`);
  }
  if (timestampOnlyCount > 0) {
    notes.push(`前端接口层已隐藏 ${timestampOnlyCount} 条仅包含时间戳的 VShell 记录。`);
  }
  if (shortBinaryControlCount > 0) {
    notes.push(
      `前端接口层已隐藏 ${shortBinaryControlCount} 条 VShell 短二进制控制帧/心跳帧，避免短控制载荷淹没明文结果。`,
    );
  }

  return {
    ...result,
    decryptedCount: Math.max(0, result.decryptedCount - hiddenCount),
    records: visibleRecords,
    notes,
  };
}

export function isLikelyVShellLowInfoControlRecord(record: C2DecryptedRecord): boolean {
  if (record.error || (record.parsed && Object.keys(record.parsed).length > 0)) {
    return false;
  }

  const decryptedLength = record.decryptedLength ?? 0;
  if (decryptedLength <= 0 || decryptedLength > vshellLowInfoControlMaxBytes) {
    return false;
  }

  const preview = String(record.plaintextPreview ?? "");
  if (!preview) {
    return decryptedLength <= 4;
  }

  const hexDecision = isLowInfoHexPreview(preview.trim(), decryptedLength);
  if (hexDecision !== undefined) {
    return hexDecision;
  }

  if (hasMeaningfulVisibleText(preview)) {
    return false;
  }

  const visibleAsciiCount = Array.from(preview).filter((char) => char >= " " && char <= "~").length;
  return visibleAsciiCount <= 1 || visibleAsciiCount / Math.max(1, Array.from(preview).length) < 0.35;
}

function normalizeC2DecryptedRecordPreview(record: C2DecryptedRecord): C2PreviewNormalization {
  if (record.error) {
    return { record, converted: false };
  }
  const preview = record.plaintextPreview ?? "";
  const hexPreview = parseHexPreviewBytes(preview, record.decryptedLength);
  if (hexPreview) {
    const decoded = hexPreview.truncated ? undefined : decodeBytesToUtf8(hexPreview.bytes);
    if (decoded !== undefined) {
      return normalizeDecodedC2Preview(record, decoded, {
        converted: true,
        tags: ["utf8-from-hex-preview"],
      });
    }
    const extracted = extractBestEffortTextFromBytes(hexPreview.bytes);
    if (extracted !== undefined) {
      return normalizeDecodedC2Preview(record, extracted, {
        converted: false,
        bestEffortConverted: true,
        truncatedHexPreview: hexPreview.truncated,
        tags: ["utf8-best-effort-from-hex-preview", ...(hexPreview.truncated ? ["truncated-hex-preview"] : [])],
      });
    }
  }

  return normalizeDecodedC2Preview(record, preview, { converted: false });
}

function normalizeDecodedC2Preview(
  record: C2DecryptedRecord,
  value: string,
  options: { converted: boolean; bestEffortConverted?: boolean; truncatedHexPreview?: boolean; tags?: string[] },
): C2PreviewNormalization {
  const normalized = normalizePreviewTextForDisplay(value);
  const baseTags = record.tags ?? [];
  const tags = [
    ...new Set([...baseTags, ...(options.tags ?? []), ...(normalized.ansiStripped ? ["ansi-stripped"] : [])]),
  ];

  if (!hasMeaningfulVisibleText(normalized.text)) {
    return {
      record: {
        ...record,
        plaintextPreview: normalized.text,
        tags,
      },
      converted: options.converted,
      bestEffortConverted: options.bestEffortConverted,
      truncatedHexPreview: options.truncatedHexPreview,
      ansiStripped: normalized.ansiStripped,
      hiddenReason: "utf8-invisible",
    };
  }

  if (isTimestampOnlyText(normalized.text)) {
    return {
      record: {
        ...record,
        plaintextPreview: normalized.text,
        tags,
      },
      converted: options.converted,
      bestEffortConverted: options.bestEffortConverted,
      truncatedHexPreview: options.truncatedHexPreview,
      ansiStripped: normalized.ansiStripped,
      hiddenReason: "timestamp-only",
    };
  }

  return {
    record: {
      ...record,
      plaintextPreview: normalized.text,
      tags,
    },
    converted: options.converted,
    bestEffortConverted: options.bestEffortConverted,
    truncatedHexPreview: options.truncatedHexPreview,
    ansiStripped: normalized.ansiStripped,
  };
}

function decodeBytesToUtf8(bytes: Uint8Array): string | undefined {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return undefined;
  }
}

function extractBestEffortTextFromBytes(bytes: Uint8Array): string | undefined {
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

function normalizePreviewTextForDisplay(value: string): { text: string; ansiStripped: boolean } {
  const ansiStripped = stripAnsiControlSequences(value);
  const controlCleaned = ansiStripped
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001a\u001c-\u001f\u007f]/g, "")
    .replace(/\r\n/g, "\n")
    .replace(/\r/g, "\n");
  return {
    text: controlCleaned.trim(),
    ansiStripped: ansiStripped !== value,
  };
}

function stripAnsiControlSequences(value: string): string {
  return value
    .replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, "")
    .replace(/\x1b\][^\x07]*(?:\x07|\x1b\\)/g, "")
    .replace(/\x1b[@-Z\\-_]/g, "");
}

function parseHexPreviewBytes(preview: string, decryptedLength?: number): HexPreviewBytes | undefined {
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

function hasMeaningfulVisibleText(value: string): boolean {
  const normalized = stripAnsiControlSequences(value).replace(/[\u0000-\u001f\u007f]/g, "");
  const visibleChars = Array.from(normalized).filter((char) => /\S/.test(char));
  if (visibleChars.length < 2) {
    return false;
  }
  if (hasForensicTextSignal(normalized)) {
    return true;
  }
  const meaningfulChars = visibleChars.filter((char) => /[\p{L}\p{N}_{}\[\]:"'./\\=&()\-]/u.test(char));
  if (meaningfulChars.length >= 3) {
    return true;
  }
  return false;
}

function isTimestampOnlyText(value: string): boolean {
  const normalized = stripAnsiControlSequences(value).trim();
  if (!normalized) {
    return false;
  }
  if (/^\d{4}[-/]\d{2}[-/]\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?$/.test(normalized)) {
    return true;
  }
  if (/^\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?$/.test(normalized)) {
    return true;
  }
  if (/^\d{10}$/.test(normalized)) {
    const epochMs = Number(normalized) * 1000;
    return epochMs >= Date.UTC(2000, 0, 1) && epochMs <= Date.UTC(2100, 0, 1);
  }
  if (/^\d{13}$/.test(normalized)) {
    const epochMs = Number(normalized);
    return epochMs >= Date.UTC(2000, 0, 1) && epochMs <= Date.UTC(2100, 0, 1);
  }
  return false;
}

function hasForensicTextSignal(value: string): boolean {
  const normalized = value.trim();
  if (!normalized) {
    return false;
  }
  if (/^\s*[\[{]/.test(value)) {
    return true;
  }
  if (/\b(?:ok|id|ip|cmd|whoami|powershell|verifykey|hacked_by|fallsnow|paperplane)\b/i.test(normalized)) {
    return true;
  }
  if (/\b\d+(?:\.\d+){1,3}\b/.test(normalized)) {
    return true;
  }
  if (
    /(?:[A-Za-z]:\\|\\\\|\/(?:bin|etc|home|tmp|usr|var)\/|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})/.test(
      normalized,
    )
  ) {
    return true;
  }
  if (/\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(normalized)) {
    return true;
  }
  return /\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b/.test(normalized);
}

function isLowInfoHexPreview(preview: string, decryptedLength: number): boolean | undefined {
  const parsed = parseHexPreviewBytes(preview, decryptedLength);
  const bytes = parsed?.bytes;
  if (!bytes || bytes.length === 0 || bytes.length > vshellLowInfoControlMaxBytes) {
    return undefined;
  }

  const visibleAsciiBytes = Array.from(bytes).filter((byte) => byte >= 0x20 && byte <= 0x7e);
  const visibleAsciiText = String.fromCharCode(...visibleAsciiBytes);
  if (hasForensicTextSignal(visibleAsciiText)) {
    return false;
  }

  const meaningfulVisibleBytes = visibleAsciiBytes.filter(
    (byte) =>
      (byte >= 0x30 && byte <= 0x39) ||
      (byte >= 0x41 && byte <= 0x5a) ||
      (byte >= 0x61 && byte <= 0x7a) ||
      byte === 0x2e ||
      byte === 0x2f ||
      byte === 0x5f ||
      byte === 0x2d ||
      byte === 0x3a ||
      byte === 0x7b ||
      byte === 0x7d,
  );
  if (meaningfulVisibleBytes.length >= 2 && visibleAsciiBytes.length / bytes.length >= 0.35) {
    return false;
  }

  return true;
}

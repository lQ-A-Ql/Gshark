import type { C2DecryptedRecord } from "../../core/types";
import {
  decodeBytesToUtf8,
  extractBestEffortTextFromBytes,
  isLowInfoHexPreview,
  parseHexPreviewBytes,
} from "./vshellHexPreview";
import {
  getVShellLowInfoControlMaxBytes,
  hasMeaningfulVisibleText,
  isTimestampOnlyText,
  normalizePreviewTextForDisplay,
} from "./vshellTextSignals";

type C2PreviewNormalization = {
  record: C2DecryptedRecord;
  converted: boolean;
  bestEffortConverted?: boolean;
  truncatedHexPreview?: boolean;
  ansiStripped?: boolean;
  hiddenReason?: "utf8-invisible" | "timestamp-only";
};

export function isLikelyVShellLowInfoControlRecord(record: C2DecryptedRecord): boolean {
  if (record.error || (record.parsed && Object.keys(record.parsed).length > 0)) {
    return false;
  }

  const decryptedLength = record.decryptedLength ?? 0;
  if (decryptedLength <= 0 || decryptedLength > getVShellLowInfoControlMaxBytes()) {
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

export function normalizeC2DecryptedRecordPreview(record: C2DecryptedRecord): C2PreviewNormalization {
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
      record: { ...record, plaintextPreview: normalized.text, tags },
      converted: options.converted,
      bestEffortConverted: options.bestEffortConverted,
      truncatedHexPreview: options.truncatedHexPreview,
      ansiStripped: normalized.ansiStripped,
      hiddenReason: "utf8-invisible",
    };
  }

  if (isTimestampOnlyText(normalized.text)) {
    return {
      record: { ...record, plaintextPreview: normalized.text, tags },
      converted: options.converted,
      bestEffortConverted: options.bestEffortConverted,
      truncatedHexPreview: options.truncatedHexPreview,
      ansiStripped: normalized.ansiStripped,
      hiddenReason: "timestamp-only",
    };
  }

  return {
    record: { ...record, plaintextPreview: normalized.text, tags },
    converted: options.converted,
    bestEffortConverted: options.bestEffortConverted,
    truncatedHexPreview: options.truncatedHexPreview,
    ansiStripped: normalized.ansiStripped,
  };
}

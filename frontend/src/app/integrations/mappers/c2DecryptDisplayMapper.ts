import type { C2DecryptedRecord, C2DecryptResult } from "../../core/types";
import { isLikelyVShellLowInfoControlRecord, normalizeC2DecryptedRecordPreview } from "./vshellDecryptDisplayRules";

export { isLikelyVShellLowInfoControlRecord } from "./vshellDecryptDisplayRules";

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

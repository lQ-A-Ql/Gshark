import type { WinRMDecryptResult } from "../../core/types";

export function asWinRMDecryptResult(input: any, fallbackPort = 0): WinRMDecryptResult {
  return {
    resultId: String(input.result_id ?? ""),
    captureName: String(input.capture_name ?? ""),
    port: Number(input.port ?? fallbackPort ?? 0),
    authMode: String(input.auth_mode ?? ""),
    previewText: String(input.preview_text ?? ""),
    previewTruncated: Boolean(input.preview_truncated),
    lineCount: Number(input.line_count ?? 0),
    frameCount: Number(input.frame_count ?? 0),
    errorFrameCount: Number(input.error_frame_count ?? 0),
    extractedFrameCount: Number(input.extracted_frame_count ?? 0),
    exportFilename: String(input.export_filename ?? "winrm-decrypt.txt"),
    message: String(input.message ?? ""),
  };
}

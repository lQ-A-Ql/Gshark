import type { WinRMDecryptResult } from "../../core/types";
import type { WinRMDecryptResultWireDTO } from "../wire/toolWireDtos";
import { asPlainObject } from "./mapperPrimitives";

export function asWinRMDecryptResult(input: unknown, fallbackPort = 0): WinRMDecryptResult {
  const payload: WinRMDecryptResultWireDTO = asPlainObject(input) ?? {};
  return {
    resultId: String(payload.result_id ?? ""),
    captureName: String(payload.capture_name ?? ""),
    port: Number(payload.port ?? fallbackPort ?? 0),
    authMode: String(payload.auth_mode ?? ""),
    previewText: String(payload.preview_text ?? ""),
    previewTruncated: Boolean(payload.preview_truncated),
    lineCount: Number(payload.line_count ?? 0),
    frameCount: Number(payload.frame_count ?? 0),
    errorFrameCount: Number(payload.error_frame_count ?? 0),
    extractedFrameCount: Number(payload.extracted_frame_count ?? 0),
    exportFilename: String(payload.export_filename ?? "winrm-decrypt.txt"),
    message: String(payload.message ?? ""),
  };
}

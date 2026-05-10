import type { CaptureTransactionStatus } from "./sentinelTypes";
import { getCaptureEmptyParseError, getCaptureOpenErrorMessage, getCapturePreloadTimeoutError } from "./capturePreloadStatus";

export function createIdleCaptureTransactionStatus(hasActiveCapture = false): CaptureTransactionStatus {
  return {
    phase: "idle",
    reason: "",
    message: "",
    pendingCaptureName: "",
    pendingCapturePath: "",
    hasActiveCapture,
  };
}

export function createPendingCaptureTransactionStatus(
  pendingCaptureName: string,
  pendingCapturePath: string,
  hasActiveCapture: boolean,
): CaptureTransactionStatus {
  return {
    phase: "pending",
    reason: "",
    message: "",
    pendingCaptureName,
    pendingCapturePath,
    hasActiveCapture,
  };
}

export function createFailedCaptureTransactionStatus(
  reason: CaptureTransactionStatus["reason"],
  message: string,
  pendingCaptureName: string,
  pendingCapturePath: string,
  hasActiveCapture: boolean,
): CaptureTransactionStatus {
  return {
    phase: "failed",
    reason,
    message,
    pendingCaptureName,
    pendingCapturePath,
    hasActiveCapture,
  };
}

export function buildFailedCaptureTransactionStatus(options: {
  readonly error: unknown;
  readonly parseError: string;
  readonly hadActiveCapture: boolean;
  readonly fallbackName: string;
  readonly fallbackPath: string;
  readonly pendingCaptureName?: string;
  readonly pendingCapturePath?: string;
}): CaptureTransactionStatus {
  const message = getCaptureOpenErrorMessage(options.error);
  const normalizedMessage = message || "打开文件失败";
  const reason =
    normalizedMessage === getCapturePreloadTimeoutError()
      ? "preload_timeout"
      : normalizedMessage === getCaptureEmptyParseError("")
        ? "empty_parse"
        : options.hadActiveCapture
          ? "switch_failed"
          : "open_failed";

  return createFailedCaptureTransactionStatus(
    reason,
    normalizedMessage,
    options.pendingCaptureName ?? options.fallbackName,
    options.pendingCapturePath ?? options.fallbackPath,
    options.hadActiveCapture,
  );
}

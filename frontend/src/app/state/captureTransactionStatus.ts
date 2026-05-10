import type { CaptureTransactionStatus } from "./sentinelTypes";

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

import type { CaptureStatus } from "../integrations/bridgeTypes";

export function normalizeCapturePathForCompare(path: string): string {
  return path.trim().replace(/\\/g, "/").toLowerCase();
}

export function isCommittedCaptureStatusForPath(status: CaptureStatus | null | undefined, filePath: string): boolean {
  if (!status?.hasCapture || status.packetCount <= 0) return false;
  return normalizeCapturePathForCompare(status.filePath) === normalizeCapturePathForCompare(filePath);
}

import { useState, type Dispatch, type SetStateAction } from "react";
import { createInitialCaptureFileMeta, type CaptureFileMeta } from "../captureOpenState";
import { createIdleCaptureTransactionStatus } from "../captureTransactionStatus";
import type { CaptureTransactionStatus } from "../sentinelTypes";

export interface UseCaptureSessionStateResult {
  readonly captureTransaction: CaptureTransactionStatus;
  readonly setCaptureTransaction: Dispatch<SetStateAction<CaptureTransactionStatus>>;
  readonly fileMeta: CaptureFileMeta;
  readonly setFileMeta: Dispatch<SetStateAction<CaptureFileMeta>>;
  readonly captureRevision: number;
  readonly setCaptureRevision: Dispatch<SetStateAction<number>>;
}

/**
 * Owns the capture session metadata slice:
 * - `captureTransaction` — pending/failed state of the active load
 * - `fileMeta` — PCAP file metadata
 * - `captureRevision` — bumps each time the capture is cleared or replaced
 */
export function useCaptureSessionState(): UseCaptureSessionStateResult {
  const [captureTransaction, setCaptureTransaction] = useState<CaptureTransactionStatus>(() =>
    createIdleCaptureTransactionStatus(false),
  );
  const [fileMeta, setFileMeta] = useState<CaptureFileMeta>(createInitialCaptureFileMeta);
  const [captureRevision, setCaptureRevision] = useState(0);

  return {
    captureTransaction,
    setCaptureTransaction,
    fileMeta,
    setFileMeta,
    captureRevision,
    setCaptureRevision,
  };
}

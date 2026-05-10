import { useCallback, useRef } from "react";
import {
  waitForCaptureSignal as waitForCaptureSignalUtil,
  wakeCaptureWaiters as wakeCaptureWaitersUtil,
} from "../captureSignal";

export function useCaptureSignalWaiters() {
  const captureWaitersRef = useRef(new Set<() => void>());

  const wakeCaptureWaiters = useCallback(() => {
    wakeCaptureWaitersUtil(captureWaitersRef.current);
  }, []);

  const waitForCaptureSignal = useCallback(
    (delayMs: number) => waitForCaptureSignalUtil(captureWaitersRef.current, delayMs),
    [],
  );

  return { captureWaitersRef, wakeCaptureWaiters, waitForCaptureSignal };
}

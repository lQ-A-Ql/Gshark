import { describe, expect, it } from "vitest";
import type { CaptureTransactionStatus } from "./sentinelTypes";
import { initializeCaptureStartState } from "./captureStartState";

describe("initializeCaptureStartState", () => {
  it("resets preload state, starts parse runtime, and records the pending capture", () => {
    const preloadProcessedRef = { current: 12 };
    const preloadTotalRef = { current: 24 };
    const parseFinishedRef = { current: true };
    const parseErrorRef = { current: "old parse error" };
    const preloadingRef = { current: false };
    const recentCaptures: unknown[] = [];
    let isFilterLoading = true;
    let packetPageError = "old packet error";
    let preloadProcessed = 12;
    let preloadTotal = 24;
    let isPreloadingCapture = false;
    let transaction: CaptureTransactionStatus | null = null;

    initializeCaptureStartState({
      opened: { fileName: "sample.pcapng", filePath: "C:/captures/sample.pcapng", fileSize: 42 },
      openedAt: "2026-05-11T01:50:00.000Z",
      hadActiveCapture: true,
      preloadProcessedRef,
      preloadTotalRef,
      parseFinishedRef,
      parseErrorRef,
      preloadingRef,
      setIsFilterLoading: (value) => {
        isFilterLoading = Boolean(value);
      },
      setPacketPageError: (value) => {
        packetPageError = String(value);
      },
      setPreloadProcessed: (value) => {
        preloadProcessed = Number(value);
      },
      setPreloadTotal: (value) => {
        preloadTotal = Number(value);
      },
      setIsPreloadingCapture: (value) => {
        isPreloadingCapture = Boolean(value);
      },
      setCaptureTransaction: (value) => {
        transaction = value as CaptureTransactionStatus;
      },
      rememberRecentCapture: (capture) => {
        recentCaptures.push(capture);
      },
    });

    expect(isFilterLoading).toBe(false);
    expect(packetPageError).toBe("");
    expect(preloadProcessed).toBe(0);
    expect(preloadTotal).toBe(0);
    expect(preloadProcessedRef.current).toBe(0);
    expect(preloadTotalRef.current).toBe(0);
    expect(isPreloadingCapture).toBe(true);
    expect(parseFinishedRef.current).toBe(false);
    expect(parseErrorRef.current).toBe("");
    expect(preloadingRef.current).toBe(true);
    expect(transaction).toMatchObject({
      phase: "pending",
      pendingCaptureName: "sample.pcapng",
      pendingCapturePath: "C:/captures/sample.pcapng",
      hasActiveCapture: true,
    });
    expect(recentCaptures).toEqual([
      {
        name: "sample.pcapng",
        path: "C:/captures/sample.pcapng",
        sizeBytes: 42,
        lastOpenedAt: "2026-05-11T01:50:00.000Z",
      },
    ]);
  });
});

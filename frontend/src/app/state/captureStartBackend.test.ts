import { describe, expect, it, vi } from "vitest";
import type { CaptureTransactionStatus } from "./sentinelTypes";
import { createCaptureTaskScope } from "../utils/captureTaskScope";
import { prepareAndStartOpenedCapture, resolveOpenedCapture, startCaptureBackend } from "./captureStartBackend";

const opened = { fileName: "sample.pcapng", filePath: "C:/captures/sample.pcapng", fileSize: 42 };

describe("captureStartBackend", () => {
  it("uses a provided path without opening a file dialog", async () => {
    const openPcapFile = vi.fn(async () => opened);

    await expect(resolveOpenedCapture({ filePath: " C:/captures/inline.pcap ", openPcapFile })).resolves.toEqual({
      fileName: "inline.pcap",
      filePath: "C:/captures/inline.pcap",
      fileSize: 0,
    });
    expect(openPcapFile).not.toHaveBeenCalled();
  });

  it("opens the file dialog when no usable path is provided", async () => {
    const openPcapFile = vi.fn(async () => opened);

    await expect(resolveOpenedCapture({ filePath: "", openPcapFile })).resolves.toBe(opened);
    expect(openPcapFile).toHaveBeenCalledTimes(1);
  });

  it("starts backend streaming and returns true while the task is current", async () => {
    const captureTaskScopeRef = { current: createCaptureTaskScope() };
    const startStreamingPackets = vi.fn(async () => undefined);

    await expect(
      startCaptureBackend({
        opened,
        captureSeq: 1,
        captureSeqRef: { current: 1 },
        captureTaskScopeRef,
        startStreamingPackets,
      }),
    ).resolves.toBe(true);

    expect(startStreamingPackets).toHaveBeenCalledWith(opened.filePath, "", expect.any(AbortSignal));
  });

  it("returns false when a newer capture sequence wins during backend start", async () => {
    const captureSeqRef = { current: 1 };
    const captureTaskScopeRef = { current: createCaptureTaskScope() };
    const startStreamingPackets = vi.fn(async () => {
      captureSeqRef.current = 2;
    });

    await expect(
      startCaptureBackend({
        opened,
        captureSeq: 1,
        captureSeqRef,
        captureTaskScopeRef,
        startStreamingPackets,
      }),
    ).resolves.toBe(false);
  });

  it("prepares replacement, initializes start state, starts streaming, and announces preload", async () => {
    const preloadProcessedRef = { current: 9 };
    const preloadTotalRef = { current: 12 };
    const parseFinishedRef = { current: true };
    const parseErrorRef = { current: "old" };
    const preloadingRef = { current: false };
    let transaction: CaptureTransactionStatus | null = null;
    const recentCaptures: unknown[] = [];
    const setBackendStatus = vi.fn();

    await expect(
      prepareAndStartOpenedCapture({
        opened,
        openedAt: "2026-05-11T02:30:00.000Z",
        hadActiveCapture: true,
        preloadProcessedRef,
        preloadTotalRef,
        parseFinishedRef,
        parseErrorRef,
        preloadingRef,
        prepareForCaptureReplacement: vi.fn(async () => undefined),
        setIsFilterLoading: vi.fn(),
        setPacketPageError: vi.fn(),
        setPreloadProcessed: vi.fn(),
        setPreloadTotal: vi.fn(),
        setIsPreloadingCapture: vi.fn(),
        setCaptureTransaction: (value) => {
          transaction = value as CaptureTransactionStatus;
        },
        setBackendStatus,
        rememberRecentCapture: (capture) => {
          recentCaptures.push(capture);
        },
        captureSeq: 1,
        captureSeqRef: { current: 1 },
        captureTaskScopeRef: { current: createCaptureTaskScope() },
        startStreamingPackets: vi.fn(async () => undefined),
      }),
    ).resolves.toBe(true);

    expect(parseFinishedRef.current).toBe(false);
    expect(preloadingRef.current).toBe(true);
    expect(transaction).toMatchObject({ phase: "pending", pendingCaptureName: "sample.pcapng" });
    expect(recentCaptures).toHaveLength(1);
    expect(setBackendStatus).toHaveBeenCalledWith("正在预加载全部数据: sample.pcapng");
  });
});

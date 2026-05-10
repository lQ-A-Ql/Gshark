import { describe, expect, it, vi } from "vitest";
import type { Packet } from "../core/types";
import { createCaptureTaskScope } from "../utils/captureTaskScope";
import type { CaptureStatus, PacketsPageResult } from "../integrations/clients/captureClient";
import { resolveCapturePreloadFirstPage } from "./capturePreloadProbe";

const opened = { fileName: "sample.pcapng", filePath: "C:/captures/sample.pcapng", fileSize: 42 };
const packet = { id: 1, proto: "TCP" } as Packet;

function createPage(overrides: Partial<PacketsPageResult> = {}): PacketsPageResult {
  return {
    items: [packet],
    nextCursor: 1,
    total: 1,
    hasMore: false,
    ...overrides,
  };
}

function createStatus(overrides: Partial<CaptureStatus> = {}): CaptureStatus {
  return {
    filePath: opened.filePath,
    hasCapture: true,
    packetCount: 1,
    ...overrides,
  };
}

function createOptions(overrides: Partial<Parameters<typeof resolveCapturePreloadFirstPage>[0]> = {}) {
  return {
    opened,
    filter: "",
    captureSeq: 1,
    captureSeqRef: { current: 1 },
    captureTaskScopeRef: { current: createCaptureTaskScope() },
    parseFinishedRef: { current: false },
    parseErrorRef: { current: "" },
    preloadProcessedRef: { current: 0 },
    preloadTotalRef: { current: 0 },
    listPacketsPage: vi.fn(async () => createPage()),
    getCaptureStatus: vi.fn(async () => createStatus()),
    waitForCaptureSignal: vi.fn(async () => undefined),
    setTotalPackets: vi.fn(),
    setPreloadProcessed: vi.fn(),
    pageSize: 50,
    timeoutMs: 100,
    pollIntervalMs: 5,
    signalWaitMs: 2,
    now: vi.fn(() => 0),
    ...overrides,
  };
}

describe("capturePreloadProbe", () => {
  it("returns the validated first page for the active opened capture", async () => {
    const options = createOptions();

    const result = await resolveCapturePreloadFirstPage(options);

    expect(result).toEqual({ items: [packet], total: 1, hasMore: false });
    expect(options.listPacketsPage).toHaveBeenCalledWith(0, 50, "", expect.any(AbortSignal));
    expect(options.setTotalPackets).toHaveBeenCalledWith(1);
    expect(options.setPreloadProcessed).toHaveBeenCalledWith(1);
    expect(options.preloadProcessedRef.current).toBe(1);
  });

  it("polls until capture status matches the opened capture", async () => {
    const options = createOptions({
      listPacketsPage: vi.fn().mockResolvedValueOnce(createPage({ items: [], total: 0 })).mockResolvedValue(createPage()),
      getCaptureStatus: vi
        .fn()
        .mockResolvedValueOnce(createStatus({ filePath: "C:/old.pcapng" }))
        .mockResolvedValue(createStatus()),
      now: vi.fn().mockReturnValueOnce(0).mockReturnValueOnce(0).mockReturnValueOnce(1),
    });

    const result = await resolveCapturePreloadFirstPage(options);

    expect(result?.total).toBe(1);
    expect(options.waitForCaptureSignal).toHaveBeenCalledWith(5);
    expect(options.listPacketsPage).toHaveBeenCalledTimes(3);
  });

  it("returns null when capture sequence changes during probing", async () => {
    const captureSeqRef = { current: 1 };
    const options = createOptions({
      captureSeqRef,
      listPacketsPage: vi.fn(async () => {
        captureSeqRef.current = 2;
        return createPage();
      }),
    });

    await expect(resolveCapturePreloadFirstPage(options)).resolves.toBeNull();
  });

  it("throws the parse error when parsing finishes without packets", async () => {
    const options = createOptions({
      parseFinishedRef: { current: true },
      parseErrorRef: { current: "tshark parse failed" },
      listPacketsPage: vi.fn(async () => createPage({ items: [], total: 0 })),
      getCaptureStatus: vi.fn(async () => createStatus({ packetCount: 0 })),
      now: vi.fn(() => 0),
    });

    await expect(resolveCapturePreloadFirstPage(options)).rejects.toThrow("tshark parse failed");
  });

  it("throws timeout when no active capture is confirmed before the deadline", async () => {
    const options = createOptions({
      listPacketsPage: vi.fn(async () => createPage({ items: [], total: 0 })),
      getCaptureStatus: vi.fn(async () => createStatus({ filePath: "C:/old.pcapng" })),
      now: vi.fn().mockReturnValueOnce(0).mockReturnValueOnce(200),
    });

    await expect(resolveCapturePreloadFirstPage(options)).rejects.toThrow(
      "capture parsing timed out before preloading finished",
    );
  });
});

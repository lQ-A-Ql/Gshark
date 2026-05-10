import { describe, expect, it, vi } from "vitest";
import type { PacketsPageResult } from "../integrations/clients/captureClient";
import { runPacketFilterWorkflow } from "./packetFilterWorkflow";

function createPage(filtering = false): PacketsPageResult {
  return {
    items: [],
    nextCursor: 0,
    total: 0,
    hasMore: false,
    filtering,
  };
}

function createOptions(overrides: Partial<Parameters<typeof runPacketFilterWorkflow>[0]> = {}) {
  return {
    filter: "tcp.port == 80",
    shouldRun: true,
    pollUntilSettled: true,
    filterSeqRef: { current: 0 },
    loadPacketPage: vi.fn(async () => createPage(false)),
    resetPacketViewport: vi.fn(),
    setIsFilterLoading: vi.fn(),
    setPacketPageError: vi.fn(),
    setBackendStatus: vi.fn(),
    now: vi.fn(() => 1000),
    sleep: vi.fn(async () => undefined),
    pollIntervalMs: 5,
    pollTimeoutMs: 100,
    ...overrides,
  };
}

describe("packetFilterWorkflow", () => {
  it("starts a filter request and finalizes status when a page returns", async () => {
    const options = createOptions();

    await runPacketFilterWorkflow(options);

    expect(options.filterSeqRef.current).toBe(1);
    expect(options.setIsFilterLoading).toHaveBeenNthCalledWith(1, true);
    expect(options.setIsFilterLoading).toHaveBeenLastCalledWith(false);
    expect(options.setPacketPageError).toHaveBeenCalledWith("");
    expect(options.resetPacketViewport).toHaveBeenCalledTimes(1);
    expect(options.loadPacketPage).toHaveBeenCalledWith(0, "tcp.port == 80");
    expect(options.setBackendStatus).toHaveBeenNthCalledWith(1, "正在应用过滤器: tcp.port == 80");
    expect(options.setBackendStatus).toHaveBeenLastCalledWith("过滤器已应用: tcp.port == 80");
  });

  it("polls until the backend reports the filter page is settled", async () => {
    const options = createOptions({
      loadPacketPage: vi.fn().mockResolvedValueOnce(createPage(true)).mockResolvedValueOnce(createPage(false)),
      now: vi.fn().mockReturnValueOnce(1000).mockReturnValueOnce(1001),
    });

    await runPacketFilterWorkflow(options);

    expect(options.setBackendStatus).toHaveBeenCalledWith("过滤器仍在后台扫描: tcp.port == 80");
    expect(options.sleep).toHaveBeenCalledWith(5);
    expect(options.loadPacketPage).toHaveBeenCalledTimes(2);
    expect(options.setIsFilterLoading).toHaveBeenLastCalledWith(false);
  });

  it("does not poll clear-filter workflow when polling is disabled", async () => {
    const options = createOptions({
      filter: "",
      pollUntilSettled: false,
      loadPacketPage: vi.fn(async () => createPage(true)),
    });

    await runPacketFilterWorkflow(options);

    expect(options.loadPacketPage).toHaveBeenCalledTimes(1);
    expect(options.sleep).not.toHaveBeenCalled();
    expect(options.setBackendStatus).toHaveBeenLastCalledWith("过滤器已清空");
  });

  it("skips backend work when workflow should not run", async () => {
    const options = createOptions({ shouldRun: false });

    await runPacketFilterWorkflow(options);

    expect(options.filterSeqRef.current).toBe(0);
    expect(options.loadPacketPage).not.toHaveBeenCalled();
    expect(options.setIsFilterLoading).not.toHaveBeenCalled();
  });

  it("does not finalize stale filter work when a newer sequence wins", async () => {
    const filterSeqRef = { current: 0 };
    const options = createOptions({
      filterSeqRef,
      loadPacketPage: vi.fn(async () => {
        filterSeqRef.current += 1;
        return createPage(false);
      }),
    });

    await runPacketFilterWorkflow(options);

    expect(options.setIsFilterLoading).toHaveBeenCalledWith(true);
    expect(options.setIsFilterLoading).not.toHaveBeenCalledWith(false);
    expect(options.setBackendStatus).not.toHaveBeenCalledWith("过滤器已应用: tcp.port == 80");
  });
});

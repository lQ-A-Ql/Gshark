import { describe, expect, it, vi } from "vitest";
import type { PacketsPageResult } from "../integrations/clients/captureClient";
import { runPacketFilterAction } from "./packetFilterAction";

function createPage(): PacketsPageResult {
  return {
    items: [],
    nextCursor: 0,
    total: 0,
    hasMore: false,
    filtering: false,
  };
}

function createOptions(overrides: Partial<Parameters<typeof runPacketFilterAction>[0]> = {}) {
  return {
    filter: "tcp.port == 443",
    syncDisplayFilter: true,
    pollUntilSettled: true,
    shouldRun: true,
    filterSeqRef: { current: 0 },
    loadPacketPage: vi.fn(async () => createPage()),
    resetPacketViewport: vi.fn(),
    setDisplayFilter: vi.fn(),
    setIsFilterLoading: vi.fn(),
    setPacketPageError: vi.fn(),
    setBackendStatus: vi.fn(),
    ...overrides,
  };
}

describe("packetFilterAction", () => {
  it("syncs explicit display filter and runs the backend workflow", async () => {
    const options = createOptions();

    await runPacketFilterAction(options);

    expect(options.setDisplayFilter).toHaveBeenCalledWith("tcp.port == 443");
    expect(options.filterSeqRef.current).toBe(1);
    expect(options.loadPacketPage).toHaveBeenCalledWith(0, "tcp.port == 443");
    expect(options.resetPacketViewport).toHaveBeenCalledTimes(1);
  });

  it("keeps the typed display filter untouched when applying the current value", async () => {
    const options = createOptions({ syncDisplayFilter: false });

    await runPacketFilterAction(options);

    expect(options.setDisplayFilter).not.toHaveBeenCalled();
    expect(options.loadPacketPage).toHaveBeenCalledWith(0, "tcp.port == 443");
  });

  it("clears the display filter without polling for a settled page", async () => {
    const options = createOptions({
      filter: "",
      pollUntilSettled: false,
      loadPacketPage: vi.fn(async () => ({ ...createPage(), filtering: true })),
    });

    await runPacketFilterAction(options);

    expect(options.setDisplayFilter).toHaveBeenCalledWith("");
    expect(options.loadPacketPage).toHaveBeenCalledTimes(1);
    expect(options.setBackendStatus).toHaveBeenLastCalledWith("过滤器已清空");
  });

  it("skips backend work when no capture is active", async () => {
    const options = createOptions({ shouldRun: false });

    await runPacketFilterAction(options);

    expect(options.setDisplayFilter).toHaveBeenCalledWith("tcp.port == 443");
    expect(options.filterSeqRef.current).toBe(0);
    expect(options.loadPacketPage).not.toHaveBeenCalled();
  });
});

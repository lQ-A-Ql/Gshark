import { describe, expect, it, vi } from "vitest";
import type { Packet } from "../core/types";
import type { PacketLocateResult, PacketsPageResult } from "../integrations/clients/captureClient";
import { createCaptureTaskScope } from "../utils/captureTaskScope";
import { locatePacketByIdWorkflow } from "./packetLocateWorkflow";

const packet = (id: number): Packet => ({ id, proto: "TCP" }) as Packet;

function createLocateResult(overrides: Partial<PacketLocateResult> = {}): PacketLocateResult {
  return {
    packetId: 7,
    cursor: 100,
    total: 200,
    found: true,
    ...overrides,
  };
}

function createPage(items: Packet[] = [packet(7)]): PacketsPageResult {
  return {
    items,
    nextCursor: 200,
    total: items.length,
    hasMore: false,
  };
}

function createOptions(overrides: Partial<Parameters<typeof locatePacketByIdWorkflow>[0]> = {}) {
  return {
    packetId: 7.8,
    pageSize: 100,
    displayFilter: "tcp",
    activeCapturePathRef: { current: "sample.pcapng" },
    captureTaskScopeRef: { current: createCaptureTaskScope() },
    locatePacketPage: vi.fn(async () => createLocateResult()),
    loadPacketPage: vi.fn(async () => createPage()),
    setDisplayFilter: vi.fn(),
    setSelectedPacketId: vi.fn(),
    setBackendStatus: vi.fn(),
    ...overrides,
  };
}

describe("packetLocateWorkflow", () => {
  it("locates a packet page, loads it, and selects the normalized packet id", async () => {
    const options = createOptions();

    const result = await locatePacketByIdWorkflow(options);

    expect(result).toMatchObject({ id: 7 });
    expect(options.locatePacketPage).toHaveBeenCalledWith(7, 100, "tcp", expect.any(AbortSignal));
    expect(options.loadPacketPage).toHaveBeenCalledWith(100, "tcp");
    expect(options.setSelectedPacketId).toHaveBeenCalledWith(7);
  });

  it("applies the override filter before loading the located packet page", async () => {
    const options = createOptions({ filterOverride: "udp" });

    await locatePacketByIdWorkflow(options);

    expect(options.locatePacketPage).toHaveBeenCalledWith(7, 100, "udp", expect.any(AbortSignal));
    expect(options.setDisplayFilter).toHaveBeenCalledWith("udp");
    expect(options.loadPacketPage).toHaveBeenCalledWith(100, "udp");
  });

  it("reports a missing packet without loading a page", async () => {
    const options = createOptions({
      locatePacketPage: vi.fn(async () => createLocateResult({ found: false })),
    });

    await expect(locatePacketByIdWorkflow(options)).resolves.toBeNull();

    expect(options.setBackendStatus).toHaveBeenCalledWith("未找到数据包 #7");
    expect(options.loadPacketPage).not.toHaveBeenCalled();
    expect(options.setSelectedPacketId).not.toHaveBeenCalled();
  });

  it("does not start locate work for invalid ids or missing captures", async () => {
    const options = createOptions({ packetId: Number.NaN, activeCapturePathRef: { current: "" } });

    await expect(locatePacketByIdWorkflow(options)).resolves.toBeNull();

    expect(options.locatePacketPage).not.toHaveBeenCalled();
    expect(options.loadPacketPage).not.toHaveBeenCalled();
  });

  it("keeps aborts and stale results quiet", async () => {
    const options = createOptions({
      locatePacketPage: vi.fn(async () => {
        options.captureTaskScopeRef.current.invalidate();
        throw new DOMException("aborted", "AbortError");
      }),
    });

    await expect(locatePacketByIdWorkflow(options)).resolves.toBeNull();

    expect(options.setBackendStatus).not.toHaveBeenCalled();
    expect(options.setSelectedPacketId).not.toHaveBeenCalled();
  });

  it("maps non-abort failures to backend status", async () => {
    const options = createOptions({
      locatePacketPage: vi.fn(async () => {
        throw new Error("locate failed");
      }),
    });

    await expect(locatePacketByIdWorkflow(options)).resolves.toBeNull();

    expect(options.setBackendStatus).toHaveBeenCalledWith("locate failed");
  });
});

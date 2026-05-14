import { describe, expect, it, vi } from "vitest";
import { createStreamClient } from "./streamClient";

type JsonRequest = <T>(path: string, init?: RequestInit) => Promise<T>;

describe("streamClient packet resource methods", () => {
  it("maps stream indexes and preserves abort signals", async () => {
    const signal = new AbortController().signal;
    const request = vi.fn(async (path: string, init?: RequestInit) => {
      expect(path).toBe("/api/streams/index?protocol=TCP");
      expect(init?.signal).toBe(signal);
      return { ids: ["3", 1, -1, "bad", 2] };
    }) as unknown as JsonRequest;

    await expect(createStreamClient(request).listStreamIds("TCP", signal)).resolves.toEqual([1, 2, 3]);
  });

  it("maps packet raw hex payloads", async () => {
    const signal = new AbortController().signal;
    const request = vi.fn(async (path: string, init?: RequestInit) => {
      expect(path).toBe("/api/packet/raw?id=42");
      expect(init?.signal).toBe(signal);
      return { raw_hex: "de ad be ef" };
    }) as unknown as JsonRequest;

    await expect(createStreamClient(request).getPacketRawHex(42, signal)).resolves.toBe("de ad be ef");
  });

  it("maps packet layer objects and rejects non-object layers", async () => {
    const request = vi
      .fn()
      .mockResolvedValueOnce({ layers: { frame: { frame_number: "42" }, tcp: {} } })
      .mockResolvedValueOnce({ layers: ["bad"] }) as unknown as JsonRequest;
    const client = createStreamClient(request);

    await expect(client.getPacketLayers(42)).resolves.toEqual({ frame: { frame_number: "42" }, tcp: {} });
    await expect(client.getPacketLayers(43)).resolves.toBeNull();
  });
});

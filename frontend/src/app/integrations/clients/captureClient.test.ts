import { describe, expect, it, vi } from "vitest";
import { asCaptureStatus, createCaptureClient } from "./captureClient";

type JsonRequest = <T>(path: string, init?: RequestInit) => Promise<T>;

const packet = {
  id: 42,
  timestamp: "2026-05-14T00:00:00Z",
  source_ip: "10.0.0.1",
  source_port: 1234,
  dest_ip: "10.0.0.2",
  dest_port: 80,
  protocol: "TCP",
  display_protocol: "HTTP",
  length: 128,
  info: "GET /",
  payload: "GET / HTTP/1.1",
  raw_hex: "474554",
  stream_id: 7,
  color_features: { tcp_syn: true },
};

describe("captureClient transport mapping", () => {
  it("maps capture status snake_case and legacy camelCase payloads", async () => {
    const signal = new AbortController().signal;
    const request = vi.fn(async (path: string, init?: RequestInit) => {
      expect(path).toBe("/api/capture/status");
      expect(init?.signal).toBe(signal);
      return { file_path: "C:/sample.pcapng", has_capture: true, packet_count: 42 };
    }) as unknown as JsonRequest;

    await expect(createCaptureClient(request, () => undefined).getCaptureStatus(signal)).resolves.toEqual({
      filePath: "C:/sample.pcapng",
      hasCapture: true,
      packetCount: 42,
    });
    expect(asCaptureStatus({ filePath: "legacy.pcap", hasCapture: true, packetCount: 3 })).toEqual({
      filePath: "legacy.pcap",
      hasCapture: true,
      packetCount: 3,
    });
  });

  it("maps packet lists and paged packet payloads", async () => {
    const signal = new AbortController().signal;
    const requestMock = vi
      .fn()
      .mockResolvedValueOnce([packet])
      .mockResolvedValueOnce({ items: [packet], next_cursor: 50, total: 120, has_more: true, filtering: true });
    const request = requestMock as unknown as JsonRequest;
    const client = createCaptureClient(request, () => undefined);

    await expect(client.listPackets()).resolves.toMatchObject([{ id: 42, src: "10.0.0.1", dst: "10.0.0.2" }]);
    await expect(client.listPacketsPage(0, 50, "tcp", signal)).resolves.toMatchObject({
      items: [{ id: 42, src: "10.0.0.1", dst: "10.0.0.2" }],
      nextCursor: 50,
      total: 120,
      hasMore: true,
      filtering: true,
    });
    expect(requestMock).toHaveBeenNthCalledWith(1, "/api/packets");
    expect(requestMock).toHaveBeenNthCalledWith(2, "/api/packets/page?cursor=0&limit=50&filter=tcp", { signal });
  });

  it("maps packet locate and packet detail payloads", async () => {
    const signal = new AbortController().signal;
    const requestMock = vi
      .fn()
      .mockResolvedValueOnce({ packet_id: 42, cursor: 100, total: 200, found: true })
      .mockResolvedValueOnce(packet);
    const request = requestMock as unknown as JsonRequest;
    const client = createCaptureClient(request, () => undefined);

    await expect(client.locatePacketPage(42, 50, "http", signal)).resolves.toEqual({
      packetId: 42,
      cursor: 100,
      total: 200,
      found: true,
    });
    await expect(client.getPacket(42, signal)).resolves.toMatchObject({
      id: 42,
      displayProtocol: "HTTP",
      payload: "GET / HTTP/1.1",
      rawHex: "474554",
      streamId: 7,
      colorFeatures: { tcpSyn: true },
    });
    expect(requestMock).toHaveBeenNthCalledWith(1, "/api/packets/locate?id=42&limit=50&filter=http", { signal });
    expect(requestMock).toHaveBeenNthCalledWith(2, "/api/packet?id=42", { signal });
  });
});

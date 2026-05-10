import { describe, expect, it, vi } from "vitest";
import type { Packet } from "../core/types";
import { preparePacketStreamState } from "./packetStreamPrepare";

function packet(overrides: Partial<Packet> = {}): Packet {
  return { id: 7, proto: "HTTP", streamId: 3, ...overrides } as Packet;
}

function createOptions(overrides: Partial<Parameters<typeof preparePacketStreamState>[0]> = {}) {
  return {
    packetId: 7,
    locatePacketById: vi.fn(async () => packet()),
    setActiveStream: vi.fn(async () => undefined),
    ...overrides,
  };
}

describe("packetStreamPrepare", () => {
  it("locates a packet, resolves its protocol, and activates its stream", async () => {
    const options = createOptions();

    const result = await preparePacketStreamState(options);

    expect(options.locatePacketById).toHaveBeenCalledWith(7, undefined);
    expect(options.setActiveStream).toHaveBeenCalledWith("HTTP", 3);
    expect(result).toMatchObject({ packet: { id: 7 }, protocol: "HTTP", streamId: 3 });
  });

  it("uses preferred protocol and passes through filter override", async () => {
    const options = createOptions({
      preferredProtocol: "UDP",
      filterOverride: "frame.number == 7",
      locatePacketById: vi.fn(async () => packet({ proto: "TCP", streamId: 9 })),
    });

    const result = await preparePacketStreamState(options);

    expect(options.locatePacketById).toHaveBeenCalledWith(7, "frame.number == 7");
    expect(options.setActiveStream).toHaveBeenCalledWith("UDP", 9);
    expect(result).toMatchObject({ protocol: "UDP", streamId: 9 });
  });

  it("does not activate a stream when no packet or stream id is available", async () => {
    for (const located of [null, packet({ streamId: undefined }), packet({ streamId: -1 })]) {
      const options = createOptions({ locatePacketById: vi.fn(async () => located) });

      const result = await preparePacketStreamState(options);

      expect(result).toMatchObject({ packet: located, protocol: null, streamId: null });
      expect(options.setActiveStream).not.toHaveBeenCalled();
    }
  });
});

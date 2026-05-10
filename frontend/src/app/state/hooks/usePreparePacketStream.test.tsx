import { act, renderHook } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { Packet } from "../../core/types";
import { usePreparePacketStream } from "./usePreparePacketStream";

function packet(overrides: Partial<Packet> = {}): Packet {
  return { id: 7, proto: "HTTP", streamId: 3, ...overrides } as Packet;
}

describe("usePreparePacketStream", () => {
  it("binds packet lookup and stream activation to packet stream preparation", async () => {
    const locatePacketById = vi.fn(async () => packet({ proto: "TCP", streamId: 9 }));
    const setActiveStream = vi.fn(async () => undefined);
    const { result } = renderHook(() => usePreparePacketStream({ locatePacketById, setActiveStream }));

    let prepared: Awaited<ReturnType<typeof result.current>> | undefined;
    await act(async () => {
      prepared = await result.current(7, "UDP", "frame.number == 7");
    });

    expect(locatePacketById).toHaveBeenCalledWith(7, "frame.number == 7");
    expect(setActiveStream).toHaveBeenCalledWith("UDP", 9);
    expect(prepared).toMatchObject({ packet: { id: 7 }, protocol: "UDP", streamId: 9 });
  });
});

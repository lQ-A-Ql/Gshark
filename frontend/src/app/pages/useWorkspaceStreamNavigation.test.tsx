import { renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Packet, StreamProtocol } from "../core/types";
import { useWorkspaceStreamNavigation } from "./useWorkspaceStreamNavigation";

const mocks = vi.hoisted(() => ({
  navigate: vi.fn(),
}));

vi.mock("react-router", () => ({
  useNavigate: () => mocks.navigate,
}));

function makePacket(streamId: number | null): Packet {
  return {
    id: 42,
    time: "00:00:00",
    src: "10.0.0.1",
    srcPort: 1234,
    dst: "10.0.0.2",
    dstPort: 443,
    proto: "TCP",
    length: 128,
    info: "packet",
    payload: "",
    streamId: streamId ?? undefined,
  };
}

describe("useWorkspaceStreamNavigation", () => {
  beforeEach(() => {
    mocks.navigate.mockReset();
  });

  it("selects packet and navigates to the selected stream target", () => {
    const selectPacket = vi.fn();
    const setActiveStream = vi.fn();
    const { result } = renderHook(() => useWorkspaceStreamNavigation({ selectPacket, setActiveStream }));

    result.current.followStream(makePacket(7), "udp");

    expect(selectPacket).toHaveBeenCalledWith(42);
    expect(setActiveStream).toHaveBeenCalledWith("UDP" satisfies StreamProtocol, 7);
    expect(mocks.navigate).toHaveBeenCalledWith("/udp-stream", { state: { streamId: 7 } });
  });

  it("does not navigate packets without stream ids", () => {
    const selectPacket = vi.fn();
    const setActiveStream = vi.fn();
    const { result } = renderHook(() => useWorkspaceStreamNavigation({ selectPacket, setActiveStream }));

    result.current.followStream(makePacket(null), "tcp");

    expect(selectPacket).not.toHaveBeenCalled();
    expect(setActiveStream).not.toHaveBeenCalled();
    expect(mocks.navigate).not.toHaveBeenCalled();
  });

  it("opens the HTTP stream list without selecting a packet", () => {
    const { result } = renderHook(() =>
      useWorkspaceStreamNavigation({ selectPacket: vi.fn(), setActiveStream: vi.fn() }),
    );

    result.current.openHttpStream();

    expect(mocks.navigate).toHaveBeenCalledWith("/http-stream");
  });
});

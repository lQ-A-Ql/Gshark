import { describe, expect, it } from "vitest";
import type { Packet } from "./types";
import { getPacketColorStyle } from "./packetColoring";

function packet(proto: string, overrides: Partial<Packet> = {}): Packet {
  return {
    id: 1,
    proto,
    info: "",
    payload: "",
    ...overrides,
  } as Packet;
}

describe("packet coloring", () => {
  it("prioritizes bad TCP signals over generic TCP coloring", () => {
    const style = getPacketColorStyle(
      packet("TCP", {
        info: "TCP Retransmission",
      }),
    );

    expect(style?.ruleName).toBe("Bad TCP");
    expect(style?.backgroundGradient).toContain("linear-gradient");
  });

  it("matches HTTP and ARP protocol rules", () => {
    expect(getPacketColorStyle(packet("HTTP"))?.ruleName).toBe("HTTP");
    expect(getPacketColorStyle(packet("ARP"))?.ruleName).toBe("ARP");
  });
});

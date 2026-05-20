import { describe, expect, it } from "vitest";
import type { Packet } from "./types";
import { getPacketColorStyle } from "./packetColoring";

function packet(proto: string, overrides: Partial<Packet> = {}): Packet {
  return { id: 1, proto, info: "", payload: "", ...overrides } as Packet;
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
    expect(style?.backgroundGradient).toContain("rgba(31, 70, 86, 0.46)");
    expect(style?.backgroundGradient).toContain("rgba(31, 70, 86, 0.2)");
    expect(style?.backgroundGradient).toContain("rgba(31, 70, 86, 0.035)");
  });

  it("matches HTTP and ARP protocol rules", () => {
    const ruleNames = ["HTTP", "ARP"].map((proto) => getPacketColorStyle(packet(proto))?.ruleName);
    expect(ruleNames).toEqual(["HTTP", "ARP"]);
  });

  it("keeps protocol color intuition while softening the shader", () => {
    const http = getPacketColorStyle(packet("HTTP"));
    const arp = getPacketColorStyle(packet("ARP"));

    expect(http?.backgroundGradient).toContain("rgba(241, 255, 214, 0.46)");
    expect(http?.backgroundGradient).toContain("radial-gradient");
    expect(http?.color).toBe("rgb(0, 0, 0)");
    expect(arp?.backgroundGradient).toContain("rgba(255, 245, 226, 0.46)");
    expect(arp?.backgroundColor).toBe("rgb(255, 245, 226)");
  });
});

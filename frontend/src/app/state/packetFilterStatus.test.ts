import { describe, expect, it } from "vitest";
import {
  getPacketFilterDoneStatus,
  getPacketFilterPollingStatus,
  getPacketFilterWorkingStatus,
  normalizePacketFilterValue,
} from "./packetFilterStatus";

describe("packetFilterStatus", () => {
  it("normalizes filter values for status decisions", () => {
    expect(normalizePacketFilterValue("  tcp.port == 80  ")).toBe("tcp.port == 80");
    expect(normalizePacketFilterValue("   ")).toBe("");
  });

  it("returns applying, polling, and done messages for non-empty filters", () => {
    const filter = "tcp.port == 80";

    expect(getPacketFilterWorkingStatus(filter)).toBe("正在应用过滤器: tcp.port == 80");
    expect(getPacketFilterPollingStatus(filter)).toBe("过滤器仍在后台扫描: tcp.port == 80");
    expect(getPacketFilterDoneStatus(filter)).toBe("过滤器已应用: tcp.port == 80");
  });

  it("returns reset and cleared messages for empty filters", () => {
    expect(getPacketFilterWorkingStatus(" ")).toBe("正在重置过滤器");
    expect(getPacketFilterPollingStatus("")).toBe("正在重置过滤器");
    expect(getPacketFilterDoneStatus("")).toBe("过滤器已清空");
  });
});

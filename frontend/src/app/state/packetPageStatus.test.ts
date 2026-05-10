import { describe, expect, it } from "vitest";
import { getPacketPageLoadErrorMessage, getPacketPageRetryStatus } from "./packetPageStatus";

describe("packet page status", () => {
  it("keeps backend transport detail visible in packet page errors", () => {
    expect(getPacketPageLoadErrorMessage(new Error("无法连接后端接口 /api/packets/page"))).toBe(
      "数据面读取失败: 无法连接后端接口 /api/packets/page",
    );
  });

  it("uses a stable fallback for non-error failures", () => {
    expect(getPacketPageLoadErrorMessage("failed")).toBe("数据面读取失败: 数据包读取失败");
  });

  it("describes retries with the active filter when present", () => {
    expect(getPacketPageRetryStatus(" tcp.stream eq 3 ")).toBe("正在重新读取过滤结果: tcp.stream eq 3");
    expect(getPacketPageRetryStatus("")).toBe("正在重新读取数据包首页");
  });
});

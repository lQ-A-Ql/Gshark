import { describe, expect, it } from "vitest";
import type { MiscModuleManifest, StreamPayloadSource } from "../../core/types";
import {
  formatPayloadWebShellInputCounts,
  formatPayloadWebShellSelectedSource,
  getPayloadWebShellModuleBadges,
  getPayloadWebShellPanelTitle,
  PAYLOAD_WEBSHELL_MINI_STATS,
} from "./PayloadWebShellInputPanelUtils";

const moduleBase: MiscModuleManifest = {
  id: "payload-webshell-decoder",
  kind: "builtin",
  title: "Payload Decoder",
  summary: "Decode payload",
  tags: ["webshell"],
  apiPrefix: "/api/misc/payload-webshell-decoder",
  requiresCapture: false,
  cancellable: true,
  supportsExport: true,
};

const sourceBase: StreamPayloadSource = {
  id: "source-1",
  packetId: 7,
  streamId: 2,
  method: "POST",
  host: "target.test",
  uri: "/shell.php",
  payload: "pass=...",
};

describe("PayloadWebShellInputPanelUtils", () => {
  it("formats panel title and module badges", () => {
    expect(getPayloadWebShellPanelTitle(moduleBase, true)).toBe("手动 Payload 输入");
    expect(getPayloadWebShellPanelTitle(moduleBase, false)).toBe("Payload Decoder");
    expect(getPayloadWebShellModuleBadges(moduleBase).map((badge) => badge.label)).toEqual([
      "无需抓包",
      "可取消",
      "支持导出",
      "实验性",
    ]);
    expect(
      getPayloadWebShellModuleBadges({ ...moduleBase, requiresCapture: true, cancellable: false }).map(
        (badge) => badge.label,
      ),
    ).toEqual(["支持导出", "实验性"]);
  });

  it("keeps stat definitions stable", () => {
    expect(PAYLOAD_WEBSHELL_MINI_STATS).toEqual([
      { title: "HTTP 报文", value: "Request / Response", tone: "cyan" },
      { title: "参数来源", value: "Query / Form / Multipart", tone: "emerald" },
      { title: "结构化输入", value: "JSON / Body / 单参数", tone: "blue" },
      { title: "包裹编码", value: "Base64url / Hex / URL 多轮", tone: "amber" },
    ]);
  });

  it("formats selected source and input count summaries", () => {
    expect(formatPayloadWebShellSelectedSource(sourceBase)).toBe(
      "当前输入来自 packet #7 / stream 2 · POST target.test/shell.php",
    );
    expect(formatPayloadWebShellSelectedSource({ ...sourceBase, streamId: undefined, method: "" })).toBe(
      "当前输入来自 packet #7 · HTTP target.test/shell.php",
    );
    expect(formatPayloadWebShellInputCounts(1234, 56)).toBe("当前输入 1,234 字符，已提交分析 56 字符。");
  });
});

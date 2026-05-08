import { describe, expect, it } from "vitest";
import type { StreamPayloadSource } from "../../core/types";
import {
  formatPayloadWebShellPacketList,
  getPayloadWebShellConfidenceTone,
  getPayloadWebShellDecoderName,
  getPayloadWebShellLocationLabel,
  getPayloadWebShellMethodLabel,
  getPayloadWebShellPreviewText,
  getPayloadWebShellRuleReasons,
  getPayloadWebShellSignals,
  getPayloadWebShellSourceBadges,
  getPayloadWebShellSourceKey,
  isPayloadWebShellSourceSelected,
} from "./PayloadWebShellSourceUtils";

function createSource(overrides: Partial<StreamPayloadSource> = {}): StreamPayloadSource {
  return {
    id: "source-1",
    packetId: 42,
    method: "POST",
    host: "example.test",
    uri: "/shell.php",
    sourceType: "form",
    paramName: "pass",
    payload: "pass=YXNzZXJ0KCRfUE9TVFsnY21kJ10pOw==",
    preview: "assert($_POST['cmd']);",
    confidence: 91,
    signals: ["base64", "php", "eval", "assert", "cmd", "post", "extra"],
    decoderHints: ["behinder", "antsword", "godzilla"],
    familyHint: "webshell_like",
    decoderOptionsHint: { decoder: "behinder" },
    sourceRole: "request-body",
    occurrenceCount: 3,
    relatedPackets: [42, 43, 44, 45, 46, 47],
    ruleReasons: ["可疑参数名", "高熵参数值", "重复出现", "命令执行特征"],
    ...overrides,
  };
}

describe("PayloadWebShellSourceUtils", () => {
  it("formats source identity, location, method and preview labels", () => {
    const source = createSource();
    expect(getPayloadWebShellSourceKey(source)).toBe("source-1-42");
    expect(getPayloadWebShellMethodLabel(source)).toBe("POST");
    expect(getPayloadWebShellLocationLabel(source)).toBe("example.test/shell.php");
    expect(getPayloadWebShellPreviewText(source)).toBe("assert($_POST['cmd']);");
    expect(isPayloadWebShellSourceSelected(source, createSource())).toBe(true);
    expect(isPayloadWebShellSourceSelected(source, createSource({ packetId: 99 }))).toBe(false);
  });

  it("uses safe fallbacks for sparse sources", () => {
    const source = createSource({
      method: "",
      host: undefined,
      uri: undefined,
      preview: undefined,
      relatedPackets: undefined,
    });
    expect(getPayloadWebShellMethodLabel(source)).toBe("HTTP");
    expect(getPayloadWebShellLocationLabel(source)).toBe("");
    expect(getPayloadWebShellPreviewText(source)).toBe(source.payload);
    expect(formatPayloadWebShellPacketList(source.relatedPackets, source.packetId)).toBe("42");
  });

  it("builds bounded badges, reasons and signal chips", () => {
    const source = createSource();
    expect(getPayloadWebShellConfidenceTone(91)).toBe("emerald");
    expect(getPayloadWebShellConfidenceTone(60)).toBe("cyan");
    expect(getPayloadWebShellConfidenceTone(20)).toBe("amber");
    expect(getPayloadWebShellDecoderName(source.decoderOptionsHint)).toBe("behinder");
    expect(getPayloadWebShellSourceBadges(source).map((badge) => badge.label)).toEqual([
      "91%",
      "form:pass",
      "webshell_like",
      "request-body",
      "behinder",
      "behinder",
      "antsword",
      "重复 3 次",
    ]);
    expect(getPayloadWebShellRuleReasons(source)).toEqual(["可疑参数名", "高熵参数值", "重复出现"]);
    expect(getPayloadWebShellSignals(source)).toEqual(["base64", "php", "eval", "assert", "cmd", "post"]);
  });

  it("formats packet lists with truncation and empty fallback", () => {
    expect(formatPayloadWebShellPacketList([1, 2, 3], 42)).toBe("1, 2, 3");
    expect(formatPayloadWebShellPacketList([1, 2, 3, 4, 5, 6], 42)).toBe("1, 2, 3, 4, 5 +1");
    expect(formatPayloadWebShellPacketList([], undefined)).toBe("--");
  });
});

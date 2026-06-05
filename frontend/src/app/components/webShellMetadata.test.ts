import { describe, expect, it } from "vitest";

import {
  getWebShellDecoderLabel,
  getWebShellFamilyLabel,
  getWebShellMetadataSummary,
  getWebShellVersionLabel,
  isChinaChopperMetadata,
} from "./webShellMetadata";

describe("webShellMetadata", () => {
  it("normalizes China Chopper aliases across family, decoder, and hints", () => {
    const source = {
      familyHint: "caidao",
      decoderHints: ["chopper"],
      decoderOptionsHint: { decoder: "china_chopper" },
      sourceRole: "script_or_command",
    };

    expect(isChinaChopperMetadata(source)).toBe(true);
    expect(getWebShellFamilyLabel(source)).toBe("菜刀 / China Chopper");
    expect(getWebShellDecoderLabel(source)).toBe("菜刀 / China Chopper");
  });

  it("keeps version unavailable when no backend hint exists", () => {
    expect(getWebShellVersionLabel({ decoderOptionsHint: {} })).toBe("未提供");
    expect(getWebShellMetadataSummary({ decoderOptionsHint: {} }, 0).fields.find((item) => item.key === "version")).toMatchObject({
      value: "未提供",
      unavailable: true,
    });
  });

  it("shows explicit version only when provided", () => {
    expect(getWebShellVersionLabel({ decoderOptionsHint: { versionHint: "v2.x-v3.x" } })).toBe("v2.x-v3.x");
  });
});

import { describe, expect, it } from "vitest";

import type { ToolRuntimeConfig } from "../../core/types";
import { toolRuntimeConfigsEqual } from "./backendLifecycleToolRuntimeStartup";

const baseConfig: ToolRuntimeConfig = {
  tsharkPath: "",
  tsharkAllowedDirs: [],
  ffmpegPath: "",
  pythonPath: "",
  voskModelPath: "",
  yaraEnabled: true,
  yaraBin: "",
  yaraRules: "",
  yaraTimeoutMs: 25000,
};

describe("toolRuntimeConfigsEqual", () => {
  it("returns true for identical configs", () => {
    expect(toolRuntimeConfigsEqual(baseConfig, { ...baseConfig })).toBe(true);
  });

  it("detects differing tshark paths", () => {
    expect(toolRuntimeConfigsEqual(baseConfig, { ...baseConfig, tsharkPath: "C:/Wireshark/tshark.exe" })).toBe(false);
  });

  it("detects differing tshark allowed dirs", () => {
    expect(
      toolRuntimeConfigsEqual(baseConfig, {
        ...baseConfig,
        tsharkAllowedDirs: ["C:/Tools"],
      }),
    ).toBe(false);
  });

  it("treats undefined and empty tsharkAllowedDirs as equal", () => {
    const left = { ...baseConfig, tsharkAllowedDirs: undefined as unknown as string[] };
    expect(toolRuntimeConfigsEqual(left, baseConfig)).toBe(true);
  });
});

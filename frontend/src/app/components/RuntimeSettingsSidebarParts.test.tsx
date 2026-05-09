import { describe, expect, it } from "vitest";

import type { ToolRuntimeConfig, ToolRuntimeSnapshot } from "../core/types";
import { buildSpeechIssues, normalizeConfig, statusTone } from "./RuntimeSettingsSidebarParts";

const completeConfig: ToolRuntimeConfig = {
  tsharkPath: "C:\\Wireshark\\tshark.exe",
  ffmpegPath: "C:\\ffmpeg\\ffmpeg.exe",
  pythonPath: "C:\\Python311\\python.exe",
  voskModelPath: "C:\\models\\vosk",
  yaraEnabled: false,
  yaraBin: "C:\\tools\\yara64.exe",
  yaraRules: "C:\\rules\\traffic.yar",
  yaraTimeoutMs: 15000,
};

function createSnapshot(overrides: Partial<ToolRuntimeSnapshot["speech"]> = {}): ToolRuntimeSnapshot {
  return {
    config: completeConfig,
    tshark: {
      available: true,
      path: completeConfig.tsharkPath,
      message: "ok",
      usingCustomPath: true,
    },
    ffmpeg: {
      available: true,
      path: completeConfig.ffmpegPath,
      message: "ok",
      usingCustomPath: true,
    },
    speech: {
      available: true,
      engine: "vosk",
      language: "zh-CN",
      pythonAvailable: true,
      pythonCommand: completeConfig.pythonPath,
      ffmpegAvailable: true,
      voskAvailable: true,
      modelAvailable: true,
      modelPath: completeConfig.voskModelPath,
      message: "ok",
      ...overrides,
    },
    yara: {
      available: true,
      enabled: false,
      path: completeConfig.yaraBin,
      rulePath: completeConfig.yaraRules,
      message: "ok",
      usingCustomBin: true,
      usingCustomRules: true,
      timeoutMs: completeConfig.yaraTimeoutMs,
    },
  };
}

describe("RuntimeSettingsSidebarParts", () => {
  it("normalizes missing config and invalid timeout", () => {
    expect(normalizeConfig(null)).toEqual({
      tsharkPath: "",
      ffmpegPath: "",
      pythonPath: "",
      voskModelPath: "",
      yaraEnabled: true,
      yaraBin: "",
      yaraRules: "",
      yaraTimeoutMs: 25000,
    });

    expect(normalizeConfig({ ...completeConfig, yaraTimeoutMs: 0 })).toEqual({
      ...completeConfig,
      yaraTimeoutMs: 25000,
    });
  });

  it("keeps explicit runtime config values", () => {
    expect(normalizeConfig(completeConfig)).toEqual(completeConfig);
  });

  it("maps dependency status tones", () => {
    expect(statusTone(true)).toContain("emerald");
    expect(statusTone(false)).toContain("rose");
    expect(statusTone(true, false)).toContain("slate");
  });

  it("builds speech dependency issue labels", () => {
    expect(buildSpeechIssues(null)).toEqual([]);
    expect(
      buildSpeechIssues(
        createSnapshot({
          available: false,
          pythonAvailable: false,
          voskAvailable: false,
          modelAvailable: false,
          ffmpegAvailable: false,
        }),
      ),
    ).toEqual(["Python 不可用", "vosk 模块缺失", "Vosk 模型目录缺失", "ffmpeg 不可用"]);
    expect(buildSpeechIssues(createSnapshot())).toEqual([]);
  });
});

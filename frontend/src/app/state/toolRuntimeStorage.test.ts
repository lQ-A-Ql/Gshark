import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { ToolRuntimeConfig } from "../core/types";

import { EMPTY_TOOL_RUNTIME_CONFIG, readToolRuntimeConfig, writeToolRuntimeConfig } from "./toolRuntimeStorage";

describe("toolRuntimeStorage", () => {
  const values = new Map<string, string>();

  beforeEach(() => {
    values.clear();
    vi.spyOn(window.localStorage, "getItem").mockImplementation((key) => values.get(key) ?? null);
    vi.spyOn(window.localStorage, "setItem").mockImplementation((key, value) => {
      values.set(key, value);
    });
    vi.spyOn(window.localStorage, "clear").mockImplementation(() => values.clear());
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("falls back to legacy tshark path", () => {
    window.localStorage.setItem("gshark.tshark-path.v1", " C:/Tools/tshark.exe ");

    expect(readToolRuntimeConfig()).toMatchObject({
      tsharkPath: "C:/Tools/tshark.exe",
      yaraEnabled: true,
      yaraTimeoutMs: 25000,
    });
  });

  it("normalizes stored runtime config", () => {
    window.localStorage.setItem(
      "gshark.tool-runtime.v1",
      JSON.stringify({
        tsharkPath: " C:/Wireshark/tshark.exe ",
        ffmpegPath: " C:/ffmpeg.exe ",
        pythonPath: " C:/Python/python.exe ",
        voskModelPath: " C:/models/vosk ",
        yaraEnabled: false,
        yaraBin: " C:/yara.exe ",
        yaraRules: " C:/rules ",
        yaraTimeoutMs: "30000",
      }),
    );

    expect(readToolRuntimeConfig()).toEqual({
      tsharkPath: "C:/Wireshark/tshark.exe",
      ffmpegPath: "C:/ffmpeg.exe",
      pythonPath: "C:/Python/python.exe",
      voskModelPath: "C:/models/vosk",
      yaraEnabled: false,
      yaraBin: "C:/yara.exe",
      yaraRules: "C:/rules",
      yaraTimeoutMs: 30000,
    });
  });

  it("writes current and legacy tshark path", () => {
    writeToolRuntimeConfig({
      tsharkPath: "C:/Wireshark/tshark.exe",
      ffmpegPath: "",
      pythonPath: "",
      voskModelPath: "",
      yaraEnabled: true,
      yaraBin: "",
      yaraRules: "",
      yaraTimeoutMs: 25000,
    });

    expect(window.localStorage.getItem("gshark.tshark-path.v1")).toBe("C:/Wireshark/tshark.exe");
    expect(JSON.parse(window.localStorage.getItem("gshark.tool-runtime.v1") ?? "{}")).toMatchObject({
      tsharkPath: "C:/Wireshark/tshark.exe",
    });
  });

  it("round-trips a complete config through the storage layer", () => {
    const config: ToolRuntimeConfig = {
      tsharkPath: "C:/Wireshark/tshark.exe",
      ffmpegPath: "C:/Tools/ffmpeg.exe",
      pythonPath: "C:/Python/python.exe",
      voskModelPath: "C:/models/vosk",
      yaraEnabled: false,
      yaraBin: "C:/Tools/yara.exe",
      yaraRules: "C:/rules",
      yaraTimeoutMs: 30000,
    };

    writeToolRuntimeConfig(config);

    expect(readToolRuntimeConfig()).toEqual(config);
  });

  it("later writes overwrite earlier writes of the same key", () => {
    writeToolRuntimeConfig({ ...EMPTY_TOOL_RUNTIME_CONFIG, tsharkPath: "first.exe" });
    writeToolRuntimeConfig({ ...EMPTY_TOOL_RUNTIME_CONFIG, tsharkPath: "second.exe" });

    expect(readToolRuntimeConfig().tsharkPath).toBe("second.exe");
    expect(window.localStorage.getItem("gshark.tshark-path.v1")).toBe("second.exe");
  });
});

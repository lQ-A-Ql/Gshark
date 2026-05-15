import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { ToolRuntimeConfig } from "../core/types";
import { EMPTY_TOOL_RUNTIME_CONFIG } from "./toolRuntimeStorageConfig";

import {
  readToolRuntimeConfig,
  readToolRuntimeConfigState,
  writeObservedToolRuntimeSnapshotConfig,
  writeUserToolRuntimeConfig,
} from "./toolRuntimeStorage";

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
    expect(readToolRuntimeConfigState()).toMatchObject({
      source: "legacy-tshark-only",
      config: { tsharkPath: "C:/Tools/tshark.exe" },
      explicitFields: { tsharkPath: true },
    });
  });

  it("marks missing storage separately from a saved empty config", () => {
    expect(readToolRuntimeConfigState()).toEqual({
      config: EMPTY_TOOL_RUNTIME_CONFIG,
      source: "missing",
      explicitFields: {},
    });
  });

  it("migrates a legacy all-empty runtime config to observed state", () => {
    window.localStorage.setItem("gshark.tool-runtime.v1", JSON.stringify(EMPTY_TOOL_RUNTIME_CONFIG));

    expect(readToolRuntimeConfigState()).toEqual({
      config: EMPTY_TOOL_RUNTIME_CONFIG,
      source: "observed-backend-snapshot",
      explicitFields: {},
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
    expect(readToolRuntimeConfigState()).toMatchObject({
      source: "stored-runtime-config",
      explicitFields: {
        tsharkPath: true,
        ffmpegPath: true,
        pythonPath: true,
        voskModelPath: true,
        yaraEnabled: true,
        yaraBin: true,
        yaraRules: true,
        yaraTimeoutMs: true,
      },
    });
  });

  it("treats malformed runtime config as missing so startup can trust the backend snapshot", () => {
    window.localStorage.setItem("gshark.tool-runtime.v1", "{not-json");

    expect(readToolRuntimeConfigState()).toEqual({
      config: EMPTY_TOOL_RUNTIME_CONFIG,
      source: "missing",
      explicitFields: {},
    });
  });

  it("writes current and legacy tshark path", () => {
    writeUserToolRuntimeConfig({
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
      version: 2,
      source: "stored-runtime-config",
      config: { tsharkPath: "C:/Wireshark/tshark.exe" },
      explicitFields: { tsharkPath: true, ffmpegPath: true },
    });
  });

  it("writes observed snapshots without explicit fields", () => {
    writeObservedToolRuntimeSnapshotConfig({ ...EMPTY_TOOL_RUNTIME_CONFIG, ffmpegPath: "C:/Env/ffmpeg.exe" });

    expect(readToolRuntimeConfigState()).toEqual({
      config: { ...EMPTY_TOOL_RUNTIME_CONFIG, ffmpegPath: "C:/Env/ffmpeg.exe" },
      source: "observed-backend-snapshot",
      explicitFields: {},
    });
  });

  it("preserves explicit empty fields for v2 user-saved config", () => {
    writeUserToolRuntimeConfig({ ...EMPTY_TOOL_RUNTIME_CONFIG, ffmpegPath: "" }, { ffmpegPath: true });

    expect(readToolRuntimeConfigState()).toMatchObject({
      source: "stored-runtime-config",
      explicitFields: { ffmpegPath: true },
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

    writeUserToolRuntimeConfig(config);

    expect(readToolRuntimeConfig()).toEqual(config);
  });

  it("later writes overwrite earlier writes of the same key", () => {
    writeUserToolRuntimeConfig({ ...EMPTY_TOOL_RUNTIME_CONFIG, tsharkPath: "first.exe" });
    writeUserToolRuntimeConfig({ ...EMPTY_TOOL_RUNTIME_CONFIG, tsharkPath: "second.exe" });

    expect(readToolRuntimeConfig().tsharkPath).toBe("second.exe");
    expect(window.localStorage.getItem("gshark.tshark-path.v1")).toBe("second.exe");
  });
});

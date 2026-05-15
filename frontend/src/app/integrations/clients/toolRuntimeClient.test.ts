import { describe, expect, it, vi } from "vitest";

import { createToolRuntimeClient } from "./toolRuntimeClient";

type JsonRequest = <T>(path: string, init?: RequestInit) => Promise<T>;

describe("toolRuntimeClient", () => {
  it("maps runtime tool status payloads without aggregate bridge types", async () => {
    const request = vi.fn(async (path: string) => {
      if (path === "/api/tools/tshark") {
        return {
          available: true,
          path: "tshark.exe",
          version: "TShark 4.2.0",
          field_profile: "compat",
          missing_optional_fields: ["usb.capdata"],
          capability_check_degraded: true,
        };
      }
      if (path === "/api/tools/ffmpeg") {
        return { available: true, path: "ffmpeg.exe", message: "ok" };
      }
      if (path === "/api/tools/speech-to-text") {
        return { available: true, engine: "vosk", python_available: true };
      }
      throw new Error(`unexpected path ${path}`);
    }) as unknown as JsonRequest;

    const client = createToolRuntimeClient(request);

    expect(await client.checkTShark()).toMatchObject({
      available: true,
      path: "tshark.exe",
      version: "TShark 4.2.0",
      fieldProfile: "compat",
      missingOptionalFields: ["usb.capdata"],
      capabilityCheckDegraded: true,
    });
    expect(await client.checkFFmpeg()).toMatchObject({ available: true, path: "ffmpeg.exe" });
    expect(await client.checkSpeechToText()).toMatchObject({ available: true, engine: "vosk" });
  });

  it("maps runtime snapshot and update payload shape", async () => {
    const request = vi.fn(async (path: string, init?: RequestInit) => {
      if (path === "/api/tools/runtime-config" && !init) {
        return {
          config: {
            tshark_path: "tshark.exe",
            ffmpeg_path: "env-ffmpeg.exe",
            python_path: "env-python.exe",
            vosk_model_path: "env-model",
          },
          tshark: { available: true },
          yara: { timeout_ms: 1000 },
        };
      }
      expect(path).toBe("/api/tools/runtime-config");
      expect(init?.method).toBe("POST");
      expect(init?.body).toBe(
        JSON.stringify({
          tshark_path: "t.exe",
          ffmpeg_path: "f.exe",
          python_path: "py.exe",
          vosk_model_path: "model",
          yara_enabled: true,
          yara_bin: "yara.exe",
          yara_rules: "rules",
          yara_timeout_ms: 12345,
        }),
      );
      return { config: { tshark_path: "t.exe" }, tshark: { available: true }, yara: { timeout_ms: 12345 } };
    }) as unknown as JsonRequest;

    const client = createToolRuntimeClient(request);
    expect(await client.getToolRuntimeSnapshot()).toMatchObject({
      config: {
        tsharkPath: "tshark.exe",
        ffmpegPath: "env-ffmpeg.exe",
        pythonPath: "env-python.exe",
        voskModelPath: "env-model",
      },
    });
    expect(
      await client.updateToolRuntimeConfig({
        tsharkPath: "t.exe",
        ffmpegPath: "f.exe",
        pythonPath: "py.exe",
        voskModelPath: "model",
        yaraEnabled: true,
        yaraBin: "yara.exe",
        yaraRules: "rules",
        yaraTimeoutMs: 12345,
      }),
    ).toMatchObject({ config: { tsharkPath: "t.exe" }, yara: { timeoutMs: 12345 } });
  });
});

import { describe, expect, it, vi } from "vitest";
import {
  asKnownDecoder,
  buildDecoderOptions,
  candidateHintBadges,
  clampBatchOrdinal,
  DEFAULT_SETTINGS,
  mergeDecoderHintSources,
  mergeHintIntoSettings,
  normalizeTransportPayload,
  prepareDecoderInput,
  readDecoderSettings,
  persistDecoderSettings,
  type DecoderHintSource,
} from "./StreamDecoderWorkbenchUtils";

describe("StreamDecoderWorkbenchUtils", () => {
  it("normalizes batch ordinals into a safe one-based range", () => {
    expect(clampBatchOrdinal("3", 5)).toBe(3);
    expect(clampBatchOrdinal("item-9", 5)).toBe(5);
    expect(clampBatchOrdinal("0", 5)).toBe(1);
    expect(clampBatchOrdinal(undefined, 0)).toBe(1);
  });

  it("recognizes supported decoder names", () => {
    expect(asKnownDecoder("Behinder")).toBe("behinder");
    expect(asKnownDecoder("godzilla")).toBe("godzilla");
    expect(asKnownDecoder("unknown")).toBeNull();
  });

  it("merges decoder hints with source hints taking source metadata priority", () => {
    const candidate: DecoderHintSource = {
      familyHint: "aes_webshell_like",
      decoderHints: ["behinder", "godzilla"],
      decoderOptionsHint: { decoder: "behinder", pass: "rebeyond" },
      paramName: "payload",
    };
    const source: DecoderHintSource = {
      familyHint: "godzilla_like",
      decoderHints: ["godzilla", "antsword"],
      decoderOptionsHint: { decoder: "godzilla", pass: "pass" },
      paramName: "pass",
    };

    expect(mergeDecoderHintSources(candidate, source)).toEqual({
      familyHint: "godzilla_like",
      decoderHints: ["godzilla", "antsword", "behinder"],
      decoderOptionsHint: { decoder: "godzilla", pass: "pass" },
      paramName: "pass",
    });
  });

  it("builds decoder options from auto hints", () => {
    const options = buildDecoderOptions("auto", DEFAULT_SETTINGS, {
      familyHint: "godzilla_like",
      decoderOptionsHint: {
        decoder: "godzilla",
        pass: "x",
        cipher: "xor",
        inputEncoding: "base64",
      },
    });

    expect(options).toMatchObject({
      pass: "x",
      cipher: "xor",
      inputEncoding: "base64",
      stripMarkers: true,
    });
  });

  it("does not overwrite manually supplied crypto material from hints", () => {
    const next = mergeHintIntoSettings(
      {
        ...DEFAULT_SETTINGS,
        godzilla: {
          ...DEFAULT_SETTINGS.godzilla,
          key: "manual-key",
        },
      },
      {
        familyHint: "godzilla_like",
        decoderOptionsHint: {
          decoder: "godzilla",
          key: "hint-key",
          pass: "cmd",
        },
      },
    );

    expect(next.godzilla.key).toBe("manual-key");
    expect(next.godzilla.pass).toBe("cmd");
  });

  it("formats candidate hint badges from meaningful options", () => {
    expect(
      candidateHintBadges({
        decoderOptionsHint: {
          decoder: "behinder",
          pass: "rebeyond",
          inputEncoding: "",
          cipherMode: "cbc",
        },
      }),
    ).toEqual(["decoder:behinder", "pass:rebeyond", "cipherMode:cbc"]);
  });

  it("extracts HTTP body from full transport payloads", () => {
    expect(normalizeTransportPayload("POST /x HTTP/1.1\r\nHost: a\r\n\r\ncmd=id")).toBe("cmd=id");
    expect(normalizeTransportPayload("plain-body")).toBe("plain-body");
  });

  it("prepares decoder input without changing non-base64 decoders", () => {
    expect(prepareDecoderInput("base64", " YWJj ")).toBe("YWJj");
    expect(prepareDecoderInput("behinder", " YWJj ")).toBe(" YWJj ");
  });

  it("persists settings with default fallback", () => {
    const storage = new Map<string, string>();
    vi.stubGlobal("window", {
      localStorage: {
        getItem: (key: string) => storage.get(key) ?? null,
        setItem: (key: string, value: string) => storage.set(key, value),
      },
    });

    persistDecoderSettings({
      ...DEFAULT_SETTINGS,
      antsword: { ...DEFAULT_SETTINGS.antsword, pass: "ants" },
    });

    expect(readDecoderSettings().antsword.pass).toBe("ants");

    vi.unstubAllGlobals();
  });
});

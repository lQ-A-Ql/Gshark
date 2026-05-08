import { describe, expect, it } from "vitest";
import {
  buildWinRMDecryptRequest,
  getWinRMResultResetState,
  parseWinRMNumericInput,
  sanitizeWinRMNumericInput,
} from "./WinRMDecryptUtils";

describe("WinRMDecryptUtils", () => {
  it("sanitizes and parses numeric input", () => {
    expect(sanitizeWinRMNumericInput("tcp/5985")).toBe("5985");
    expect(parseWinRMNumericInput("2oo")).toBe(2);
    expect(parseWinRMNumericInput("")).toBe(0);
  });

  it("builds a password auth decrypt request", () => {
    expect(
      buildWinRMDecryptRequest({
        authMode: "password",
        hash: "hash-ignored",
        password: "secret",
        port: "tcp/5985",
        previewLines: "200 lines",
      }),
    ).toEqual({
      port: 5985,
      authMode: "password",
      password: "secret",
      ntHash: "",
      previewLines: 200,
      includeErrorFrames: false,
      extractCommandOutput: true,
    });
  });

  it("builds an NT hash decrypt request", () => {
    expect(
      buildWinRMDecryptRequest({
        authMode: "nt_hash",
        hash: "31d6cfe0d16ae931b73c59d7e0c089c0",
        password: "ignored",
        port: "5986",
        previewLines: "",
      }),
    ).toEqual({
      port: 5986,
      authMode: "nt_hash",
      password: "",
      ntHash: "31d6cfe0d16ae931b73c59d7e0c089c0",
      previewLines: 0,
      includeErrorFrames: false,
      extractCommandOutput: true,
    });
  });

  it("returns reset state for result cleanup", () => {
    expect(getWinRMResultResetState()).toEqual({
      error: "",
      previewDialogError: "",
      previewDialogText: "",
      previewOpen: false,
      result: null,
    });
  });
});

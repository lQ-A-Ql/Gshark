import { describe, expect, it } from "vitest";
import { buildFailedCaptureTransactionStatus } from "./captureTransactionStatus";
import { getCapturePreloadTimeoutError } from "./capturePreloadStatus";

describe("captureTransactionStatus", () => {
  it("builds open failure transactions with fallback capture fields", () => {
    expect(
      buildFailedCaptureTransactionStatus({
        error: new Error("open failed"),
        parseError: "",
        hadActiveCapture: false,
        fallbackName: "new.pcap",
        fallbackPath: "C:/new.pcap",
      }),
    ).toMatchObject({
      phase: "failed",
      reason: "open_failed",
      message: "open failed",
      pendingCaptureName: "new.pcap",
      pendingCapturePath: "C:/new.pcap",
      hasActiveCapture: false,
    });
  });

  it("marks switch failures when replacing an active capture", () => {
    expect(
      buildFailedCaptureTransactionStatus({
        error: new Error("parse failed"),
        parseError: "",
        hadActiveCapture: true,
        fallbackName: "",
        fallbackPath: "",
        pendingCaptureName: "pending.pcap",
        pendingCapturePath: "D:/pending.pcap",
      }).reason,
    ).toBe("switch_failed");
  });

  it("marks timeout and empty parse failures", () => {
    expect(
      buildFailedCaptureTransactionStatus({
        error: new Error(getCapturePreloadTimeoutError()),
        parseError: "",
        hadActiveCapture: false,
        fallbackName: "",
        fallbackPath: "",
      }).reason,
    ).toBe("preload_timeout");

    expect(
      buildFailedCaptureTransactionStatus({
        error: new Error("capture parsing finished without any packets; please verify tshark compatibility"),
        parseError: "tshark failed",
        hadActiveCapture: false,
        fallbackName: "",
        fallbackPath: "",
      }).reason,
    ).toBe("empty_parse");
  });
});

import { describe, expect, it } from "vitest";
import {
  finishCaptureParseRuntime,
  markCaptureParseFinished,
  startCaptureParseRuntime,
  stopCapturePreloading,
} from "./captureParseRuntimeState";

describe("captureParseRuntimeState", () => {
  it("starts capture parse runtime", () => {
    const parseFinishedRef = { current: true };
    const parseErrorRef = { current: "old error" };
    const preloadingRef = { current: false };
    let isPreloadingCapture = false;

    startCaptureParseRuntime({
      parseFinishedRef,
      parseErrorRef,
      preloadingRef,
      setIsPreloadingCapture: (value) => {
        isPreloadingCapture = typeof value === "function" ? value(isPreloadingCapture) : value;
      },
    });

    expect(parseFinishedRef.current).toBe(false);
    expect(parseErrorRef.current).toBe("");
    expect(preloadingRef.current).toBe(true);
    expect(isPreloadingCapture).toBe(true);
  });

  it("finishes capture parse runtime and clears previous error", () => {
    const parseFinishedRef = { current: false };
    const parseErrorRef = { current: "parse failed" };
    const preloadingRef = { current: true };
    let isPreloadingCapture = true;

    finishCaptureParseRuntime({
      parseFinishedRef,
      parseErrorRef,
      preloadingRef,
      setIsPreloadingCapture: (value) => {
        isPreloadingCapture = typeof value === "function" ? value(isPreloadingCapture) : value;
      },
    });

    expect(parseFinishedRef.current).toBe(true);
    expect(parseErrorRef.current).toBe("");
    expect(preloadingRef.current).toBe(false);
    expect(isPreloadingCapture).toBe(false);
  });

  it("stops preloading without changing parse result", () => {
    const preloadingRef = { current: true };
    let isPreloadingCapture = true;

    stopCapturePreloading({
      preloadingRef,
      setIsPreloadingCapture: (value) => {
        isPreloadingCapture = typeof value === "function" ? value(isPreloadingCapture) : value;
      },
    });

    expect(preloadingRef.current).toBe(false);
    expect(isPreloadingCapture).toBe(false);
  });

  it("marks parse finished with optional error message", () => {
    const parseFinishedRef = { current: false };
    const parseErrorRef = { current: "" };

    markCaptureParseFinished({
      parseFinishedRef,
      parseErrorRef,
      errorMessage: "invalid pcap",
    });

    expect(parseFinishedRef.current).toBe(true);
    expect(parseErrorRef.current).toBe("invalid pcap");

    markCaptureParseFinished({
      parseFinishedRef,
      parseErrorRef,
    });

    expect(parseFinishedRef.current).toBe(true);
    expect(parseErrorRef.current).toBe("invalid pcap");
  });
});

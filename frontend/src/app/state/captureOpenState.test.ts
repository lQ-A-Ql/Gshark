import { describe, expect, it } from "vitest";
import {
  buildCaptureFileMeta,
  buildOpenedCaptureFromPath,
  buildRecentCapture,
  createClosedCaptureFileMeta,
  createInitialCaptureFileMeta,
} from "./captureOpenState";

describe("captureOpenState helpers", () => {
  it("builds initial and closed capture file meta without sharing objects", () => {
    expect(createInitialCaptureFileMeta()).toEqual({
      name: "",
      sizeBytes: 0,
      path: "",
    });
    expect(createClosedCaptureFileMeta()).toEqual({
      name: "未打开文件",
      sizeBytes: 0,
      path: "",
    });
    expect(createInitialCaptureFileMeta()).not.toBe(createInitialCaptureFileMeta());
    expect(createClosedCaptureFileMeta()).not.toBe(createClosedCaptureFileMeta());
  });

  it("builds opened capture metadata from a provided path", () => {
    expect(buildOpenedCaptureFromPath(" C:\\captures\\sample.pcapng ")).toEqual({
      filePath: "C:\\captures\\sample.pcapng",
      fileName: "sample.pcapng",
      fileSize: 0,
    });
    expect(buildOpenedCaptureFromPath("/tmp/capture.pcap")).toEqual({
      filePath: "/tmp/capture.pcap",
      fileName: "capture.pcap",
      fileSize: 0,
    });
  });

  it("returns null for blank provided paths", () => {
    expect(buildOpenedCaptureFromPath("")).toBeNull();
    expect(buildOpenedCaptureFromPath("   ")).toBeNull();
  });

  it("builds file meta from an opened capture", () => {
    expect(
      buildCaptureFileMeta({
        filePath: "C:\\captures\\sample.pcapng",
        fileName: "sample.pcapng",
        fileSize: 42,
      }),
    ).toEqual({
      path: "C:\\captures\\sample.pcapng",
      name: "sample.pcapng",
      sizeBytes: 42,
    });
  });

  it("normalizes missing file size for file meta and recent captures", () => {
    const opened = {
      filePath: "C:\\captures\\sample.pcapng",
      fileName: "sample.pcapng",
    };

    expect(buildCaptureFileMeta(opened).sizeBytes).toBe(0);
    expect(buildRecentCapture(opened, "2026-05-08T15:20:00.000Z")).toEqual({
      path: "C:\\captures\\sample.pcapng",
      name: "sample.pcapng",
      sizeBytes: 0,
      lastOpenedAt: "2026-05-08T15:20:00.000Z",
    });
  });
});

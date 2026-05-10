import { describe, expect, it } from "vitest";
import { isCommittedCaptureStatusForPath, normalizeCapturePathForCompare } from "./captureCommitStatus";

describe("capture commit status", () => {
  it("normalizes Windows paths for backend active-capture comparison", () => {
    expect(normalizeCapturePathForCompare("C:\\Users\\QAQ\\capture.pcapng")).toBe("c:/users/qaq/capture.pcapng");
  });

  it("accepts a committed active capture for the selected file", () => {
    expect(
      isCommittedCaptureStatusForPath(
        {
          filePath: "C:\\Users\\QAQ\\Downloads\\attachment-17.pcapng",
          hasCapture: true,
          packetCount: 1509,
        },
        "c:/users/qaq/downloads/attachment-17.pcapng",
      ),
    ).toBe(true);
  });

  it("rejects old active capture status during replacement", () => {
    expect(
      isCommittedCaptureStatusForPath(
        {
          filePath: "C:\\Users\\QAQ\\Downloads\\old.pcapng",
          hasCapture: true,
          packetCount: 200,
        },
        "C:\\Users\\QAQ\\Downloads\\new.pcapng",
      ),
    ).toBe(false);
  });

  it("rejects empty or uncommitted captures", () => {
    expect(
      isCommittedCaptureStatusForPath(
        {
          filePath: "C:\\Users\\QAQ\\Downloads\\empty.pcapng",
          hasCapture: true,
          packetCount: 0,
        },
        "C:\\Users\\QAQ\\Downloads\\empty.pcapng",
      ),
    ).toBe(false);
    expect(isCommittedCaptureStatusForPath(null, "C:\\Users\\QAQ\\Downloads\\empty.pcapng")).toBe(false);
  });
});

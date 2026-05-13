import { act, renderHook } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { createInitialCaptureFileMeta } from "../captureOpenState";
import { createIdleCaptureTransactionStatus } from "../captureTransactionStatus";
import { useCaptureSessionState } from "./useCaptureSessionState";

describe("useCaptureSessionState", () => {
  it("initializes slice values with the documented factories", () => {
    const { result } = renderHook(() => useCaptureSessionState());

    expect(result.current.captureTransaction).toEqual(createIdleCaptureTransactionStatus(false));
    expect(result.current.fileMeta).toEqual(createInitialCaptureFileMeta());
    expect(result.current.captureRevision).toBe(0);
  });

  it("updates slice state via setters", () => {
    const { result, rerender } = renderHook(() => useCaptureSessionState());

    act(() => {
      result.current.setFileMeta({
        name: "sample.pcapng",
        sizeBytes: 1024,
        path: "/tmp/sample.pcapng",
      });
      result.current.setCaptureRevision((prev) => prev + 1);
      result.current.setCaptureTransaction({
        phase: "pending",
        reason: "",
        message: "",
        pendingCaptureName: "sample.pcapng",
        pendingCapturePath: "/tmp/sample.pcapng",
        hasActiveCapture: true,
      });
    });
    rerender();

    expect(result.current.fileMeta).toEqual({
      name: "sample.pcapng",
      sizeBytes: 1024,
      path: "/tmp/sample.pcapng",
    });
    expect(result.current.captureRevision).toBe(1);
    expect(result.current.captureTransaction.phase).toBe("pending");
    expect(result.current.captureTransaction.pendingCapturePath).toBe("/tmp/sample.pcapng");
  });
});

import { act, renderHook } from "@testing-library/react";
import { useRef, useState } from "react";
import { describe, expect, it } from "vitest";
import type { CaptureScopedTask } from "../../utils/captureTaskScope";
import { createCaptureTaskScope } from "../../utils/captureTaskScope";
import { usePacketPageCancellation } from "./usePacketPageCancellation";

describe("usePacketPageCancellation", () => {
  it("bumps packet page sequence, aborts packet-page task, and clears loading state", () => {
    const { result } = renderHook(() => {
      const captureTaskScopeRef = useRef(createCaptureTaskScope());
      const staleTaskRef = useRef<CaptureScopedTask | null>(null);
      staleTaskRef.current ??= captureTaskScopeRef.current.beginTask("packet-page");
      const packetPageSeqRef = useRef(4);
      const [isPageLoading, setIsPageLoading] = useState(true);
      const cancelPacketPageLoad = usePacketPageCancellation({
        captureTaskScopeRef,
        packetPageSeqRef,
        setIsPageLoading,
      });
      return { cancelPacketPageLoad, isPageLoading, packetPageSeqRef, staleTask: staleTaskRef.current };
    });

    act(() => result.current.cancelPacketPageLoad());

    expect(result.current.packetPageSeqRef.current).toBe(5);
    expect(result.current.staleTask.isCurrent()).toBe(false);
    expect(result.current.isPageLoading).toBe(false);
  });
});

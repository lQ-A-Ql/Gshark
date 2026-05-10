import { act, renderHook } from "@testing-library/react";
import { useRef, useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { createCaptureTaskScope } from "../../utils/captureTaskScope";
import { useRefreshAnalysisResult } from "./useRefreshAnalysisResult";

describe("useRefreshAnalysisResult", () => {
  it("binds current capture refs and backend status setter to analysis refresh", async () => {
    const refreshAnalysisResultImpl = vi.fn(async () => undefined);
    const { result } = renderHook(() => {
      const activeCapturePathRef = useRef("sample.pcapng");
      const captureTaskScopeRef = useRef(createCaptureTaskScope());
      const [backendStatus, setBackendStatus] = useState("");
      const refreshAnalysisResult = useRefreshAnalysisResult({
        activeCapturePathRef,
        backendConnected: true,
        captureTaskScopeRef,
        refreshAnalysisResultImpl,
        setBackendStatus,
      });
      return { backendStatus, captureTaskScopeRef, refreshAnalysisResult, setBackendStatus };
    });

    await act(async () => {
      await result.current.refreshAnalysisResult({ quietSuccess: true });
    });

    expect(refreshAnalysisResultImpl).toHaveBeenCalledWith({
      quietSuccess: true,
      backendConnected: true,
      activeCapturePath: "sample.pcapng",
      captureTaskScope: result.current.captureTaskScopeRef.current,
      setBackendStatus: result.current.setBackendStatus,
    });
  });
});

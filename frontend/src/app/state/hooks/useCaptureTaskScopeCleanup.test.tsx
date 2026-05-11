import { renderHook } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { CaptureScopedTask } from "../../utils/captureTaskScope";
import { createCaptureTaskScope } from "../../utils/captureTaskScope";
import { useCaptureTaskScopeCleanup } from "./useCaptureTaskScopeCleanup";

describe("useCaptureTaskScopeCleanup", () => {
  it("invalidates active capture tasks on unmount", () => {
    const captureTaskScopeRef = { current: createCaptureTaskScope() };
    const staleTask: CaptureScopedTask = captureTaskScopeRef.current.beginTask("packet-page");

    const { unmount } = renderHook(() => useCaptureTaskScopeCleanup(captureTaskScopeRef));

    expect(staleTask.isCurrent()).toBe(true);
    unmount();
    expect(staleTask.isCurrent()).toBe(false);
  });
});

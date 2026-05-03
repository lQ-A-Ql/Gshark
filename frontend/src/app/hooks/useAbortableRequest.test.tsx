import { act, renderHook } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { isAbortLikeError, useAbortableRequest } from "./useAbortableRequest";

describe("useAbortableRequest", () => {
  it("ignores stale responses after a newer request starts", async () => {
    const success = vi.fn();
    const settled = vi.fn();
    const { result } = renderHook(() => useAbortableRequest());

    let resolveFirst: ((value: string) => void) | undefined;
    let resolveSecond: ((value: string) => void) | undefined;

    act(() => {
      result.current.run({
        request: () => new Promise<string>((resolve) => {
          resolveFirst = resolve;
        }),
        onSuccess: success,
        onSettled: settled,
      });
      result.current.run({
        request: () => new Promise<string>((resolve) => {
          resolveSecond = resolve;
        }),
        onSuccess: success,
        onSettled: settled,
      });
    });

    await act(async () => {
      resolveFirst?.("stale");
      resolveSecond?.("fresh");
      await Promise.resolve();
      await Promise.resolve();
    });

    expect(success).toHaveBeenCalledTimes(1);
    expect(success).toHaveBeenCalledWith("fresh");
    expect(settled).toHaveBeenCalledTimes(1);
  });

  it("aborts the current request when cancel is called", () => {
    const seenSignals: AbortSignal[] = [];
    const { result } = renderHook(() => useAbortableRequest());

    act(() => {
      result.current.run({
        request: (signal) => {
          seenSignals.push(signal);
          return new Promise<string>(() => undefined);
        },
        onSuccess: vi.fn(),
      });
    });

    expect(seenSignals[0]?.aborted).toBe(false);
    act(() => {
      result.current.cancel();
    });
    expect(seenSignals[0]?.aborted).toBe(true);
  });

  it("recognizes abort-like errors", () => {
    expect(isAbortLikeError(new DOMException("The operation was aborted.", "AbortError"))).toBe(true);
    expect(isAbortLikeError(new Error("request aborted"))).toBe(true);
    expect(isAbortLikeError(new Error("network failed"))).toBe(false);
  });
});

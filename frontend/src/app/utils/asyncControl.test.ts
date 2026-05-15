import { describe, expect, it, vi } from "vitest";
import { OperationTimeoutError, isOperationTimeoutError, withAbortableTimeout, withTimeout } from "./asyncControl";

describe("asyncControl", () => {
  it("resolves the original operation before timeout", async () => {
    await expect(withTimeout(Promise.resolve("ok"), 100)).resolves.toBe("ok");
  });

  it("rejects with OperationTimeoutError when the operation stalls", async () => {
    vi.useFakeTimers();
    try {
      const promise = withTimeout(new Promise<string>(() => undefined), 250, "startup check stalled");
      const expectation = expect(promise).rejects.toMatchObject({
        name: "OperationTimeoutError",
        message: "startup check stalled",
        timeoutMs: 250,
      });
      await vi.advanceTimersByTimeAsync(250);
      await expectation;
      await promise.catch((error) => {
        expect(error).toBeInstanceOf(OperationTimeoutError);
      });
    } finally {
      vi.useRealTimers();
    }
  });

  it("aborts the underlying operation when the abortable timeout expires", async () => {
    vi.useFakeTimers();
    try {
      let signalRef: AbortSignal | null = null;
      const promise = withAbortableTimeout(
        (signal) => {
          signalRef = signal;
          return new Promise<string>(() => undefined);
        },
        250,
        "startup check stalled",
      );
      const expectation = expect(promise).rejects.toMatchObject({
        name: "OperationTimeoutError",
        message: "startup check stalled",
      });
      await vi.advanceTimersByTimeAsync(250);
      expect(signalRef).not.toBeNull();
      expect((signalRef as unknown as AbortSignal).aborted).toBe(true);
      await expectation;
    } finally {
      vi.useRealTimers();
    }
  });

  it("detects timeout errors without matching unrelated errors", () => {
    const timeout = new OperationTimeoutError("late", 100);
    expect(isOperationTimeoutError(timeout)).toBe(true);
    expect(isOperationTimeoutError(new Error("late"))).toBe(false);
  });
});

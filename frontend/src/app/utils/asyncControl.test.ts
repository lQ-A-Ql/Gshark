import { describe, expect, it, vi } from "vitest";
import { OperationTimeoutError, isOperationTimeoutError, withTimeout } from "./asyncControl";

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

  it("detects timeout errors without matching unrelated errors", () => {
    const timeout = new OperationTimeoutError("late", 100);
    expect(isOperationTimeoutError(timeout)).toBe(true);
    expect(isOperationTimeoutError(new Error("late"))).toBe(false);
  });
});

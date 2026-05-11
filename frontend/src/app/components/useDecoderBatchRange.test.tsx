import { renderHook } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { useDecoderBatchRange } from "./useDecoderBatchRange";

describe("useDecoderBatchRange", () => {
  it("tracks the one-based ordinal for the selected batch item", () => {
    const { result, rerender } = renderHook(
      (selectedBatchIndex?: number) =>
        useDecoderBatchRange(
          [
            { index: 10, label: "a", payload: "A" },
            { index: 20, label: "b", payload: "B" },
          ],
          selectedBatchIndex,
        ),
      { initialProps: 20 as number | undefined },
    );

    expect(result.current.selectedBatchOrdinal).toBe(2);
    expect(result.current.rangeStart).toBe("2");

    rerender(10);
    expect(result.current.selectedBatchOrdinal).toBe(1);
    expect(result.current.rangeStart).toBe("1");
  });
});

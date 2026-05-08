import { act, renderHook } from "@testing-library/react";
import { useRef, useState } from "react";
import { describe, expect, it } from "vitest";
import { useSyncedRefValue } from "./useSyncedRefValue";

function useRefHarness(initial: number) {
  const [value, setValue] = useState(initial);
  const valueRef = useRef(value);
  useSyncedRefValue(valueRef, value);
  return { value, setValue, valueRef };
}

describe("useSyncedRefValue", () => {
  it("keeps mutable refs synchronized with latest value", async () => {
    const { result, rerender } = renderHook(() => useRefHarness(1));
    expect(result.current.valueRef.current).toBe(1);

    act(() => {
      result.current.setValue(9);
    });
    rerender();
    expect(result.current.valueRef.current).toBe(9);
  });
});

import { act, renderHook } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { useDisplayFilterState } from "./useDisplayFilterState";

describe("useDisplayFilterState", () => {
  it("initializes displayFilter to an empty string", () => {
    const { result } = renderHook(() => useDisplayFilterState());
    expect(result.current.displayFilter).toBe("");
  });

  it("updates displayFilter via the returned setter", () => {
    const { result, rerender } = renderHook(() => useDisplayFilterState());

    act(() => {
      result.current.setDisplayFilter("http");
    });
    rerender();

    expect(result.current.displayFilter).toBe("http");
  });

  it("supports functional updates", () => {
    const { result, rerender } = renderHook(() => useDisplayFilterState());

    act(() => {
      result.current.setDisplayFilter("tcp");
    });
    rerender();

    act(() => {
      result.current.setDisplayFilter((prev) => `${prev} and udp`);
    });
    rerender();

    expect(result.current.displayFilter).toBe("tcp and udp");
  });
});

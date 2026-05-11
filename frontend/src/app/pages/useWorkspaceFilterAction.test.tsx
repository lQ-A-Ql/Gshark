import { renderHook } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { useWorkspaceFilterAction } from "./useWorkspaceFilterAction";

describe("useWorkspaceFilterAction", () => {
  it("remembers and applies trimmed filters", () => {
    const applyFilter = vi.fn();
    const rememberFilter = vi.fn();
    const setDisplayFilter = vi.fn();
    const { result } = renderHook(() =>
      useWorkspaceFilterAction({ applyFilter, displayFilter: "", rememberFilter, setDisplayFilter }),
    );

    result.current(" tcp.stream eq 7 ");

    expect(setDisplayFilter).toHaveBeenCalledWith("tcp.stream eq 7");
    expect(rememberFilter).toHaveBeenCalledWith("tcp.stream eq 7");
    expect(applyFilter).toHaveBeenCalledWith("tcp.stream eq 7");
  });

  it("clears filter when no value remains", () => {
    const applyFilter = vi.fn();
    const { result } = renderHook(() =>
      useWorkspaceFilterAction({
        applyFilter,
        displayFilter: "   ",
        rememberFilter: vi.fn(),
        setDisplayFilter: vi.fn(),
      }),
    );

    result.current();

    expect(applyFilter).toHaveBeenCalledWith("");
  });
});

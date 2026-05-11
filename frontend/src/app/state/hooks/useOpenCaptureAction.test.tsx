import { act, renderHook } from "@testing-library/react";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { useOpenCaptureAction } from "./useOpenCaptureAction";

describe("useOpenCaptureAction", () => {
  it("clears display filter and starts capture with an empty filter override", async () => {
    const startCapture = vi.fn().mockResolvedValue(true);
    const { result } = renderHook(() => {
      const [displayFilter, setDisplayFilter] = useState("tcp.port == 443");
      const openCapture = useOpenCaptureAction({ setDisplayFilter, startCapture });
      return { displayFilter, openCapture };
    });

    await act(async () => {
      await expect(result.current.openCapture("sample.pcap")).resolves.toBe(true);
    });

    expect(result.current.displayFilter).toBe("");
    expect(startCapture).toHaveBeenCalledWith("sample.pcap", "");
  });
});

import { renderHook, waitFor } from "@testing-library/react";
import { useRef, useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { createCaptureTaskScope } from "../../utils/captureTaskScope";
import { useSelectedPacketArtifact } from "./useSelectedPacketArtifact";

function useArtifactHarness(options: {
  selectedPacketId: number | null;
  selectedPacket: { id: number } | null;
  shouldLoad: boolean;
  taskKey: string;
  loadArtifact: (packetId: number, signal: AbortSignal) => Promise<string>;
  resetValue: string;
  initialValue: string;
}) {
  const captureTaskScopeRef = useRef(createCaptureTaskScope());
  const [value, setValue] = useState(options.initialValue);

  useSelectedPacketArtifact<string>({
    selectedPacketId: options.selectedPacketId,
    selectedPacket: options.selectedPacket,
    shouldLoad: options.shouldLoad,
    taskKey: options.taskKey,
    captureTaskScopeRef,
    loadArtifact: options.loadArtifact,
    setValue,
    resetValue: options.resetValue,
  });

  return { value };
}

describe("useSelectedPacketArtifact", () => {
  it("loads artifact data for selected packets", async () => {
    const loadArtifact = vi.fn(async () => "hex-payload");
    const { result } = renderHook(() =>
      useArtifactHarness({
        selectedPacketId: 7,
        selectedPacket: { id: 7 },
        shouldLoad: true,
        taskKey: "packet-raw-hex",
        loadArtifact,
        resetValue: "",
        initialValue: "",
      }),
    );

    await waitFor(() => {
      expect(result.current.value).toBe("hex-payload");
    });
    expect(loadArtifact).toHaveBeenCalledWith(7, expect.any(AbortSignal));
  });

  it("resets artifact state when loading is disabled", async () => {
    const loadArtifact = vi.fn(async () => "should-not-load");
    const { result } = renderHook(() =>
      useArtifactHarness({
        selectedPacketId: null,
        selectedPacket: null,
        shouldLoad: false,
        taskKey: "packet-raw-hex",
        loadArtifact,
        resetValue: "",
        initialValue: "stale-value",
      }),
    );

    await waitFor(() => {
      expect(result.current.value).toBe("");
    });
    expect(loadArtifact).not.toHaveBeenCalled();
  });

  it("resets artifact state on non-abort loader failures", async () => {
    const loadArtifact = vi.fn(async () => {
      throw new Error("fetch failed");
    });
    const { result } = renderHook(() =>
      useArtifactHarness({
        selectedPacketId: 11,
        selectedPacket: { id: 11 },
        shouldLoad: true,
        taskKey: "packet-layers",
        loadArtifact,
        resetValue: "",
        initialValue: "old-value",
      }),
    );

    await waitFor(() => {
      expect(result.current.value).toBe("");
    });
  });
});

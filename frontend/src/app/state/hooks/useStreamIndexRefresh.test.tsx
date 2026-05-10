import { act, renderHook } from "@testing-library/react";
import { useRef, useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { createCaptureTaskScope } from "../../utils/captureTaskScope";
import { createEmptyStreamIds } from "../streamState";
import { useStreamIndexRefresh } from "./useStreamIndexRefresh";

describe("useStreamIndexRefresh", () => {
  it("loads stream ids through the pure refresh workflow", async () => {
    const listStreamIds = vi.fn(async (protocol) => {
      if (protocol === "HTTP") return [1];
      if (protocol === "TCP") return [2];
      return [3];
    });
    const { result } = renderHook(() => {
      const activeCapturePathRef = useRef("sample.pcapng");
      const captureTaskScopeRef = useRef(createCaptureTaskScope());
      const [backendStatus, setBackendStatus] = useState("");
      const [streamIds, setStreamIds] = useState(createEmptyStreamIds);
      const refreshStreamIndex = useStreamIndexRefresh({
        activeCapturePathRef,
        backendConnected: true,
        captureTaskScopeRef,
        listStreamIds,
        setBackendStatus,
        setStreamIds,
      });
      return { backendStatus, refreshStreamIndex, streamIds };
    });

    await act(async () => {
      await result.current.refreshStreamIndex();
    });

    expect(listStreamIds).toHaveBeenCalledTimes(3);
    expect(result.current.streamIds).toEqual({ http: [1], tcp: [2], udp: [3] });
    expect(result.current.backendStatus).toBe("");
  });
});

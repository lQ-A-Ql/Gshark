import { act, renderHook } from "@testing-library/react";
import { useRef, useState } from "react";
import { describe, expect, it, vi } from "vitest";
import type { Packet } from "../../core/types";
import type { PacketLocateResult, PacketsPageResult } from "../../integrations/clients/captureClient";
import { createCaptureTaskScope } from "../../utils/captureTaskScope";
import { usePacketLocateById } from "./usePacketLocateById";

const packet = (id: number): Packet => ({ id, proto: "TCP" }) as Packet;
const locateResult = (): PacketLocateResult => ({ packetId: 7, cursor: 100, total: 200, found: true });
const page = (): PacketsPageResult => ({ items: [packet(7)], nextCursor: 200, total: 1, hasMore: false });

describe("usePacketLocateById", () => {
  it("binds packet locating workflow to provider filter, page loader, and selection state", async () => {
    const locatePacketPage = vi.fn(async () => locateResult());
    const loadPacketPage = vi.fn(async () => page());
    const { result } = renderHook(() => {
      const activeCapturePathRef = useRef("sample.pcapng");
      const captureTaskScopeRef = useRef(createCaptureTaskScope());
      const [backendStatus, setBackendStatus] = useState("");
      const [displayFilter, setDisplayFilter] = useState("tcp");
      const [selectedPacketId, setSelectedPacketId] = useState<number | null>(null);
      const locatePacketById = usePacketLocateById({
        activeCapturePathRef,
        captureTaskScopeRef,
        displayFilter,
        loadPacketPage,
        locatePacketPage,
        pageSize: 100,
        setBackendStatus,
        setDisplayFilter,
        setSelectedPacketId,
      });
      return { backendStatus, displayFilter, locatePacketById, selectedPacketId };
    });

    let located: Packet | null = null;
    await act(async () => {
      located = await result.current.locatePacketById(7.8, "udp");
    });

    expect(located).toMatchObject({ id: 7 });
    expect(locatePacketPage).toHaveBeenCalledWith(7, 100, "udp", expect.any(AbortSignal));
    expect(loadPacketPage).toHaveBeenCalledWith(100, "udp");
    expect(result.current.displayFilter).toBe("udp");
    expect(result.current.selectedPacketId).toBe(7);
    expect(result.current.backendStatus).toBe("");
  });
});

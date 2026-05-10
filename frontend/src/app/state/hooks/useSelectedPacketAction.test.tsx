import { act, renderHook } from "@testing-library/react";
import { useState } from "react";
import { describe, expect, it } from "vitest";
import type { Packet } from "../../core/types";
import { useSelectedPacketAction } from "./useSelectedPacketAction";

const packet = (id: number): Packet => ({ id, proto: "TCP" }) as Packet;

describe("useSelectedPacketAction", () => {
  it("selects packet id and drops stale selected detail", () => {
    const { result } = renderHook(() => {
      const [selectedPacketId, setSelectedPacketId] = useState<number | null>(null);
      const [selectedPacketDetail, setSelectedPacketDetail] = useState<Packet | null>(packet(4));
      const selectPacket = useSelectedPacketAction({ setSelectedPacketDetail, setSelectedPacketId });
      return { selectPacket, selectedPacketDetail, selectedPacketId };
    });

    act(() => result.current.selectPacket(5));

    expect(result.current.selectedPacketId).toBe(5);
    expect(result.current.selectedPacketDetail).toBeNull();
  });
});

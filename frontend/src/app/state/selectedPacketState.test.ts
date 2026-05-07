import { describe, expect, it } from "vitest";
import {
  keepSelectedPacketDetailForId,
  preserveSelectedPacketId,
  resolveSelectedPacket,
  shouldLoadSelectedPacketArtifacts,
  shouldLoadSelectedPacketDetail,
} from "./selectedPacketState";
import type { Packet } from "../core/types";

const packet = (id: number, extra: Partial<Packet> = {}): Packet => ({ id, proto: "TCP", ...extra }) as Packet;

describe("selectedPacketState helpers", () => {
  it("uses the first packet when no explicit selection exists", () => {
    expect(resolveSelectedPacket([packet(1), packet(2)], null, null)?.id).toBe(1);
  });

  it("uses the selected packet from the current page when available", () => {
    expect(resolveSelectedPacket([packet(1), packet(2)], 2, null)?.id).toBe(2);
  });

  it("falls back to detailed packet when the selected id is outside the current page", () => {
    expect(resolveSelectedPacket([packet(1), packet(2)], 9, packet(9))?.id).toBe(9);
  });

  it("merges page packet and detail packet for the same id", () => {
    const selected = resolveSelectedPacket([packet(7, { proto: "TCP" })], 7, packet(7, { proto: "HTTP", length: 120 }));
    expect(selected).toMatchObject({ id: 7, proto: "HTTP", length: 120 });
  });

  it("keeps cached detail only when it matches the new selected id", () => {
    expect(keepSelectedPacketDetailForId(packet(4), 4)?.id).toBe(4);
    expect(keepSelectedPacketDetailForId(packet(4), 5)).toBeNull();
  });

  it("decides when selected packet detail and artifacts need loading", () => {
    expect(shouldLoadSelectedPacketDetail(null, null)).toBe(false);
    expect(shouldLoadSelectedPacketDetail(3, packet(3))).toBe(false);
    expect(shouldLoadSelectedPacketDetail(3, packet(4))).toBe(true);
    expect(shouldLoadSelectedPacketArtifacts(null, packet(3))).toBe(false);
    expect(shouldLoadSelectedPacketArtifacts(3, null)).toBe(false);
    expect(shouldLoadSelectedPacketArtifacts(3, packet(3))).toBe(true);
  });

  it("preserves existing selection when live packets arrive", () => {
    expect(preserveSelectedPacketId(null, 8)).toBe(8);
    expect(preserveSelectedPacketId(6, 8)).toBe(6);
  });
});

import { describe, expect, it } from "vitest";
import {
  getCurrentPacketPage,
  getNextPacketCursor,
  getPacketPageCursor,
  getPrevPacketCursor,
  getTotalPacketPages,
  normalizePacketCursor,
  normalizePacketId,
  packetPageHasPacket,
} from "./packetPagination";
import type { Packet } from "../core/types";

const packet = (id: number): Packet => ({ id }) as Packet;

describe("packetPagination helpers", () => {
  it("normalizes invalid packet cursors and ids", () => {
    expect(normalizePacketCursor(Number.NaN)).toBe(0);
    expect(normalizePacketCursor(-10)).toBe(0);
    expect(normalizePacketCursor(12.9)).toBe(12);
    expect(normalizePacketId(Number.POSITIVE_INFINITY)).toBe(0);
    expect(normalizePacketId(42.7)).toBe(42);
  });

  it("moves packet cursors by page size without underflow", () => {
    expect(getNextPacketCursor(40, 20)).toBe(60);
    expect(getNextPacketCursor(Number.NaN, 20)).toBe(20);
    expect(getPrevPacketCursor(40, 20)).toBe(20);
    expect(getPrevPacketCursor(10, 20)).toBe(0);
  });

  it("computes current and total pages with a stable minimum page", () => {
    expect(getCurrentPacketPage(0, 50)).toBe(1);
    expect(getCurrentPacketPage(100, 50)).toBe(3);
    expect(getTotalPacketPages(0, 50)).toBe(1);
    expect(getTotalPacketPages(101, 50)).toBe(3);
  });

  it("clamps arbitrary page requests to known packet bounds", () => {
    expect(getPacketPageCursor(1, 150, 50)).toBe(0);
    expect(getPacketPageCursor(3, 150, 50)).toBe(100);
    expect(getPacketPageCursor(9, 150, 50)).toBe(100);
    expect(getPacketPageCursor(-4, 150, 50)).toBe(0);
    expect(getPacketPageCursor(Number.NaN, 150, 50)).toBe(0);
  });

  it("checks whether a loaded page still contains the selected packet", () => {
    const items = [packet(10), packet(11), packet(12)];
    expect(packetPageHasPacket(items, 11)).toBe(true);
    expect(packetPageHasPacket(items, 99)).toBe(false);
    expect(packetPageHasPacket(items, Number.NaN)).toBe(false);
  });
});

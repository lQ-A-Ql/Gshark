import type { Packet } from "../core/types";

export function normalizePacketCursor(cursor: number): number {
  if (!Number.isFinite(cursor)) {
    return 0;
  }
  return Math.max(0, Math.floor(cursor));
}

export function normalizePacketId(packetId: number): number {
  if (!Number.isFinite(packetId)) {
    return 0;
  }
  return Math.floor(packetId);
}

export function getNextPacketCursor(currentCursor: number, pageSize: number): number {
  return normalizePacketCursor(currentCursor) + normalizePacketPageSize(pageSize);
}

export function getPrevPacketCursor(currentCursor: number, pageSize: number): number {
  return Math.max(0, normalizePacketCursor(currentCursor) - normalizePacketPageSize(pageSize));
}

export function getTotalPacketPages(totalPackets: number, pageSize: number): number {
  const safeTotal = Number.isFinite(totalPackets) ? Math.max(0, Math.floor(totalPackets)) : 0;
  return Math.max(1, Math.ceil(safeTotal / normalizePacketPageSize(pageSize)));
}

export function getCurrentPacketPage(pageStart: number, pageSize: number): number {
  return Math.floor(normalizePacketCursor(pageStart) / normalizePacketPageSize(pageSize)) + 1;
}

export function getPacketPageCursor(page: number, totalPackets: number, pageSize: number): number {
  const totalPages = getTotalPacketPages(totalPackets, pageSize);
  const targetPage = Number.isFinite(page) ? Math.floor(page) : 1;
  const clampedPage = Math.max(1, Math.min(targetPage, totalPages));
  return (clampedPage - 1) * normalizePacketPageSize(pageSize);
}

export function packetPageHasPacket(items: Packet[], packetId: number): boolean {
  const normalized = normalizePacketId(packetId);
  if (normalized <= 0) {
    return false;
  }
  return items.some((packet) => packet.id === normalized);
}

function normalizePacketPageSize(pageSize: number): number {
  if (!Number.isFinite(pageSize) || pageSize <= 0) {
    return 1;
  }
  return Math.floor(pageSize);
}

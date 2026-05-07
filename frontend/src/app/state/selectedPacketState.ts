import type { Packet } from "../core/types";

export function resolveSelectedPacket(
  packets: Packet[],
  selectedPacketId: number | null,
  selectedPacketDetail: Packet | null,
): Packet | null {
  const fallback =
    selectedPacketId == null
      ? (packets[0] ?? null)
      : (packets.find((packet) => packet.id === selectedPacketId) ?? null);

  if (!fallback) {
    return selectedPacketDetail;
  }

  if (selectedPacketDetail?.id === fallback.id) {
    return {
      ...fallback,
      ...selectedPacketDetail,
    };
  }

  return fallback;
}

export function keepSelectedPacketDetailForId(
  selectedPacketDetail: Packet | null,
  selectedPacketId: number,
): Packet | null {
  return selectedPacketDetail?.id === selectedPacketId ? selectedPacketDetail : null;
}

export function shouldLoadSelectedPacketDetail(
  selectedPacketId: number | null,
  selectedPacketDetail: Packet | null,
): boolean {
  return selectedPacketId != null && selectedPacketDetail?.id !== selectedPacketId;
}

export function shouldLoadSelectedPacketArtifacts(
  selectedPacketId: number | null,
  selectedPacket: Packet | null,
): selectedPacket is Packet {
  return selectedPacketId != null && selectedPacket != null;
}

export function preserveSelectedPacketId(currentId: number | null, fallbackId: number): number {
  return currentId ?? fallbackId;
}

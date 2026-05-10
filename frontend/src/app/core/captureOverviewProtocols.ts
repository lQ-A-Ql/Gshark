import type { GlobalTrafficStats, Packet, TrafficBucket } from "./types";

export function pickTopProtocols(stats: GlobalTrafficStats | null, packets: Packet[]): TrafficBucket[] {
  if (stats && Array.isArray(stats.protocolDist) && stats.protocolDist.length > 0) {
    return stats.protocolDist.slice(0, 4);
  }

  const counts = new Map<string, number>();
  for (const packet of packets) {
    const label = String(packet.displayProtocol || packet.proto || "OTHER").trim().toUpperCase();
    counts.set(label, (counts.get(label) ?? 0) + 1);
  }
  return Array.from(counts.entries())
    .map(([label, count]) => ({ label, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 4);
}

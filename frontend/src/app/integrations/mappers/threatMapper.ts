import type { ThreatHit } from "../../core/types";

export function asThreatHit(input: any): ThreatHit {
  return {
    id: Number(input.id ?? 0),
    packetId: Number(input.packet_id ?? 0),
    category: String(input.category ?? "Anomaly") as ThreatHit["category"],
    rule: String(input.rule ?? ""),
    level: threatLevel(String(input.level ?? "low")),
    preview: String(input.preview ?? ""),
    match: String(input.match ?? ""),
  };
}

function threatLevel(value: string): ThreatHit["level"] {
  if (value === "critical" || value === "high" || value === "medium" || value === "low") {
    return value;
  }
  return "low";
}

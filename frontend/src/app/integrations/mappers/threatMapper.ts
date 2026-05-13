import type { ThreatHit } from "../../core/types";
import { asPlainObject } from "./mapperPrimitives";

export function asThreatHit(input: unknown): ThreatHit {
  const payload = asPlainObject(input) ?? {};
  return {
    id: Number(payload.id ?? 0),
    packetId: Number(payload.packet_id ?? 0),
    category: String(payload.category ?? "Anomaly") as ThreatHit["category"],
    rule: String(payload.rule ?? ""),
    level: threatLevel(String(payload.level ?? "low")),
    preview: String(payload.preview ?? ""),
    match: String(payload.match ?? ""),
  };
}

function threatLevel(value: string): ThreatHit["level"] {
  if (value === "critical" || value === "high" || value === "medium" || value === "low") {
    return value;
  }
  return "low";
}

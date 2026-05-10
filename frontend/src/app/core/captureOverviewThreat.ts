import type { ThreatHit } from "./types";

export function pickSuspiciousHits(threatHits: ThreatHit[]): ThreatHit[] {
  return [...threatHits]
    .sort((a, b) => threatLevelRank(b.level) - threatLevelRank(a.level) || a.packetId - b.packetId)
    .slice(0, 5);
}

function threatLevelRank(level: ThreatHit["level"]) {
  if (level === "critical") return 4;
  if (level === "high") return 3;
  if (level === "medium") return 2;
  return 1;
}

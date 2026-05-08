export type ParsedProgressStatus =
  | { consumed: false }
  | { consumed: true; kind: "malformed" }
  | { consumed: true; kind: "media"; current: number; total: number; label: string }
  | { consumed: true; kind: "threat"; current: number; total: number; label: string }
  | { consumed: true; kind: "capture"; phase: string; processed: number; total: number };

export function parseProgressStatus(message: string): ParsedProgressStatus {
  if (!message.startsWith("__progress__:")) {
    return { consumed: false };
  }
  const parts = message.split(":");
  if (parts.length < 3) {
    return { consumed: true, kind: "malformed" };
  }

  const phase = parts[1];
  if (phase === "media") {
    return {
      consumed: true,
      kind: "media",
      current: Number(parts[2]) || 0,
      total: Number(parts[3]) || 0,
      label: parts.slice(4).join(":").trim(),
    };
  }
  if (phase === "threat") {
    return {
      consumed: true,
      kind: "threat",
      current: Number(parts[2]) || 0,
      total: Number(parts[3]) || 0,
      label: parts.slice(4).join(":").trim(),
    };
  }
  if (parts.length < 4) {
    return { consumed: true, kind: "malformed" };
  }

  return {
    consumed: true,
    kind: "capture",
    phase,
    processed: Number(parts[2]) || 0,
    total: Number(parts[3]) || 0,
  };
}

export function pushRecentLabel(prev: string[], label: string, limit: number): string[] {
  if (!label) {
    return prev;
  }
  return [label, ...prev.filter((item) => item !== label)].slice(0, limit);
}

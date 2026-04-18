export function parseChunkBytes(body: string, limit = Number.POSITIVE_INFINITY): number[] {
  const raw = (body ?? "").trim();
  if (!raw) return [];
  const isHex = /^([0-9a-fA-F]{2})(:[0-9a-fA-F]{2})*$/.test(raw);
  if (!isHex) {
    return Array.from(new TextEncoder().encode(raw.slice(0, Number.isFinite(limit) ? limit : undefined)));
  }
  const parts = raw.split(":");
  const size = Math.min(parts.length, Number.isFinite(limit) ? limit : parts.length);
  const bytes: number[] = [];
  for (let i = 0; i < size; i += 1) {
    const value = Number.parseInt(parts[i], 16);
    if (Number.isFinite(value)) {
      bytes.push(value);
    }
  }
  return bytes;
}

export function bytesToAscii(bytes: number[]): string {
  if (bytes.length === 0) return "(empty payload)";
  return bytes.map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : ".")).join("");
}

export function bytesToHexDump(bytes: number[]): string {
  if (bytes.length === 0) return "(empty payload)";
  const lines: string[] = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i + 16);
    const hex = chunk.map((b) => b.toString(16).padStart(2, "0")).join(" ");
    const ascii = chunk.map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : ".")).join("");
    lines.push(`${i.toString(16).padStart(4, "0")}  ${hex.padEnd(47, " ")}  ${ascii}`);
  }
  return lines.join("\n");
}

export function estimatePayloadBytes(body: string): number {
  const raw = (body ?? "").trim();
  if (!raw) return 0;
  if (/^([0-9a-fA-F]{2})(:[0-9a-fA-F]{2})*$/.test(raw)) {
    return raw.split(":").length;
  }
  return new TextEncoder().encode(raw).length;
}

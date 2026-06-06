export function normalizePacketTime(value: unknown): string {
  const raw = String(value ?? "").trim();
  if (!raw) return "";
  if (/^\d{13,}$/.test(raw)) {
    const ms = Number(raw.slice(0, 13));
    if (!Number.isNaN(ms)) {
      const d = new Date(ms);
      return `${d.toTimeString().slice(0, 8)}.${String(d.getMilliseconds()).padStart(3, "0")}`;
    }
  }
  const parsed = new Date(raw);
  if (!Number.isNaN(parsed.getTime())) {
    return parsed.toISOString().slice(11, 23);
  }
  return raw.length > 16 ? `${raw.slice(0, 13)}...` : raw;
}

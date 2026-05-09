export function joinParts(busId: string, deviceAddress: string) {
  const parts = [busId && `bus ${busId}`, deviceAddress && `dev ${deviceAddress}`].filter(Boolean);
  return parts.length > 0 ? parts.join(" / ") : "--";
}

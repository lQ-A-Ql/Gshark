export function normalizeEvidenceKeyword(value: string | undefined): string {
  if (!value?.trim()) return "";
  const normalized = normalizeEvidenceValue(value);
  if (normalized === "ja3") return "JA3";
  if (normalized === "ja3s") return "JA3S";
  if (normalized === "china_chopper") return "菜刀 / China Chopper";
  if (normalized === "webshell") return "WebShell";
  if (normalized === "dnp3") return "DNP3";
  if (normalized === "playbook") return "Playbook";
  if (normalized === "ioc") return "IOC";
  if (normalized === "rule") return "Rule";
  return value;
}

export function normalizeEvidenceValue(value: string | undefined): string {
  return (value ?? "")
    .trim()
    .toLowerCase()
    .replace(/[\s-]+/g, "_");
}

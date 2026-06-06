import type { EvidenceModule } from "../../core/types";

export function normalizeEvidenceModule(raw: string): EvidenceModule {
  const lower = raw.toLowerCase();
  if (lower.includes("c2")) return "c2";
  if (lower.includes("apt")) return "apt";
  if (lower.includes("hunting") || lower.includes("yara") || lower.includes("threat")) return "hunting";
  if (lower.includes("industrial")) return "industrial";
  if (lower.includes("vehicle")) return "vehicle";
  if (lower.includes("usb")) return "usb";
  if (lower.includes("media") || lower.includes("speech") || lower.includes("rtp")) return "media";
  if (lower.includes("object")) return "object";
  if (lower.includes("misc") || lower.includes("webshell") || lower.includes("decoder")) return "misc";
  if (lower.includes("stream")) return "stream";
  return "unknown";
}

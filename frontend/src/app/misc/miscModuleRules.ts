import { Binary, Database, KeyRound, Mail, Shield, Wrench, type LucideIcon } from "lucide-react";
import type { MiscModuleManifest } from "../core/types";
import type { MiscCategory } from "./MiscToolsShell";

export const miscCategoryOptions: MiscCategory[] = ["Misc", "Payload", "Modules", "WinRM", "SMB3"];

export function summarizeModule(module: MiscModuleManifest) {
  const items: string[] = [];
  if (module.protocolDomain) items.push(module.protocolDomain);
  if (module.supportsExport) items.push("支持导出");
  if (module.requiresCapture) items.push("需要抓包");
  return items.slice(0, 3);
}

export function matchesCategory(module: MiscModuleManifest, category: MiscCategory) {
  const haystack = [
    module.title,
    module.summary,
    module.protocolDomain,
    ...(module.tags ?? []),
    ...(module.dependsOn ?? []),
  ]
    .join(" ")
    .toLowerCase();
  switch (category) {
    case "Modules":
      return module.kind === "custom";
    case "Payload":
      return (
        haystack.includes("payload") ||
        haystack.includes("webshell") ||
        haystack.includes("decode") ||
        haystack.includes("base64")
      );
    case "WinRM":
      return haystack.includes("winrm") || haystack.includes("ntlm");
    case "SMB3":
      return haystack.includes("smb3");
    default:
      return true;
  }
}

export function resolveModuleIcon(module: MiscModuleManifest): { Icon: LucideIcon; surface: string; text: string } {
  const haystack = [module.id, module.title, module.summary, module.protocolDomain, ...(module.tags ?? [])]
    .join(" ")
    .toLowerCase();
  if (haystack.includes("mysql")) {
    return { Icon: Database, surface: "gshark-soft-fill border-emerald-200/28 bg-emerald-50/20", text: "text-emerald-700" };
  }
  if (haystack.includes("shiro") || haystack.includes("rememberme")) {
    return { Icon: KeyRound, surface: "gshark-soft-fill border-amber-200/28 bg-amber-50/20", text: "text-amber-700" };
  }
  if (haystack.includes("smtp") || haystack.includes("mail")) {
    return { Icon: Mail, surface: "gshark-soft-fill border-sky-200/28 bg-sky-50/20", text: "text-sky-700" };
  }
  if (haystack.includes("payload") || haystack.includes("webshell") || haystack.includes("decode") || haystack.includes("base64")) {
    return { Icon: Binary, surface: "gshark-soft-fill border-cyan-200/28 bg-cyan-50/20", text: "text-cyan-700" };
  }
  if (haystack.includes("ntlm") || haystack.includes("smb3") || haystack.includes("winrm")) {
    return { Icon: KeyRound, surface: "gshark-soft-fill border-sky-200/28 bg-sky-50/20", text: "text-sky-700" };
  }
  if (haystack.includes("http") || haystack.includes("auth")) {
    return { Icon: Shield, surface: "gshark-soft-fill border-indigo-200/28 bg-indigo-50/20", text: "text-indigo-700" };
  }
  return { Icon: Wrench, surface: "gshark-soft-fill border-slate-200/28 bg-slate-50/20", text: "text-slate-700" };
}

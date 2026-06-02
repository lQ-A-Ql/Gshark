import { Binary, Database, KeyRound, Mail, Shield, Wrench, type LucideIcon } from "lucide-react";
import type { MiscModuleManifest } from "../core/types";

export type MiscCategory = "credential" | "payload" | "protocol" | "utility" | "custom";

export const miscCategoryLabels: Record<MiscCategory, string> = {
  credential: "凭据",
  payload: "Payload",
  protocol: "协议",
  utility: "工具",
  custom: "自定义",
};

export const miscCategoryOrder: MiscCategory[] = ["credential", "payload", "protocol", "utility", "custom"];

export const miscCategoryOptions: MiscCategory[] = miscCategoryOrder;

function buildHaystack(module: MiscModuleManifest): string {
  return [module.id, module.title, module.summary, module.protocolDomain, ...(module.tags ?? []), ...(module.dependsOn ?? [])]
    .join(" ")
    .toLowerCase();
}

export function moduleCategory(module: MiscModuleManifest): MiscCategory {
  if (module.kind === "custom") return "custom";
  const haystack = buildHaystack(module);
  if (haystack.includes("winrm") || haystack.includes("ntlm") || haystack.includes("smb3") || haystack.includes("shiro") || haystack.includes("rememberme")) {
    return "credential";
  }
  if (haystack.includes("payload") || haystack.includes("webshell") || haystack.includes("decode") || haystack.includes("base64")) {
    return "payload";
  }
  if (haystack.includes("http") || haystack.includes("mysql") || haystack.includes("smtp") || haystack.includes("mail")) {
    return "protocol";
  }
  if (haystack.includes("timestamp") || haystack.includes("hash") || haystack.includes("convert")) {
    return "utility";
  }
  return "utility";
}

export function matchesCategory(module: MiscModuleManifest, category: MiscCategory) {
  return moduleCategory(module) === category;
}
export function summarizeModule(module: MiscModuleManifest) {
  const items: string[] = [];
  if (module.protocolDomain) items.push(module.protocolDomain);
  if (module.supportsExport) items.push("支持导出");
  if (module.requiresCapture) items.push("需要抓包");
  return items.slice(0, 3);
}

export function resolveModuleIcon(module: MiscModuleManifest): { Icon: LucideIcon; surface: string; text: string } {
  const haystack = buildHaystack(module);
  if (haystack.includes("mysql")) {
    return { Icon: Database, surface: "meow-soft-fill border-emerald-200/28 bg-emerald-50/20", text: "text-emerald-700" };
  }
  if (haystack.includes("shiro") || haystack.includes("rememberme")) {
    return { Icon: KeyRound, surface: "meow-soft-fill border-amber-200/28 bg-amber-50/20", text: "text-amber-700" };
  }
  if (haystack.includes("smtp") || haystack.includes("mail")) {
    return { Icon: Mail, surface: "meow-soft-fill border-sky-200/28 bg-sky-50/20", text: "text-sky-700" };
  }
  if (haystack.includes("payload") || haystack.includes("webshell") || haystack.includes("decode") || haystack.includes("base64")) {
    return { Icon: Binary, surface: "meow-soft-fill border-cyan-200/28 bg-cyan-50/20", text: "text-cyan-700" };
  }
  if (haystack.includes("ntlm") || haystack.includes("smb3") || haystack.includes("winrm")) {
    return { Icon: KeyRound, surface: "meow-soft-fill border-sky-200/28 bg-sky-50/20", text: "text-sky-700" };
  }
  if (haystack.includes("http") || haystack.includes("auth")) {
    return { Icon: Shield, surface: "meow-soft-fill border-indigo-200/28 bg-indigo-50/20", text: "text-indigo-700" };
  }
  return { Icon: Wrench, surface: "meow-soft-fill border-slate-200/28 bg-slate-50/20", text: "text-slate-700" };
}

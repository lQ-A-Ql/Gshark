import {
  ChevronDown,
  Database,
  KeyRound,
  Mail,
  Binary,
  Shield,
  Upload,
  Wrench,
  type LucideIcon,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState, type ChangeEvent } from "react";
import { PageShell } from "../components/PageShell";
import { Button } from "../components/ui/button";
import { bridge } from "../integrations/wailsBridge";
import type { MiscModuleManifest } from "../core/types";
import { resolveMiscModuleRenderer } from "../misc/registry";
import { ErrorBlock } from "../misc/ui";
import { cn } from "../components/ui/utils";

type MiscCategory = "Misc" | "Payload" | "Modules" | "WinRM" | "SMB3";

const categoryOptions: MiscCategory[] = ["Misc", "Payload", "Modules", "WinRM", "SMB3"];

export default function MiscTools() {
  const [modules, setModules] = useState<MiscModuleManifest[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [importing, setImporting] = useState(false);
  const [activeCategory, setActiveCategory] = useState<MiscCategory>("Misc");
  const [expandedModules, setExpandedModules] = useState<Record<string, boolean>>({});
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  async function loadModules(isCancelled: () => boolean = () => false) {
    setLoading(true);
    setError("");
    try {
      const rows = await bridge.listMiscModules();
      if (isCancelled()) return;
      setModules(rows);
      setExpandedModules((current) => {
        const next = { ...current };
        for (const module of rows) {
          if (next[module.id] === undefined) {
            next[module.id] = module.id === rows[0]?.id;
          }
        }
        return next;
      });
    } catch (loadError) {
      if (isCancelled()) return;
      setModules([]);
      setError(loadError instanceof Error ? loadError.message : "加载 MISC 模块失败");
    } finally {
      if (!isCancelled()) {
        setLoading(false);
      }
    }
  }

  useEffect(() => {
    let cancelled = false;
    void loadModules(() => cancelled);
    return () => {
      cancelled = true;
    };
  }, []);

  async function handleImportModule(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) {
      return;
    }
    setImporting(true);
    setError("");
    try {
      await bridge.importMiscModulePackage(file);
      await loadModules();
      setActiveCategory("Misc");
    } catch (importError) {
      setError(importError instanceof Error ? importError.message : "导入模块包失败");
    } finally {
      setImporting(false);
    }
  }

  async function handleModuleDeleted() {
    await loadModules();
  }

  function toggleModule(moduleID: string) {
    setExpandedModules((current) => ({
      ...current,
      [moduleID]: !current[moduleID],
    }));
  }

  const filteredModules = useMemo(() => modules.filter((module) => matchesCategory(module, activeCategory)), [modules, activeCategory]);

  const heroDescription = useMemo(() => {
    const builtins = modules.filter((module) => module.kind !== "custom").length;
    const customs = modules.filter((module) => module.kind === "custom").length;
    return `将低频但高价值的协议辅助能力按模块编排，当前已接入 ${modules.length} 个模块（内建 ${builtins} / 自定义 ${customs}）。`;
  }, [modules]);

  return (
    <PageShell
      className="bg-[radial-gradient(circle_at_top,rgba(196,181,253,0.45),transparent_38%),linear-gradient(180deg,#efeafe_0%,#ece9ff_36%,#edefff_100%)]"
      innerClassName="mx-auto flex w-full max-w-[1160px] flex-col gap-6 px-4 py-8 sm:px-6 lg:px-8"
    >
      <section className="rounded-[28px] border border-white/70 bg-white/72 px-6 py-6 shadow-[0_30px_80px_rgba(108,99,255,0.16)] backdrop-blur-xl sm:px-8 lg:px-10">
        <div className="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">
          <div className="min-w-0 flex-1 space-y-4">
            <div className="flex flex-wrap items-center gap-4">
              <div className="flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-violet-100 text-violet-600 shadow-sm">
                  <Wrench className="h-4.5 w-4.5" />
                </div>
                <div className="min-w-0">
                  <div className="flex flex-wrap items-baseline gap-2">
                    <h1 className="text-[19px] font-bold tracking-tight text-slate-900 sm:text-[22px]">MISC 工具箱</h1>
                    <span className="text-[11px] font-semibold uppercase tracking-[0.32em] text-slate-400">SPECIALIZED TRAFFIC UTILITIES</span>
                  </div>
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-2 rounded-full border border-violet-100/90 bg-violet-50/60 px-3 py-2 text-xs text-slate-500 shadow-sm">
                <span className="font-semibold text-slate-600">模块层</span>
                {categoryOptions.map((item) => {
                  const active = activeCategory === item;
                  return (
                    <button
                      key={item}
                      type="button"
                      onClick={() => setActiveCategory(item)}
                      className={cn(
                        "rounded-full border px-3 py-1 font-medium transition-all",
                        active
                          ? "border-violet-200 bg-violet-100 text-violet-700 shadow-sm"
                          : "border-slate-200 bg-white/80 text-slate-500 hover:border-violet-200 hover:text-violet-600",
                      )}
                    >
                      {item}
                    </button>
                  );
                })}
              </div>
            </div>

            <div className="grid gap-3 text-[13px] text-slate-500 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-end">
              <p className="max-w-2xl leading-7 text-slate-500">{heroDescription}</p>
              <div className="flex flex-wrap gap-2 text-[11px]">
                <span className="rounded-full border border-violet-100 bg-violet-50 px-3 py-1 text-violet-700 shadow-sm">支持中断</span>
                <span className="rounded-full border border-slate-200 bg-white/80 px-3 py-1 text-slate-600 shadow-sm">协议专题</span>
                <span className="rounded-full border border-slate-200 bg-white/80 px-3 py-1 text-slate-600 shadow-sm">结果可导出</span>
              </div>
            </div>
          </div>

          <div className="flex shrink-0 flex-col items-start gap-3 lg:items-end">
            <div className="max-w-[360px] text-sm leading-7 text-slate-500 lg:text-right">
              将低频但高价值的协议辅助能力按模块编排，内置 WinRM 与 SMB3，同时为自定义模块预留稳定接入位。
            </div>
            <input ref={fileInputRef} type="file" accept=".zip" className="hidden" onChange={(event) => void handleImportModule(event)} />
            <Button
              type="button"
              onClick={() => fileInputRef.current?.click()}
              disabled={importing}
              className="h-11 rounded-full bg-slate-900 px-5 text-sm font-semibold text-white shadow-[0_18px_36px_rgba(15,23,42,0.26)] hover:bg-slate-800"
            >
              <Upload className="mr-2 h-4 w-4" />
              {importing ? "导入中..." : "导入模块 ZIP"}
            </Button>
          </div>
        </div>
      </section>

      {error && <ErrorBlock message={error} />}

      {loading ? (
        <div className="rounded-[24px] border border-white/80 bg-white/86 px-4 py-12 text-center text-sm font-medium text-slate-500 shadow-[0_20px_55px_rgba(148,163,184,0.16)] backdrop-blur">
          正在加载 MISC 模块...
        </div>
      ) : (
        <div className="space-y-4">
          {filteredModules.map((module) => {
            const Renderer = resolveMiscModuleRenderer(module.id);
            const expanded = Boolean(expandedModules[module.id]);
            const meta = summarizeModule(module);
            const icon = resolveModuleIcon(module);
            return (
              <section
                key={module.id}
                className={cn(
                  "overflow-hidden rounded-[24px] border bg-white/88 shadow-[0_22px_55px_rgba(148,163,184,0.16)] backdrop-blur-xl transition-all duration-300 hover:shadow-[0_28px_72px_rgba(99,102,241,0.16)]",
                  expanded ? "border-violet-200/80 shadow-[0_28px_72px_rgba(99,102,241,0.18)]" : "border-white/80",
                )}
              >
                <button
                  type="button"
                  data-testid={`misc-module-toggle-${module.id}`}
                  onClick={() => toggleModule(module.id)}
                  aria-expanded={expanded}
                  className="flex w-full items-center justify-between gap-4 px-6 py-5 text-left sm:px-7"
                >
                  <div className="flex min-w-0 items-center gap-4">
                    <div className={cn("flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl border shadow-sm", icon.surface)}>
                      <icon.Icon className={cn("h-4.5 w-4.5", icon.text)} />
                    </div>
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <h2 className="truncate text-[17px] font-semibold tracking-tight text-slate-900">{module.title}</h2>
                        {module.kind === "custom" ? (
                          <span className="rounded-full border border-violet-200 bg-violet-50 px-2.5 py-0.5 text-[11px] font-semibold text-violet-700">Custom</span>
                        ) : null}
                        {module.cancellable ? (
                          <span
                            title="该模块的分析请求支持中途取消或切换时自动中断"
                            className="rounded-full border border-emerald-200 bg-emerald-50 px-2.5 py-0.5 text-[11px] font-semibold text-emerald-700"
                          >
                            支持中断
                          </span>
                        ) : null}
                      </div>
                      <div className="mt-1 flex flex-wrap items-center gap-2 text-[12px] text-slate-500">
                        <span className="line-clamp-1 max-w-[640px]">{module.summary}</span>
                        {meta.length > 0 ? <span className="text-slate-300">•</span> : null}
                        {meta.map((item) => (
                          <span key={`${module.id}-${item}`} className="rounded-full border border-slate-200 bg-slate-50 px-2.5 py-0.5 text-[11px] text-slate-500 shadow-sm">
                            {item}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>

                  <div className="flex shrink-0 items-center">
                    <span
                      className={cn(
                        "inline-flex items-center gap-2 rounded-full border px-3.5 py-1.5 text-[11px] font-semibold shadow-sm transition-all sm:text-xs",
                        expanded
                          ? "border-violet-200 bg-violet-50 text-violet-700"
                          : "border-slate-200 bg-white text-slate-500",
                      )}
                    >
                      {expanded ? "收起工作台" : "展开工作台"}
                      <ChevronDown className={cn("h-4 w-4 transition-transform duration-300", expanded ? "rotate-180" : "")} />
                    </span>
                  </div>
                </button>

                <div
                  aria-hidden={!expanded}
                  className={cn(
                    "grid transition-[grid-template-rows,opacity,visibility] duration-300 ease-[cubic-bezier(0.22,1,0.36,1)]",
                    expanded ? "visible grid-rows-[1fr] opacity-100" : "pointer-events-none invisible grid-rows-[0fr] opacity-0",
                  )}
                >
                  <div className="overflow-hidden px-6 pb-6 sm:px-7">
                    <div className="pt-1">
                      <Renderer module={module} onModuleDeleted={handleModuleDeleted} surfaceVariant="embedded" />
                    </div>
                  </div>
                </div>
              </section>
            );
          })}

          {filteredModules.length === 0 && !error && (
            <div className="rounded-[24px] border border-dashed border-white/80 bg-white/86 px-4 py-12 text-center text-sm text-slate-500 shadow-[0_18px_50px_rgba(148,163,184,0.12)]">
              当前筛选下没有可展示的 MISC 模块。
            </div>
          )}
        </div>
      )}
    </PageShell>
  );
}

function summarizeModule(module: MiscModuleManifest) {
  const items: string[] = [];
  if (module.protocolDomain) items.push(module.protocolDomain);
  if (module.supportsExport) items.push("支持导出");
  if (module.requiresCapture) items.push("需要抓包");
  return items.slice(0, 3);
}

function matchesCategory(module: MiscModuleManifest, category: MiscCategory) {
  const haystack = [module.title, module.summary, module.protocolDomain, ...(module.tags ?? []), ...(module.dependsOn ?? [])]
    .join(" ")
    .toLowerCase();
  switch (category) {
    case "Modules":
      return module.kind === "custom";
    case "Payload":
      return haystack.includes("payload") || haystack.includes("webshell") || haystack.includes("decode") || haystack.includes("base64");
    case "WinRM":
      return haystack.includes("winrm") || haystack.includes("ntlm");
    case "SMB3":
      return haystack.includes("smb3");
    default:
      return true;
  }
}

function resolveModuleIcon(module: MiscModuleManifest): { Icon: LucideIcon; surface: string; text: string } {
  const haystack = [module.id, module.title, module.summary, module.protocolDomain, ...(module.tags ?? [])].join(" ").toLowerCase();
  if (haystack.includes("mysql")) {
    return { Icon: Database, surface: "border-emerald-200 bg-emerald-50", text: "text-emerald-700" };
  }
  if (haystack.includes("shiro") || haystack.includes("rememberme")) {
    return { Icon: KeyRound, surface: "border-amber-200 bg-amber-50", text: "text-amber-700" };
  }
  if (haystack.includes("smtp") || haystack.includes("mail")) {
    return { Icon: Mail, surface: "border-sky-200 bg-sky-50", text: "text-sky-700" };
  }
  if (haystack.includes("payload") || haystack.includes("webshell") || haystack.includes("decode") || haystack.includes("base64")) {
    return { Icon: Binary, surface: "border-cyan-200 bg-cyan-50", text: "text-cyan-700" };
  }
  if (haystack.includes("ntlm") || haystack.includes("smb3") || haystack.includes("winrm")) {
    return { Icon: KeyRound, surface: "border-violet-200 bg-violet-50", text: "text-violet-700" };
  }
  if (haystack.includes("http") || haystack.includes("auth")) {
    return { Icon: Shield, surface: "border-indigo-200 bg-indigo-50", text: "text-indigo-700" };
  }
  return { Icon: Wrench, surface: "border-slate-200 bg-slate-50", text: "text-slate-700" };
}

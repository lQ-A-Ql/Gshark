import { Suspense } from "react";
import { ChevronDown } from "lucide-react";
import { CollapsibleContent, StatusHint } from "../components/DesignSystem";
import { cn } from "../components/ui/utils";
import type { MiscModuleManifest } from "../core/types";
import { resolveMiscModuleRenderer } from "./registry";
import { resolveModuleIcon, summarizeModule } from "./miscModuleRules";

interface MiscModuleCardProps {
  module: MiscModuleManifest;
  expanded: boolean;
  mounted: boolean;
  onModuleDeleted: (moduleId: string) => void | Promise<void>;
  onToggleModule: (moduleId: string) => void;
}

export function MiscModuleCard({ module, expanded, mounted, onModuleDeleted, onToggleModule }: MiscModuleCardProps) {
  const Renderer = resolveMiscModuleRenderer(module.id);
  const meta = summarizeModule(module);
  const icon = resolveModuleIcon(module);
  return (
    <section
      className={cn(
        "overflow-hidden rounded-[24px] border bg-white/88 shadow-[0_22px_55px_rgba(148,163,184,0.16)] backdrop-blur-xl transition-all duration-300 hover:shadow-[0_28px_72px_rgba(8,145,178,0.14)]",
        expanded ? "border-cyan-200/80 shadow-[0_28px_72px_rgba(8,145,178,0.16)]" : "border-white/80",
      )}
    >
      <button
        type="button"
        data-testid={`misc-module-toggle-${module.id}`}
        onClick={() => onToggleModule(module.id)}
        aria-expanded={expanded}
        className="flex w-full items-center justify-between gap-4 px-6 py-5 text-left sm:px-7"
      >
        <div className="flex min-w-0 items-center gap-4">
          <div
            className={cn(
              "flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl border shadow-sm",
              icon.surface,
            )}
          >
            <icon.Icon className={cn("h-4.5 w-4.5", icon.text)} />
          </div>
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="truncate text-[17px] font-semibold tracking-tight text-slate-900">{module.title}</h2>
              {module.kind === "custom" ? (
                <span className="rounded-full border border-slate-200 bg-slate-50 px-2.5 py-0.5 text-[11px] font-semibold text-slate-700">
                  Custom
                </span>
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
                <span
                  key={`${module.id}-${item}`}
                  className="rounded-full border border-slate-200 bg-slate-50 px-2.5 py-0.5 text-[11px] text-slate-500 shadow-sm"
                >
                  {item}
                </span>
              ))}
            </div>
          </div>
        </div>

        <span
          className={cn(
            "inline-flex shrink-0 items-center gap-2 rounded-full border px-3.5 py-1.5 text-[11px] font-semibold shadow-sm transition-all sm:text-xs",
            expanded ? "border-cyan-200 bg-cyan-50 text-cyan-700" : "border-slate-200 bg-white text-slate-500",
          )}
        >
          {expanded ? "收起工作台" : "展开工作台"}
          <ChevronDown className={cn("h-4 w-4 transition-transform duration-300", expanded ? "rotate-180" : "")} />
        </span>
      </button>

      <CollapsibleContent open={expanded}>
        {mounted ? (
          <div className="px-6 pb-6 sm:px-7">
            <div className="border-t border-slate-100 pt-5">
              <Suspense fallback={<ModuleLoadingState module={module} />}>
                <Renderer module={module} onModuleDeleted={onModuleDeleted} surfaceVariant="embedded" />
              </Suspense>
            </div>
          </div>
        ) : null}
      </CollapsibleContent>
    </section>
  );
}

function ModuleLoadingState({ module }: { module: MiscModuleManifest }) {
  return (
    <StatusHint className="px-4 py-8 text-center text-sm font-medium" tone="cyan">
      正在加载 {module.title} 工作台...
    </StatusHint>
  );
}

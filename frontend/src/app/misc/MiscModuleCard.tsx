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
        "gshark-tile gshark-diffuse-edge overflow-hidden transition-all duration-300",
        expanded ? "border-cyan-200/28" : "border-white/18",
      )}
    >
      <button
        type="button"
        data-testid={`misc-module-toggle-${module.id}`}
        onClick={() => onToggleModule(module.id)}
        aria-expanded={expanded}
        className="flex w-full items-center justify-between gap-4 px-4 py-4 text-left sm:px-5"
      >
        <div className="flex min-w-0 items-center gap-4">
          <div className={cn("flex h-10 w-10 shrink-0 items-center justify-center", icon.surface)}>
            <icon.Icon className={cn("h-4.5 w-4.5", icon.text)} />
          </div>
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="truncate text-[15px] font-semibold tracking-tight text-slate-900">{module.title}</h2>
              {module.kind === "custom" ? (
                <span className="gshark-diffuse-chip border-slate-200/22 bg-slate-50/18 px-2.5 py-0.5 text-[11px] font-semibold text-slate-700">
                  Custom
                </span>
              ) : null}
              {module.cancellable ? (
                <span
                  title="该模块的分析请求支持中途取消或切换时自动中断"
                  className="gshark-diffuse-chip border-emerald-200/24 bg-emerald-50/18 px-2.5 py-0.5 text-[11px] font-semibold text-emerald-700"
                >
                  支持中断
                </span>
              ) : null}
            </div>
            <div className="mt-1 flex flex-wrap items-center gap-2 text-[11px] text-slate-500">
              <span className="line-clamp-1 max-w-[640px]">{module.summary}</span>
              {meta.length > 0 ? <span className="text-slate-300">•</span> : null}
              {meta.map((item) => (
                <span
                  key={`${module.id}-${item}`}
                  className="gshark-diffuse-chip border-slate-200/20 bg-slate-50/14 px-2.5 py-0.5 text-[11px] text-slate-500"
                >
                  {item}
                </span>
              ))}
            </div>
          </div>
        </div>

        <span
          className={cn(
            "gshark-diffuse-chip inline-flex shrink-0 items-center gap-2 px-3 py-1.5 text-[11px] font-semibold transition-all",
            expanded
              ? "border-cyan-200/28 bg-cyan-50/18 text-cyan-700"
              : "border-slate-200/20 bg-slate-50/12 text-slate-500",
          )}
        >
          {expanded ? "收起工作台" : "展开工作台"}
          <ChevronDown className={cn("h-4 w-4 transition-transform duration-300", expanded ? "rotate-180" : "")} />
        </span>
      </button>

      <CollapsibleContent open={expanded}>
        {mounted ? (
          <div className="px-4 pb-4 sm:px-5">
            <div className="border-t border-[var(--gshark-tile-divider)] pt-4">
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

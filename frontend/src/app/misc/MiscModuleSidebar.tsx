import { useMemo } from "react";
import { cn } from "../components/ui/utils";
import type { MiscModuleManifest } from "../core/types";
import { miscCategoryLabels, miscCategoryOrder, moduleCategory, resolveModuleIcon, type MiscCategory } from "./miscModuleRules";

interface MiscModuleSidebarProps {
  modules: MiscModuleManifest[];
  selectedModuleId: string | null;
  onSelectModule: (id: string) => void;
}

export function MiscModuleSidebar({ modules, selectedModuleId, onSelectModule }: MiscModuleSidebarProps) {
  const grouped = useMemo(() => {
    const groups: Record<MiscCategory, MiscModuleManifest[]> = {
      credential: [],
      payload: [],
      protocol: [],
      utility: [],
      custom: [],
    };
    for (const mod of modules) {
      const cat = moduleCategory(mod);
      groups[cat].push(mod);
    }
    return groups;
  }, [modules]);

  return (
    <nav className="meow-aurora-surface flex w-56 shrink-0 flex-col overflow-y-auto border-r border-[var(--meow-tile-divider)]">
      <div className="flex flex-col gap-1 p-3">
        {miscCategoryOrder.map((category) => {
          const items = grouped[category];
          if (items.length === 0) return null;
          return (
            <div key={category} className="mb-1">
              <div className="px-2 pb-1 pt-2 text-[10px] font-semibold uppercase tracking-[0.2em] text-slate-400">
                {miscCategoryLabels[category]}
              </div>
              {items.map((mod) => {
                const isActive = selectedModuleId === mod.id;
                const icon = resolveModuleIcon(mod);
                return (
                  <button
                    key={mod.id}
                    type="button"
                    data-testid={`misc-module-toggle-${mod.id}`}
                    aria-expanded={isActive}
                    onClick={() => onSelectModule(mod.id)}
                    className={cn(
                      "flex w-full items-center gap-2.5 rounded-sm px-2 py-1.5 text-left text-[13px] transition-all",
                      isActive
                        ? "bg-cyan-50/30 font-semibold text-cyan-800 shadow-[inset_0_0_0_1px_rgba(6,182,212,0.18)]"
                        : "text-slate-600 hover:bg-slate-50/40 hover:text-slate-800",
                    )}
                  >
                    <icon.Icon className={cn("h-3.5 w-3.5 shrink-0", isActive ? "text-cyan-600" : icon.text)} />
                    <span className="truncate">{mod.title}</span>
                  </button>
                );
              })}
            </div>
          );
        })}
      </div>
    </nav>
  );
}

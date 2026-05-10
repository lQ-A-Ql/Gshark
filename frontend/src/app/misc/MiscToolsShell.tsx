import { useMemo } from "react";
import { EmptyState, StatusHint } from "../components/DesignSystem";
import { PageShell } from "../components/PageShell";
import type { MiscModuleManifest } from "../core/types";
import { ErrorBlock } from "./ui";
import { MiscModuleCard } from "./MiscModuleCard";
import { MiscToolsHero } from "./MiscToolsHero";
import { matchesCategory } from "./miscModuleRules";

export type MiscCategory = "Misc" | "Payload" | "Modules" | "WinRM" | "SMB3";

interface MiscToolsShellProps {
  modules: MiscModuleManifest[];
  loading: boolean;
  error: string;
  importing: boolean;
  activeCategory: MiscCategory;
  expandedModules: Record<string, boolean>;
  mountedModules: Record<string, boolean>;
  onCategoryChange: (category: MiscCategory) => void;
  onImportModule: (file: File) => void | Promise<void>;
  onModuleDeleted: (moduleId: string) => void | Promise<void>;
  onToggleModule: (moduleId: string) => void;
}

export function MiscToolsShell({
  modules,
  loading,
  error,
  importing,
  activeCategory,
  expandedModules,
  mountedModules,
  onCategoryChange,
  onImportModule,
  onModuleDeleted,
  onToggleModule,
}: MiscToolsShellProps) {
  const filteredModules = useMemo(
    () => modules.filter((module) => matchesCategory(module, activeCategory)),
    [modules, activeCategory],
  );
  const heroDescription = useMemo(() => {
    const builtins = modules.filter((module) => module.kind !== "custom").length;
    const customs = modules.filter((module) => module.kind === "custom").length;
    return `将低频但高价值的协议辅助能力按模块编排，当前已接入 ${modules.length} 个模块（内建 ${builtins} / 自定义 ${customs}）。`;
  }, [modules]);

  return (
    <PageShell
      className="bg-[radial-gradient(circle_at_top,rgba(125,211,252,0.42),transparent_38%),linear-gradient(180deg,#ecfeff_0%,#f0fdfa_36%,#f8fafc_100%)]"
      innerClassName="mx-auto flex w-full max-w-[1160px] flex-col gap-6 px-4 py-8 sm:px-6 lg:px-8"
    >
      <MiscToolsHero
        activeCategory={activeCategory}
        heroDescription={heroDescription}
        importing={importing}
        onCategoryChange={onCategoryChange}
        onImportModule={onImportModule}
      />

      {error && <ErrorBlock message={error} />}

      {loading ? (
        <StatusHint
          className="px-4 py-12 text-center text-sm font-medium shadow-[0_20px_55px_rgba(148,163,184,0.16)]"
          tone="cyan"
        >
          正在加载 MISC 模块...
        </StatusHint>
      ) : (
        <div className="space-y-4">
          {filteredModules.map((module) => (
            <MiscModuleCard
              key={module.id}
              module={module}
              expanded={Boolean(expandedModules[module.id])}
              mounted={Boolean(expandedModules[module.id]) || Boolean(mountedModules[module.id])}
              onModuleDeleted={onModuleDeleted}
              onToggleModule={onToggleModule}
            />
          ))}

          {filteredModules.length === 0 && !error && (
            <EmptyState className="border-white/80 bg-white/86 px-4 py-12 text-sm shadow-[0_18px_50px_rgba(148,163,184,0.12)]">
              当前筛选下没有可展示的 MISC 模块。
            </EmptyState>
          )}
        </div>
      )}
    </PageShell>
  );
}

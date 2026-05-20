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
    <PageShell>
      <MiscToolsHero
        activeCategory={activeCategory}
        heroDescription={heroDescription}
        importing={importing}
        onCategoryChange={onCategoryChange}
        onImportModule={onImportModule}
      />

      {error && <ErrorBlock message={error} />}

      {loading ? (
        <StatusHint className="gshark-tile px-4 py-12 text-center text-sm font-medium" tone="cyan">
          正在加载 MISC 模块...
        </StatusHint>
      ) : (
        <div className="gshark-tile-grid">
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
            <EmptyState className="gshark-tile px-4 py-12 text-sm">当前筛选下没有可展示的 MISC 模块。</EmptyState>
          )}
        </div>
      )}
    </PageShell>
  );
}

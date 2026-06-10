import { useMemo } from "react";
import { AnalysisWorkbenchShell } from "../components/analysis/AnalysisWorkbenchShell";
import type { AnalysisWorkbenchSection } from "../components/analysis/analysisWorkbenchTypes";
import { StatusHint } from "../components/DesignSystem";
import { PageShell } from "../components/PageShell";
import { cn } from "../components/ui/utils";
import type { MiscModuleManifest } from "../core/types";
import { miscCategoryLabels, miscCategoryOrder, moduleCategory, resolveModuleIcon } from "./miscModuleRules";
import { ErrorBlock } from "./ui";
import { MiscToolsSlimHeader } from "./MiscToolsSlimHeader";
import { MiscModuleWorkbench } from "./MiscModuleWorkbench";

export type { MiscCategory } from "./miscModuleRules";

interface MiscToolsShellProps {
  modules: MiscModuleManifest[];
  loading: boolean;
  error: string;
  importing: boolean;
  selectedModuleId: string | null;
  onSelectModule: (id: string) => void;
  onImportModule: (file: File) => void | Promise<void>;
  onImportModuleFromNativeDialog?: () => void | Promise<void>;
  onModuleDeleted: (moduleId: string) => void | Promise<void>;
}

export function MiscToolsShell({
  modules,
  loading,
  error,
  importing,
  selectedModuleId,
  onSelectModule,
  onImportModule,
  onImportModuleFromNativeDialog,
  onModuleDeleted,
}: MiscToolsShellProps) {
  const moduleSections = useMemo(() => buildMiscModuleSections(modules, selectedModuleId), [modules, selectedModuleId]);

  return (
    <PageShell>
      <MiscToolsSlimHeader
        moduleCount={modules.length}
        importing={importing}
        onImportModule={onImportModule}
        onImportModuleFromNativeDialog={onImportModuleFromNativeDialog}
      />

      {error && <ErrorBlock message={error} />}

      {loading ? (
        <StatusHint className="meow-tile px-4 py-12 text-center text-sm font-medium" tone="cyan">
          正在加载 MISC 模块...
        </StatusHint>
      ) : (
        <AnalysisWorkbenchShell
          sections={moduleSections}
          selectedSection={selectedModuleId ?? ""}
          onSectionChange={onSelectModule}
          title={modules.find((mod) => mod.id === selectedModuleId)?.title}
          description={modules.find((mod) => mod.id === selectedModuleId)?.summary}
          contentClassName="p-5"
          navLabel="MISC 模块导航"
        >
          <MiscModuleWorkbench
            modules={modules}
            selectedModuleId={selectedModuleId}
            onModuleDeleted={onModuleDeleted}
          />
        </AnalysisWorkbenchShell>
      )}
    </PageShell>
  );
}

function buildMiscModuleSections(
  modules: MiscModuleManifest[],
  selectedModuleId: string | null,
): AnalysisWorkbenchSection[] {
  const grouped = new Map<string, MiscModuleManifest[]>();
  for (const category of miscCategoryOrder) grouped.set(category, []);
  for (const mod of modules) {
    grouped.get(moduleCategory(mod))?.push(mod);
  }

  const sections: AnalysisWorkbenchSection[] = [];
  for (const category of miscCategoryOrder) {
    for (const mod of grouped.get(category) ?? []) {
      const icon = resolveModuleIcon(mod);
      const active = selectedModuleId === mod.id;
      sections.push({
        id: mod.id,
        title: mod.title,
        group: miscCategoryLabels[category],
        testId: `misc-module-toggle-${mod.id}`,
        expanded: active,
        icon: <icon.Icon className={cn("h-3.5 w-3.5", active ? "text-cyan-600" : icon.text)} />,
      });
    }
  }
  return sections;
}

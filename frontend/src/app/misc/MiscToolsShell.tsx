import { StatusHint } from "../components/DesignSystem";
import { PageShell } from "../components/PageShell";
import type { MiscModuleManifest } from "../core/types";
import { ErrorBlock } from "./ui";
import { MiscToolsSlimHeader } from "./MiscToolsSlimHeader";
import { MiscModuleSidebar } from "./MiscModuleSidebar";
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
        <div className="flex min-h-0 flex-1 overflow-hidden">
          <MiscModuleSidebar
            modules={modules}
            selectedModuleId={selectedModuleId}
            onSelectModule={onSelectModule}
          />
          <MiscModuleWorkbench
            modules={modules}
            selectedModuleId={selectedModuleId}
            onModuleDeleted={onModuleDeleted}
          />
        </div>
      )}
    </PageShell>
  );
}

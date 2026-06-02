import { Suspense } from "react";
import { StatusHint } from "../components/DesignSystem";
import { MeowEmptyState } from "../components/MeowEmptyState";
import type { MiscModuleManifest } from "../core/types";
import { summarizeModule } from "./miscModuleRules";
import { resolveMiscModuleRenderer } from "./registry";

interface MiscModuleWorkbenchProps {
  modules: MiscModuleManifest[];
  selectedModuleId: string | null;
  onModuleDeleted: (moduleId: string) => void | Promise<void>;
}

export function MiscModuleWorkbench({ modules, selectedModuleId, onModuleDeleted }: MiscModuleWorkbenchProps) {
  const selectedModule = selectedModuleId ? modules.find((m) => m.id === selectedModuleId) : null;

  if (!selectedModule) {
    return (
      <div className="flex flex-1 items-center justify-center overflow-auto p-8">
        <MeowEmptyState variant="box">
          当前筛选下没有可展示的 MISC 模块。
        </MeowEmptyState>
      </div>
    );
  }

  const Renderer = resolveMiscModuleRenderer(selectedModule.id);
  const meta = summarizeModule(selectedModule);

  return (
    <div className="flex-1 overflow-auto p-5">
      <div className="mb-4 flex flex-wrap items-center gap-2 text-[12px] text-slate-500">
        <span className="font-semibold text-slate-700">{selectedModule.summary}</span>
        {meta.length > 0 && <span className="text-slate-300">·</span>}
        {meta.map((item) => (
          <span key={item} className="meow-diffuse-chip border-slate-200/20 bg-slate-50/14 px-2.5 py-0.5 text-[11px] text-slate-500">
            {item}
          </span>
        ))}
      </div>
      <Suspense fallback={<WorkbenchLoading title={selectedModule.title} />}>
        <Renderer module={selectedModule} onModuleDeleted={onModuleDeleted} surfaceVariant="card" />
      </Suspense>
    </div>
  );
}

function WorkbenchLoading({ title }: { title: string }) {
  return (
    <StatusHint className="px-4 py-12 text-center text-sm font-medium" tone="cyan">
      正在加载 {title} 工作台...
    </StatusHint>
  );
}

import { Wrench } from "lucide-react";
import { MiscImportButtons } from "./MiscImportButtons";

interface MiscToolsSlimHeaderProps {
  moduleCount: number;
  importing: boolean;
  onImportModule: (file: File) => void | Promise<void>;
  onImportModuleFromNativeDialog?: () => void | Promise<void>;
}

export function MiscToolsSlimHeader({
  moduleCount,
  importing,
  onImportModule,
  onImportModuleFromNativeDialog,
}: MiscToolsSlimHeaderProps) {
  return (
    <header className="flex items-center justify-between gap-4 border-b border-[var(--meow-tile-divider)] px-5 py-3">
      <div className="flex items-center gap-3">
        <div className="meow-soft-fill flex h-8 w-8 items-center justify-center border-cyan-200/24 bg-cyan-50/18 text-cyan-700">
          <Wrench className="h-3.5 w-3.5" />
        </div>
        <h1 className="text-[15px] font-bold tracking-tight text-slate-900">MISC 工具箱</h1>
        <span className="meow-diffuse-chip border-slate-200/20 bg-slate-50/14 px-2.5 py-0.5 text-[11px] font-semibold text-slate-500">
          {moduleCount} 个模块
        </span>
      </div>
      <MiscImportButtons
        importing={importing}
        onImportModule={onImportModule}
        onImportModuleFromNativeDialog={onImportModuleFromNativeDialog}
      />
    </header>
  );
}

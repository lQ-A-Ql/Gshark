import { useRef, type ChangeEvent } from "react";
import { Upload, Wrench } from "lucide-react";
import { Button } from "../components/ui/button";
import { cn } from "../components/ui/utils";
import type { MiscCategory } from "./MiscToolsShell";
import { miscCategoryOptions } from "./miscModuleRules";

interface MiscToolsHeroProps {
  activeCategory: MiscCategory;
  heroDescription: string;
  importing: boolean;
  onCategoryChange: (category: MiscCategory) => void;
  onImportModule: (file: File) => void | Promise<void>;
}

export function MiscToolsHero({
  activeCategory,
  heroDescription,
  importing,
  onCategoryChange,
  onImportModule,
}: MiscToolsHeroProps) {
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  function handleImportModule(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (file) void onImportModule(file);
  }

  return (
    <section className="gshark-tile-header overflow-hidden">
      <div className="pointer-events-none h-px w-full bg-gradient-to-r from-cyan-400/20 via-sky-400/10 to-transparent" />
      <div className="flex flex-col gap-4 px-5 py-4 sm:px-6 lg:flex-row lg:items-start lg:justify-between">
        <div className="min-w-0 flex-1 space-y-3">
          <div className="flex flex-wrap items-center gap-3">
            <div className="flex items-center gap-3">
              <div className="gshark-soft-fill flex h-10 w-10 items-center justify-center border-cyan-200/24 bg-cyan-50/18 text-cyan-700">
                <Wrench className="h-4.5 w-4.5" />
              </div>
              <div className="min-w-0">
                <div className="flex flex-wrap items-baseline gap-2">
                  <h1 className="text-[18px] font-bold tracking-tight text-slate-900 sm:text-[20px]">MISC 工具箱</h1>
                  <span className="text-[10px] font-semibold uppercase tracking-[0.28em] text-slate-400">
                    SPECIALIZED TRAFFIC UTILITIES
                  </span>
                </div>
              </div>
            </div>

            <div className="gshark-tile-toolbar flex flex-wrap items-center gap-1.5 border-cyan-200/18 bg-cyan-50/10 px-2.5 py-1.5 text-xs text-slate-500">
              <span className="font-semibold text-slate-600">模块层</span>
              {miscCategoryOptions.map((item) => {
                const active = activeCategory === item;
                return (
                  <button
                    key={item}
                    type="button"
                    onClick={() => onCategoryChange(item)}
                    className={cn(
                      "border px-2.5 py-0.5 font-medium transition-all",
                      "gshark-diffuse-chip",
                      active
                        ? "border-cyan-200/28 bg-cyan-50/24 text-cyan-700"
                        : "border-slate-200/18 bg-slate-50/10 text-slate-500 hover:border-cyan-200/28 hover:text-cyan-700",
                    )}
                  >
                    {item}
                  </button>
                );
              })}
            </div>
          </div>

          <div className="grid gap-3 text-[12px] text-slate-500 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-end">
            <p className="max-w-2xl leading-6 text-slate-500">{heroDescription}</p>
            <div className="flex flex-wrap gap-2 text-[11px]">
              <span className="gshark-diffuse-chip border-cyan-200/22 bg-cyan-50/18 px-3 py-1 text-cyan-700">
                支持中断
              </span>
              <span className="gshark-diffuse-chip border-slate-200/18 bg-slate-50/10 px-3 py-1 text-slate-600">
                协议专题
              </span>
              <span className="gshark-diffuse-chip border-slate-200/18 bg-slate-50/10 px-3 py-1 text-slate-600">
                结果可导出
              </span>
            </div>
          </div>
        </div>

        <div className="flex shrink-0 flex-col items-start gap-3 lg:items-end">
          <div className="max-w-[340px] text-xs leading-6 text-slate-500 lg:text-right">
            将低频但高价值的协议辅助能力按模块编排，内置 WinRM 与 SMB3，同时为自定义模块提供稳定接入位。
          </div>
          <input ref={fileInputRef} type="file" accept=".zip" className="hidden" onChange={handleImportModule} />
          <Button
            type="button"
            onClick={() => fileInputRef.current?.click()}
            disabled={importing}
            className="h-9 rounded-sm bg-cyan-600 px-4 text-xs font-semibold text-white hover:bg-cyan-700"
          >
            <Upload className="mr-2 h-4 w-4" />
            {importing ? "导入中..." : "导入模块 ZIP"}
          </Button>
        </div>
      </div>
    </section>
  );
}

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
    <section className="rounded-[28px] border border-white/70 bg-white/72 px-6 py-6 shadow-[0_30px_80px_rgba(8,145,178,0.16)] backdrop-blur-xl sm:px-8 lg:px-10">
      <div className="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">
        <div className="min-w-0 flex-1 space-y-4">
          <div className="flex flex-wrap items-center gap-4">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-cyan-100 text-cyan-700 shadow-sm">
                <Wrench className="h-4.5 w-4.5" />
              </div>
              <div className="min-w-0">
                <div className="flex flex-wrap items-baseline gap-2">
                  <h1 className="text-[19px] font-bold tracking-tight text-slate-900 sm:text-[22px]">MISC 工具箱</h1>
                  <span className="text-[11px] font-semibold uppercase tracking-[0.32em] text-slate-400">
                    SPECIALIZED TRAFFIC UTILITIES
                  </span>
                </div>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2 rounded-full border border-cyan-100/90 bg-cyan-50/60 px-3 py-2 text-xs text-slate-500 shadow-sm">
              <span className="font-semibold text-slate-600">模块层</span>
              {miscCategoryOptions.map((item) => {
                const active = activeCategory === item;
                return (
                  <button
                    key={item}
                    type="button"
                    onClick={() => onCategoryChange(item)}
                    className={cn(
                      "rounded-full border px-3 py-1 font-medium transition-all",
                      active
                        ? "border-cyan-200 bg-cyan-100 text-cyan-700 shadow-sm"
                        : "border-slate-200 bg-white/80 text-slate-500 hover:border-cyan-200 hover:text-cyan-700",
                    )}
                  >
                    {item}
                  </button>
                );
              })}
            </div>
          </div>

          <div className="grid gap-3 text-[13px] text-slate-500 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-end">
            <p className="max-w-2xl leading-7 text-slate-500">{heroDescription}</p>
            <div className="flex flex-wrap gap-2 text-[11px]">
              <span className="rounded-full border border-cyan-100 bg-cyan-50 px-3 py-1 text-cyan-700 shadow-sm">
                支持中断
              </span>
              <span className="rounded-full border border-slate-200 bg-white/80 px-3 py-1 text-slate-600 shadow-sm">
                协议专题
              </span>
              <span className="rounded-full border border-slate-200 bg-white/80 px-3 py-1 text-slate-600 shadow-sm">
                结果可导出
              </span>
            </div>
          </div>
        </div>

        <div className="flex shrink-0 flex-col items-start gap-3 lg:items-end">
          <div className="max-w-[360px] text-sm leading-7 text-slate-500 lg:text-right">
            将低频但高价值的协议辅助能力按模块编排，内置 WinRM 与 SMB3，同时为自定义模块提供稳定接入位。
          </div>
          <input ref={fileInputRef} type="file" accept=".zip" className="hidden" onChange={handleImportModule} />
          <Button
            type="button"
            onClick={() => fileInputRef.current?.click()}
            disabled={importing}
            className="h-11 rounded-full bg-cyan-600 px-5 text-sm font-semibold text-white shadow-[0_18px_36px_rgba(8,145,178,0.22)] hover:bg-cyan-700"
          >
            <Upload className="mr-2 h-4 w-4" />
            {importing ? "导入中..." : "导入模块 ZIP"}
          </Button>
        </div>
      </div>
    </section>
  );
}

import { Wrench } from "lucide-react";
import { useEffect, useRef, useState, type ChangeEvent } from "react";
import { AnalysisHero } from "../components/AnalysisHero";
import { PageShell } from "../components/PageShell";
import { Button } from "../components/ui/button";
import { bridge } from "../integrations/wailsBridge";
import type { MiscModuleManifest } from "../core/types";
import { resolveMiscModuleRenderer } from "../misc/registry";
import { ErrorBlock } from "../misc/ui";

export default function MiscTools() {
  const [modules, setModules] = useState<MiscModuleManifest[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [importing, setImporting] = useState(false);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  async function loadModules(isCancelled: () => boolean = () => false) {
    setLoading(true);
    setError("");
    try {
      const rows = await bridge.listMiscModules();
      if (isCancelled()) return;
      setModules(rows);
    } catch (loadError) {
      if (isCancelled()) return;
      setModules([]);
      setError(loadError instanceof Error ? loadError.message : "加载 MISC 模块失败");
    } finally {
      if (!isCancelled()) {
        setLoading(false);
      }
    }
  }

  useEffect(() => {
    let cancelled = false;
    void loadModules(() => cancelled);
    return () => {
      cancelled = true;
    };
  }, []);

  async function handleImportModule(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) {
      return;
    }
    setImporting(true);
    setError("");
    try {
      await bridge.importMiscModulePackage(file);
      await loadModules();
    } catch (importError) {
      setError(importError instanceof Error ? importError.message : "导入模块包失败");
    } finally {
      setImporting(false);
    }
  }

  async function handleModuleDeleted() {
    await loadModules();
  }

  return (
    <PageShell>
      <AnalysisHero
        icon={<Wrench className="h-5 w-5" />}
        title="MISC 工具箱"
        subtitle="SPECIALIZED TRAFFIC UTILITIES"
        description="将低频但高价值的协议辅助能力按模块编排，内置 WinRM 与 SMB3，同时为自定义模块预留稳定接入位。"
        tags={["Misc", "Modules", "WinRM", "SMB3"]}
        tagsLabel="模块层"
        theme="cyan"
      />

      <div className="mb-4 flex items-center justify-end">
        <input ref={fileInputRef} type="file" accept=".zip" className="hidden" onChange={(event) => void handleImportModule(event)} />
        <Button type="button" variant="outline" onClick={() => fileInputRef.current?.click()} disabled={importing}>
          {importing ? "导入中..." : "导入模块 ZIP"}
        </Button>
      </div>

      {error && <ErrorBlock message={error} />}
      {loading ? (
        <div className="rounded-xl border border-slate-200 bg-white px-4 py-10 text-center text-sm font-medium text-slate-500 shadow-sm">
          正在加载 MISC 模块...
        </div>
      ) : (
        <div className="grid min-w-0 gap-6 xl:grid-cols-2">
          {modules.map((module) => {
            const Renderer = resolveMiscModuleRenderer(module.id);
            return (
              <div key={module.id} className="xl:col-span-1">
                <Renderer module={module} onModuleDeleted={handleModuleDeleted} />
              </div>
            );
          })}
          {modules.length === 0 && !error && (
            <div className="rounded-xl border border-dashed border-slate-200 bg-white px-4 py-10 text-center text-sm text-slate-500 shadow-sm xl:col-span-2">
              当前没有可展示的 MISC 模块。
            </div>
          )}
        </div>
      )}
    </PageShell>
  );
}

import { useEffect, useState } from "react";
import type { MiscModuleManifest } from "../core/types";
import { bridge } from "../integrations/wailsBridge";
import { MiscToolsShell, type MiscCategory } from "../misc/MiscToolsShell";

export default function MiscTools() {
  const [modules, setModules] = useState<MiscModuleManifest[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [importing, setImporting] = useState(false);
  const [activeCategory, setActiveCategory] = useState<MiscCategory>("Misc");
  const [expandedModules, setExpandedModules] = useState<Record<string, boolean>>({});
  const [mountedModules, setMountedModules] = useState<Record<string, boolean>>({});

  async function loadModules(isCancelled: () => boolean = () => false) {
    setLoading(true);
    setError("");
    try {
      const rows = await bridge.listMiscModules();
      if (isCancelled()) return;
      setModules(rows);
      setExpandedModules((current) => {
        const next = { ...current };
        for (const module of rows) {
          if (next[module.id] === undefined) {
            next[module.id] = module.id === rows[0]?.id;
          }
        }
        return next;
      });
      setMountedModules((current) => {
        const next: Record<string, boolean> = {};
        for (const module of rows) {
          if (current[module.id] || module.id === rows[0]?.id) {
            next[module.id] = true;
          }
        }
        return next;
      });
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

  async function handleImportModule(file: File) {
    setImporting(true);
    setError("");
    try {
      await bridge.importMiscModulePackage(file);
      await loadModules();
      setActiveCategory("Misc");
    } catch (importError) {
      setError(importError instanceof Error ? importError.message : "导入模块包失败");
    } finally {
      setImporting(false);
    }
  }

  async function handleModuleDeleted() {
    await loadModules();
  }

  function toggleModule(moduleID: string) {
    setMountedModules((current) => ({
      ...current,
      [moduleID]: true,
    }));
    setExpandedModules((current) => ({
      ...current,
      [moduleID]: !current[moduleID],
    }));
  }

  return (
    <MiscToolsShell
      modules={modules}
      loading={loading}
      error={error}
      importing={importing}
      activeCategory={activeCategory}
      expandedModules={expandedModules}
      mountedModules={mountedModules}
      onCategoryChange={setActiveCategory}
      onImportModule={handleImportModule}
      onModuleDeleted={handleModuleDeleted}
      onToggleModule={toggleModule}
    />
  );
}

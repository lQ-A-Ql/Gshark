import { useCallback, useEffect, useState } from "react";
import type { MiscModuleManifest } from "../core/types";
import { backendClients } from "../integrations/backendClients";
import type { MiscCategory } from "./MiscToolsShell";

interface MiscToolsCatalogClient {
  listMiscModules(): Promise<MiscModuleManifest[]>;
  importMiscModulePackage(file: File): Promise<unknown>;
}

export interface UseMiscToolsCatalogOptions {
  miscModuleClient?: MiscToolsCatalogClient;
}

export function useMiscToolsCatalog({
  miscModuleClient = backendClients.miscModule,
}: UseMiscToolsCatalogOptions = {}) {
  const [modules, setModules] = useState<MiscModuleManifest[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [importing, setImporting] = useState(false);
  const [activeCategory, setActiveCategory] = useState<MiscCategory>("Misc");
  const [expandedModules, setExpandedModules] = useState<Record<string, boolean>>({});
  const [mountedModules, setMountedModules] = useState<Record<string, boolean>>({});

  const loadModules = useCallback(
    async (isCancelled: () => boolean = () => false) => {
      setLoading(true);
      setError("");
      try {
        const rows = await miscModuleClient.listMiscModules();
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
    },
    [miscModuleClient],
  );

  useEffect(() => {
    let cancelled = false;
    void loadModules(() => cancelled);
    return () => {
      cancelled = true;
    };
  }, [loadModules]);

  const importModule = useCallback(
    async (file: File) => {
      setImporting(true);
      setError("");
      try {
        await miscModuleClient.importMiscModulePackage(file);
        await loadModules();
        setActiveCategory("Misc");
      } catch (importError) {
        setError(importError instanceof Error ? importError.message : "导入模块包失败");
      } finally {
        setImporting(false);
      }
    },
    [loadModules, miscModuleClient],
  );

  const moduleDeleted = useCallback(async () => {
    await loadModules();
  }, [loadModules]);

  const toggleModule = useCallback((moduleID: string) => {
    setMountedModules((current) => ({
      ...current,
      [moduleID]: true,
    }));
    setExpandedModules((current) => ({
      ...current,
      [moduleID]: !current[moduleID],
    }));
  }, []);

  return {
    modules,
    loading,
    error,
    importing,
    activeCategory,
    expandedModules,
    mountedModules,
    setActiveCategory,
    importModule,
    moduleDeleted,
    toggleModule,
  };
}

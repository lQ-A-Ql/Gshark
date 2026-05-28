import { useCallback, useEffect, useRef, useState } from "react";
import type { PluginItem } from "../../core/types";
import { backendClients } from "../../integrations/backendClients";
import type { PluginSource } from "../../integrations/mappers/pluginSourceMapper";

export interface UsePluginManagerOptions {
  pluginClient?: typeof backendClients.plugin;
}

export function usePluginManager({ pluginClient = backendClients.plugin }: UsePluginManagerOptions = {}) {
  const [plugins, setPlugins] = useState<PluginItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [sourcePlugin, setSourcePlugin] = useState<PluginSource | null>(null);
  const [sourceLoading, setSourceLoading] = useState(false);
  const mountedRef = useRef(true);
  const pendingOpsRef = useRef(0);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  const refreshPlugins = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const items = await pluginClient.listPlugins();
      if (mountedRef.current) {
        setPlugins(items);
      }
    } catch (err) {
      if (mountedRef.current) {
        setError(err instanceof Error ? err.message : "插件列表加载失败");
      }
    } finally {
      if (mountedRef.current) {
        setLoading(false);
      }
    }
  }, [pluginClient]);

  useEffect(() => {
    void refreshPlugins();
  }, [refreshPlugins]);

  const withOp = useCallback(
    async <T,>(fn: () => Promise<T>): Promise<T> => {
      pendingOpsRef.current++;
      try {
        return await fn();
      } finally {
        pendingOpsRef.current--;
        if (pendingOpsRef.current === 0 && mountedRef.current) {
          await refreshPlugins();
        }
      }
    },
    [refreshPlugins],
  );

  const addPlugin = useCallback(
    async (input: { name: string; entry: string; version?: string; author?: string; tag?: string }) => {
      setError("");
      try {
        await withOp(() =>
          pluginClient.addPlugin({
            id: "",
            name: input.name,
            entry: input.entry,
            version: input.version ?? "1.0.0",
            author: input.author ?? "",
            tag: input.tag ?? "",
            enabled: true,
          }),
        );
      } catch (err) {
        const msg = err instanceof Error ? err.message : "添加插件失败";
        if (mountedRef.current) setError(msg);
        throw err;
      }
    },
    [pluginClient, withOp],
  );

  const deletePlugin = useCallback(
    async (id: string) => {
      setError("");
      try {
        await withOp(() => pluginClient.deletePlugin(id));
      } catch (err) {
        const msg = err instanceof Error ? err.message : "删除插件失败";
        if (mountedRef.current) setError(msg);
        throw err;
      }
    },
    [pluginClient, withOp],
  );

  const togglePlugin = useCallback(
    async (id: string) => {
      setError("");
      try {
        await withOp(() => pluginClient.togglePlugin(id));
      } catch (err) {
        const msg = err instanceof Error ? err.message : "切换插件状态失败";
        if (mountedRef.current) setError(msg);
        throw err;
      }
    },
    [pluginClient, withOp],
  );

  const bulkToggle = useCallback(
    async (ids: string[], enabled: boolean) => {
      setError("");
      try {
        await withOp(() => pluginClient.setPluginsEnabled(ids, enabled));
      } catch (err) {
        const msg = err instanceof Error ? err.message : "批量操作失败";
        if (mountedRef.current) setError(msg);
        throw err;
      }
    },
    [pluginClient, withOp],
  );

  const openSource = useCallback(
    async (id: string) => {
      if (mountedRef.current) setSourceLoading(true);
      setError("");
      try {
        const source = await pluginClient.getPluginSource(id);
        if (mountedRef.current) {
          setSourcePlugin(source);
        }
      } catch (err) {
        if (mountedRef.current) {
          setError(err instanceof Error ? err.message : "加载插件源码失败");
        }
      } finally {
        if (mountedRef.current) {
          setSourceLoading(false);
        }
      }
    },
    [pluginClient],
  );

  const saveSource = useCallback(
    async (source: PluginSource) => {
      if (mountedRef.current) setSourceLoading(true);
      setError("");
      try {
        await pluginClient.savePluginSource(source);
        if (mountedRef.current) {
          setSourcePlugin(null);
        }
        await refreshPlugins();
      } catch (err) {
        const msg = err instanceof Error ? err.message : "保存插件源码失败";
        if (mountedRef.current) setError(msg);
        throw err;
      } finally {
        if (mountedRef.current) {
          setSourceLoading(false);
        }
      }
    },
    [pluginClient, refreshPlugins],
  );

  const closeSource = useCallback(() => {
    setSourcePlugin(null);
  }, []);

  return {
    plugins,
    loading,
    error,
    sourcePlugin,
    sourceLoading,
    refreshPlugins,
    addPlugin,
    deletePlugin,
    togglePlugin,
    bulkToggle,
    openSource,
    saveSource,
    closeSource,
  };
}

import { useCallback, useEffect, useState } from "react";
import type { ExtractedObject } from "../../core/types";
import { backendClients } from "../../integrations/backendClients";

interface ObjectExportClient {
  listObjects(): Promise<ExtractedObject[]>;
  downloadObjectsZip(ids: number[]): Promise<void>;
}

export interface UseObjectExportOptions {
  backendConnected: boolean;
  extractedObjects: ExtractedObject[];
  objectClient?: ObjectExportClient;
}

export function useObjectExport({
  backendConnected,
  extractedObjects,
  objectClient = backendClients.object,
}: UseObjectExportOptions) {
  const [fallbackObjects, setFallbackObjects] = useState<ExtractedObject[] | null>(null);
  const [error, setError] = useState("");

  const refreshObjects = useCallback(() => {
    if (!backendConnected) {
      setFallbackObjects(null);
      return;
    }
    if (extractedObjects.length > 0) {
      setFallbackObjects(null);
      return;
    }

    let cancelled = false;
    void objectClient
      .listObjects()
      .then((rows) => {
        if (!cancelled) {
          setFallbackObjects(rows.length > 0 ? rows : null);
          setError("");
        }
      })
      .catch((err) => {
        if (!cancelled) {
          setFallbackObjects(null);
          setError(err instanceof Error ? err.message : "对象列表加载失败");
        }
      });

    return () => {
      cancelled = true;
    };
  }, [backendConnected, extractedObjects, objectClient]);

  useEffect(() => {
    return refreshObjects();
  }, [refreshObjects]);

  const downloadZip = useCallback(
    async (ids: number[]) => {
      if (ids.length === 0) return false;
      try {
        await objectClient.downloadObjectsZip(ids);
        return true;
      } catch (err) {
        console.error("下载失败:", err);
        return false;
      }
    },
    [objectClient],
  );

  const sourceObjects = extractedObjects.length > 0 ? extractedObjects : (fallbackObjects ?? []);

  return { objects: sourceObjects, error, refreshObjects, downloadZip };
}

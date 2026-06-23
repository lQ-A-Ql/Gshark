import { useCallback, useEffect, useRef, useState } from "react";
import type { ExtractedObject } from "../../core/types";
import { useAbortableRequest } from "../../hooks/useAbortableRequest";
import { backendClients } from "../../integrations/backendClients";

interface ObjectExportClient {
  listObjects(signal?: AbortSignal): Promise<ExtractedObject[]>;
  downloadObjectsZip(ids: number[], signal?: AbortSignal): Promise<void>;
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
  const { run: runObjectRequest, cancel: cancelObjectRequest } = useAbortableRequest();
  const { run: runDownloadRequest } = useAbortableRequest();
  const resolveDownloadRef = useRef<((value: boolean) => void) | null>(null);

  const refreshObjects = useCallback(() => {
    if (!backendConnected) {
      cancelObjectRequest();
      setFallbackObjects(null);
      return;
    }
    if (extractedObjects.length > 0) {
      cancelObjectRequest();
      setFallbackObjects(null);
      return;
    }

    return runObjectRequest({
      request: (signal) => objectClient.listObjects(signal),
      onSuccess: (rows) => {
        setFallbackObjects(rows.length > 0 ? rows : null);
        setError("");
      },
      onError: (err) => {
        setFallbackObjects(null);
        setError(err instanceof Error ? err.message : "对象列表加载失败");
      },
    });
  }, [backendConnected, cancelObjectRequest, extractedObjects.length, objectClient, runObjectRequest]);

  useEffect(() => {
    return refreshObjects();
  }, [refreshObjects]);

  const downloadZip = useCallback(
    async (ids: number[]) => {
      if (ids.length === 0) return false;
      resolveDownloadRef.current?.(false);
      return new Promise<boolean>((resolve) => {
        resolveDownloadRef.current = resolve;
        runDownloadRequest({
          request: (signal) => objectClient.downloadObjectsZip(ids, signal).then(() => true),
          onSuccess: () => {
            resolveDownloadRef.current = null;
            resolve(true);
          },
          onError: (err) => {
            console.error("下载失败:", err);
            resolveDownloadRef.current = null;
            resolve(false);
          },
          onSettled: () => {
            resolveDownloadRef.current = null;
          },
        });
      });
    },
    [objectClient, runDownloadRequest],
  );

  useEffect(
    () => () => {
      resolveDownloadRef.current?.(false);
      resolveDownloadRef.current = null;
    },
    [],
  );

  const sourceObjects = extractedObjects.length > 0 ? extractedObjects : (fallbackObjects ?? []);

  return { objects: sourceObjects, error, refreshObjects, downloadZip };
}

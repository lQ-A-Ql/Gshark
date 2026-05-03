import { useCallback, useEffect, useState } from "react";
import type { ExtractedObject } from "../../core/types";
import { bridge } from "../../integrations/wailsBridge";

export interface UseObjectExportOptions {
  backendConnected: boolean;
  extractedObjects: ExtractedObject[];
}

export function useObjectExport({ backendConnected, extractedObjects }: UseObjectExportOptions) {
  const [fallbackObjects, setFallbackObjects] = useState<ExtractedObject[] | null>(null);

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
    void bridge
      .listObjects()
      .then((rows) => {
        if (!cancelled) {
          setFallbackObjects(rows.length > 0 ? rows : null);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setFallbackObjects(null);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [backendConnected, extractedObjects]);

  useEffect(() => {
    return refreshObjects();
  }, [refreshObjects]);

  const sourceObjects = extractedObjects.length > 0 ? extractedObjects : (fallbackObjects ?? []);

  return { objects: sourceObjects, refreshObjects };
}

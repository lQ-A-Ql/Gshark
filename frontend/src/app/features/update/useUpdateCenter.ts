import { useCallback, useEffect, useState } from "react";
import type { AppUpdateStatus } from "../../core/types";
import { backendClients } from "../../integrations/backendClients";

interface UpdateRuntimeClient {
  checkAppUpdate(): Promise<AppUpdateStatus>;
  installAppUpdate(): Promise<void>;
}

export interface UpdateCenterState {
  status: AppUpdateStatus | null;
  loading: boolean;
  installing: boolean;
  error: string;
  installProgress: number;
  notes: string;
  refreshStatus: () => Promise<void>;
  installUpdate: () => Promise<void>;
}

export function useUpdateCenter(runtimeClient: UpdateRuntimeClient = backendClients.runtime): UpdateCenterState {
  const [status, setStatus] = useState<AppUpdateStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [installing, setInstalling] = useState(false);
  const [error, setError] = useState("");
  const [installProgress, setInstallProgress] = useState(0);

  const refreshStatus = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const next = await runtimeClient.checkAppUpdate();
      setStatus(next);
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : "检查更新失败");
    } finally {
      setLoading(false);
    }
  }, [runtimeClient]);

  const installUpdate = useCallback(async () => {
    setInstalling(true);
    setError("");
    setInstallProgress(12);
    try {
      await runtimeClient.installAppUpdate();
      setInstallProgress(100);
    } catch (nextError) {
      setInstalling(false);
      setInstallProgress(0);
      setError(nextError instanceof Error ? nextError.message : "启动更新失败");
      await refreshStatus();
    }
  }, [refreshStatus, runtimeClient]);

  useEffect(() => {
    void refreshStatus();
  }, [refreshStatus]);

  useEffect(() => {
    if (!installing) {
      return undefined;
    }
    const timer = window.setInterval(() => {
      setInstallProgress((prev) => {
        if (prev >= 92) {
          return prev;
        }
        return Math.min(92, prev + 6);
      });
    }, 420);
    return () => window.clearInterval(timer);
  }, [installing]);

  return {
    status,
    loading,
    installing,
    error,
    installProgress,
    notes: status?.releaseNotes?.trim() || "该版本没有附带 Release 说明。",
    refreshStatus,
    installUpdate,
  };
}

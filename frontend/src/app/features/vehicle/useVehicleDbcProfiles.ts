import { useCallback, useEffect, useState } from "react";
import type { DBCProfile } from "../../core/types";
import { backendClients } from "../../integrations/backendClients";

interface VehicleDBCClient {
  listVehicleDBCProfiles(): Promise<DBCProfile[]>;
  addVehicleDBC(path: string): Promise<DBCProfile[]>;
  removeVehicleDBC(path: string): Promise<DBCProfile[]>;
  openDBCFile(): Promise<{ filePath: string }>;
}

export interface UseVehicleDbcProfilesOptions {
  backendConnected: boolean;
  vehicleDBCClient?: VehicleDBCClient;
}

export function useVehicleDbcProfiles({
  backendConnected,
  vehicleDBCClient = backendClients.vehicleDBC,
}: UseVehicleDbcProfilesOptions) {
  const [profiles, setProfiles] = useState<DBCProfile[]>([]);
  const [pathInput, setPathInput] = useState("");
  const [error, setError] = useState("");

  const refreshProfiles = useCallback(() => {
    if (!backendConnected) {
      setProfiles([]);
      return;
    }
    void vehicleDBCClient
      .listVehicleDBCProfiles()
      .then((items) => setProfiles(items))
      .catch(() => setProfiles([]));
  }, [backendConnected, vehicleDBCClient]);

  const addPath = useCallback(
    async (path: string) => {
      const normalized = path.trim();
      if (!normalized) return false;
      try {
        const nextProfiles = await vehicleDBCClient.addVehicleDBC(normalized);
        setProfiles(nextProfiles);
        setPathInput("");
        setError("");
        return true;
      } catch (err) {
        setError(err instanceof Error ? err.message : "DBC 导入失败");
        return false;
      }
    },
    [vehicleDBCClient],
  );

  const removePath = useCallback(
    async (path: string) => {
      try {
        const nextProfiles = await vehicleDBCClient.removeVehicleDBC(path);
        setProfiles(nextProfiles);
        setError("");
        return true;
      } catch (err) {
        setError(err instanceof Error ? err.message : "DBC 移除失败");
        return false;
      }
    },
    [vehicleDBCClient],
  );

  const importFile = useCallback(() => {
    return vehicleDBCClient
      .openDBCFile()
      .then((file) => addPath(file.filePath))
      .catch((err) => {
        if (err instanceof Error && err.message !== "未选择 DBC 文件") {
          setError(err.message);
        }
        return false;
      });
  }, [addPath, vehicleDBCClient]);

  useEffect(() => {
    refreshProfiles();
  }, [refreshProfiles]);

  return {
    profiles,
    pathInput,
    error,
    refreshProfiles,
    setPathInput,
    addPath,
    removePath,
    importFile,
  };
}

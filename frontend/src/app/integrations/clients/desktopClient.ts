import type { AppUpdateStatus } from "../../core/types";
import type { OpenFileResult } from "./captureClient";

type JsonRequest = <T>(path: string, init?: RequestInit) => Promise<T>;

export interface DesktopAppBinding {
  BackendStatus?: () => Promise<string>;
  CheckAppUpdate?: () => Promise<AppUpdateStatus | null | undefined>;
  InstallAppUpdate?: () => Promise<void>;
  OpenDBCDialog?: () => Promise<OpenFileResult | null | undefined>;
}

type GetDesktopApp = () => DesktopAppBinding | undefined;

let lastBackendReadinessError = "";

export function getLastBackendReadinessError() {
  return lastBackendReadinessError;
}

export interface DesktopClient {
  isAvailable(): Promise<boolean>;
  getDesktopBackendStatus(): Promise<string>;
  checkAppUpdate(): Promise<AppUpdateStatus>;
  installAppUpdate(): Promise<void>;
  openDBCFile(): Promise<OpenFileResult>;
}

function asAppUpdateStatus(result: AppUpdateStatus): AppUpdateStatus {
  return {
    currentVersion: String(result.currentVersion ?? ""),
    currentVersionDisplay: String(result.currentVersionDisplay ?? ""),
    currentVersionSource: String(result.currentVersionSource ?? ""),
    currentExecutable: String(result.currentExecutable ?? ""),
    localHash: String(result.localHash ?? ""),
    repo: String(result.repo ?? ""),
    authMode: String(result.authMode ?? ""),
    checkedAt: String(result.checkedAt ?? ""),
    apiUrl: String(result.apiUrl ?? ""),
    hasUpdate: Boolean(result.hasUpdate),
    upToDate: Boolean(result.upToDate),
    hashMismatch: Boolean(result.hashMismatch),
    latestTag: String(result.latestTag ?? ""),
    latestName: String(result.latestName ?? ""),
    latestPublishedAt: String(result.latestPublishedAt ?? ""),
    releaseUrl: String(result.releaseUrl ?? ""),
    releaseNotes: String(result.releaseNotes ?? ""),
    selectedAsset: result.selectedAsset
      ? {
          name: String(result.selectedAsset.name ?? ""),
          downloadUrl: String(result.selectedAsset.downloadUrl ?? ""),
          sizeBytes: Number(result.selectedAsset.sizeBytes ?? 0),
          contentType: String(result.selectedAsset.contentType ?? "") || undefined,
        }
      : undefined,
    canInstall: Boolean(result.canInstall),
    message: String(result.message ?? ""),
  };
}

export function createDesktopClient(request: JsonRequest, getDesktopApp: GetDesktopApp): DesktopClient {
  return {
    async isAvailable() {
      const desktopApp = getDesktopApp();
      if (desktopApp?.BackendStatus) {
        try {
          const status = String(await desktopApp.BackendStatus())
            .trim()
            .toLowerCase();
          if (status && status !== "running" && status !== "running (reused-existing)" && status !== "starting") {
            return false;
          }
        } catch {
          // Ignore desktop status errors and fall through to HTTP health check.
        }
      }
      try {
        await request<{ status: string }>("/health");
        await request<unknown>("/api/runtime/identity");
        await request<unknown>("/api/capture/status");
        lastBackendReadinessError = "";
        return true;
      } catch (error) {
        lastBackendReadinessError = describeDataPlaneReadinessError(error);
        return false;
      }
    },

    async getDesktopBackendStatus() {
      const desktopApp = getDesktopApp();
      if (!desktopApp?.BackendStatus) {
        return "";
      }
      try {
        return String(await desktopApp.BackendStatus()).trim();
      } catch {
        return "";
      }
    },

    async checkAppUpdate() {
      const desktopApp = getDesktopApp();
      if (!desktopApp?.CheckAppUpdate) {
        throw new Error("当前环境不支持桌面端更新");
      }
      const result = await desktopApp.CheckAppUpdate();
      if (!result) {
        throw new Error("更新状态为空");
      }
      return asAppUpdateStatus(result);
    },

    async installAppUpdate() {
      const desktopApp = getDesktopApp();
      if (!desktopApp?.InstallAppUpdate) {
        throw new Error("当前环境不支持桌面端更新");
      }
      await desktopApp.InstallAppUpdate();
    },

    async openDBCFile() {
      const desktopApp = getDesktopApp();
      if (!desktopApp?.OpenDBCDialog) {
        throw new Error("当前环境不支持原生 DBC 文件选择");
      }
      const result = await desktopApp.OpenDBCDialog();
      if (!result?.filePath) {
        throw new Error("未选择 DBC 文件");
      }
      return {
        filePath: String(result.filePath),
        fileSize: Number(result.fileSize ?? 0),
        fileName: String(result.fileName ?? String(result.filePath).split(/[\\/]/).pop() ?? "database.dbc"),
      };
    },
  };
}

function describeDataPlaneReadinessError(error: unknown): string {
  if (error instanceof Error && error.message.trim()) {
    return `后端端口在线，但 HTTP 数据面不可用：${error.message}`;
  }
  return "后端端口在线，但 HTTP 数据面不可用：无法完成鉴权或状态探针。";
}

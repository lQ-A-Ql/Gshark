import type { AppUpdateStatus } from "../core/types";
import type { OpenFileResult } from "./clients/captureClient";

export interface DesktopTransportBinding {
  BackendStatus?: () => Promise<string>;
  GetBackendAuthToken?: () => Promise<string | null | undefined>;
  CheckAppUpdate?: () => Promise<AppUpdateStatus | null | undefined>;
  InstallAppUpdate?: () => Promise<void>;
  OpenDBCDialog?: () => Promise<OpenFileResult | null | undefined>;
  OpenCaptureDialog?: () => Promise<OpenFileResult | null | undefined>;
  IsBackendReady?: () => Promise<boolean>;
  GetToolRuntimeSnapshot?: () => Promise<unknown>;
  GetToolRuntimeSnapshotFast?: () => Promise<unknown>;
  GetToolRuntimeSnapshotFull?: () => Promise<unknown>;
  UpdateToolRuntimeConfig?: (config: unknown) => Promise<unknown>;
  UpdateToolRuntimeConfigFast?: (config: unknown) => Promise<unknown>;
  UpdateToolRuntimeConfigFull?: (config: unknown) => Promise<unknown>;
  SetTSharkPath?: (path: string) => Promise<unknown>;
  StartCapture?: (filePath: string, filter: string) => Promise<void>;
  StopCapture?: () => Promise<void>;
  PrepareCaptureReplacement?: () => Promise<void>;
  CloseCapture?: () => Promise<void>;
  GetCaptureStatus?: () => Promise<unknown>;
  ListPacketsPage?: (cursor: number, limit: number, filter: string) => Promise<unknown>;
  GetTLSConfig?: () => Promise<unknown>;
  UpdateTLSConfig?: (cfg: unknown) => Promise<void>;
}

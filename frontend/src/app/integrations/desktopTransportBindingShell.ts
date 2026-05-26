import type { AppUpdateStatus } from "../core/types";
import type { OpenFileResult } from "./clients/captureClient";

export interface DesktopShellBinding {
  GetDesktopWebviewSmokeConfig?: () => Promise<unknown>;
  WriteDesktopWebviewSmokeResult?: (payload: unknown) => Promise<void>;
  BackendStatus?: () => Promise<string>;
  GetBackendAuthToken?: () => Promise<string | null | undefined>;
  CheckAppUpdate?: () => Promise<AppUpdateStatus | null | undefined>;
  InstallAppUpdate?: () => Promise<void>;
  OpenDBCDialog?: () => Promise<OpenFileResult | null | undefined>;
  OpenCaptureDialog?: () => Promise<OpenFileResult | null | undefined>;
  SelectMiscModulePackage?: () => Promise<OpenFileResult | null | undefined>;
  IsBackendReady?: () => Promise<boolean>;
  PingBackendDataPlane?: () => Promise<unknown>;
  InvokeBackendJSON?: (request: unknown) => Promise<unknown>;
  InvokeBackendBlob?: (request: unknown) => Promise<unknown>;
  InvokeBackendText?: (request: unknown) => Promise<string>;
}

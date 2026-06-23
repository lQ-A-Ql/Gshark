export interface DesktopControlPlaneBinding {
  GetToolRuntimeSnapshot?: () => Promise<unknown>;
  GetToolRuntimeSnapshotFast?: () => Promise<unknown>;
  GetToolRuntimeSnapshotFull?: () => Promise<unknown>;
  UpdateToolRuntimeConfig?: (config: unknown) => Promise<unknown>;
  UpdateToolRuntimeConfigFast?: (config: unknown) => Promise<unknown>;
  UpdateToolRuntimeConfigFull?: (config: unknown) => Promise<unknown>;
  GetMCPStatus?: () => Promise<unknown>;
  UpdateMCPConfig?: (config: unknown) => Promise<unknown>;
  SetTSharkPath?: (path: string) => Promise<unknown>;
  AllowTSharkDir?: (dir: string) => Promise<unknown>;
  ListTSharkAllowedDirs?: () => Promise<unknown>;
  RemoveTSharkAllowedDir?: (dir: string) => Promise<unknown>;
  AllowToolDir?: (tool: string, dir: string) => Promise<unknown>;
  ListToolAllowedDirs?: (tool: string) => Promise<unknown>;
  RemoveToolAllowedDir?: (tool: string, dir: string) => Promise<unknown>;
  StartCapture?: (filePath: string, filter: string) => Promise<void>;
  StopCapture?: () => Promise<void>;
  PrepareCaptureReplacement?: () => Promise<void>;
  CloseCapture?: () => Promise<void>;
  GetCaptureStatus?: () => Promise<unknown>;
  GetTLSConfig?: () => Promise<unknown>;
  UpdateTLSConfig?: (cfg: unknown) => Promise<void>;
}

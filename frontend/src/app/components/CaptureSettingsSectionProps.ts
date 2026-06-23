import type { TSharkStatus } from "../integrations/clients/toolRuntimeClient";
import type { RuntimeSettingsSectionProps } from "./RuntimeSettingsSectionTypes";

export type CaptureSettingsSectionProps = RuntimeSettingsSectionProps & {
  allowTSharkDir?: (dir: string) => Promise<TSharkStatus>;
  removeTSharkAllowedDir?: (dir: string) => Promise<unknown>;
  refreshTSharkAllowedDirs?: () => Promise<unknown>;
};

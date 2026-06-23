import type { RuntimeSettingsSectionProps, RuntimeToolAllowedDirsField } from "./RuntimeSettingsSectionTypes";
import { ToolPathAllowWarning } from "./TSharkPathAllowWarning";

type ToolWarningStatus = { path?: string; customPath?: string; pathWarning?: string };

type Props = ToolWarningStatus & {
  status?: ToolWarningStatus | null;
  field: RuntimeToolAllowedDirsField;
  allowToolDir?: RuntimeSettingsSectionProps["allowToolDir"];
};

export function RuntimeToolPathAllowWarning({ status, field, allowToolDir, ...fallback }: Props) {
  const allowDir = allowToolDir ? (dir: string) => allowToolDir(field, dir) : undefined;
  return <ToolPathAllowWarning status={status ?? fallback} allowDir={allowDir} />;
}

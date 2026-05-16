import { StatusLine } from "./RuntimeSettingsSidebarParts";

type RuntimeToolStatus = {
  available?: boolean;
  message?: string;
  path?: string;
};

export function RuntimeToolStatusLine({
  label,
  status,
  known,
  unknownMessage,
  unknownStateText,
  enabled,
  degraded,
}: {
  label: string;
  status?: RuntimeToolStatus;
  known: boolean;
  unknownMessage?: string;
  unknownStateText?: string;
  enabled?: boolean;
  degraded?: boolean;
}) {
  return (
    <StatusLine
      label={label}
      available={status?.available}
      enabled={enabled}
      known={known}
      degraded={degraded}
      message={status?.message ?? unknownMessage ?? "等待检测"}
      unknownStateText={unknownStateText}
      path={status?.path}
    />
  );
}

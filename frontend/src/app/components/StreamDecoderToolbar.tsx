import { Binary, Bug, Search, ShieldAlert, Wand2 } from "lucide-react";
import type { StreamDecoderKind } from "../core/types";
import { DecoderButton, SettingsButton } from "./StreamDecoderWorkbenchParts";
import type { DecoderSettingsKind } from "./StreamDecoderSettingsPanel";

export function StreamDecoderToolbar({
  runningDecoder,
  disabled,
  onRunDecoder,
  onOpenSettings,
  onCancel,
}: {
  runningDecoder: StreamDecoderKind | null;
  disabled: boolean;
  onRunDecoder: (decoder: StreamDecoderKind) => void;
  onOpenSettings: (settings: DecoderSettingsKind) => void;
  onCancel: () => void;
}) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      <DecoderButton
        icon={Search}
        label="自动检测"
        active={runningDecoder === "auto"}
        disabled={disabled}
        onClick={() => onRunDecoder("auto")}
      />
      <DecoderButton
        icon={Binary}
        label="Base64"
        active={runningDecoder === "base64"}
        disabled={disabled}
        onClick={() => onRunDecoder("base64")}
      />
      <DecoderButton
        icon={ShieldAlert}
        label="Behinder"
        active={runningDecoder === "behinder"}
        disabled={disabled}
        onClick={() => onRunDecoder("behinder")}
      />
      <SettingsButton onClick={() => onOpenSettings("behinder")} />
      <DecoderButton
        icon={Bug}
        label="AntSword"
        active={runningDecoder === "antsword"}
        disabled={disabled}
        onClick={() => onRunDecoder("antsword")}
      />
      <SettingsButton onClick={() => onOpenSettings("antsword")} />
      <DecoderButton
        icon={Wand2}
        label="Godzilla"
        active={runningDecoder === "godzilla"}
        disabled={disabled}
        onClick={() => onRunDecoder("godzilla")}
      />
      <SettingsButton onClick={() => onOpenSettings("godzilla")} />
      {runningDecoder && (
        <button
          type="button"
          onClick={onCancel}
          className="inline-flex items-center gap-2 rounded-lg border border-rose-200 bg-rose-50 px-3 py-2 text-xs font-semibold text-rose-700 shadow-sm transition-colors hover:bg-rose-100"
        >
          取消
        </button>
      )}
    </div>
  );
}

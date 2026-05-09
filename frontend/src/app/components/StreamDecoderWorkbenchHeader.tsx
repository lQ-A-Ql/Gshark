import type { StreamDecoderKind } from "../core/types";
import { StreamDecoderToolbar } from "./StreamDecoderToolbar";
import type { DecoderSettingsKind } from "./StreamDecoderSettingsPanel";

export function StreamDecoderWorkbenchHeader({
  chunkLabel,
  runningDecoder,
  disabled,
  onRunDecoder,
  onOpenSettings,
  onCancel,
}: {
  chunkLabel: string;
  runningDecoder: StreamDecoderKind | null;
  disabled: boolean;
  onRunDecoder: (decoder: StreamDecoderKind) => void;
  onOpenSettings: (settings: DecoderSettingsKind) => void;
  onCancel: () => void;
}) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3">
      <div>
        <div className="text-sm font-semibold text-foreground">Payload 解码工作台</div>
        <div className="text-xs text-muted-foreground">{chunkLabel}</div>
      </div>
      <StreamDecoderToolbar
        runningDecoder={runningDecoder}
        disabled={disabled}
        onRunDecoder={onRunDecoder}
        onOpenSettings={onOpenSettings}
        onCancel={onCancel}
      />
    </div>
  );
}

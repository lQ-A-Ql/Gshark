import type { ThreatHit } from "../../core/types";
export { ThreatHuntingCategoryPanel, ThreatHuntingProgressPanel } from "./ThreatHuntingSummaryPanels";
import {
  ThreatHuntingConfigPanel,
  ThreatHuntingHitDetailPanel,
  ThreatHuntingHitsTable,
} from "./ThreatHuntingWorkbenchSections";

export interface ThreatHuntingStats {
  ctf: number;
  owasp: number;
  anomaly: number;
}

export interface ThreatHuntingProgressView {
  title: string;
  detail: string;
  value: number;
  phaseLabel: string;
  current: number;
  total: number;
}

interface ThreatHuntingWorkbenchPanelProps {
  actionBusy: string;
  backendConnected: boolean;
  configBusy: boolean;
  hits: ThreatHit[];
  huntBusy: boolean;
  prefixText: string;
  selected: ThreatHit | null;
  selectedHit: number | null;
  statusText: string;
  yaraBin: string;
  yaraEnabled: boolean;
  yaraRules: string;
  yaraTimeoutMs: number;
  onApplyConfigAndRun: () => void | Promise<void>;
  onJumpToPacket: (packetId: number) => void | Promise<void>;
  onLoadConfig: () => void | Promise<void>;
  onOpenRelatedStream: (packetId: number) => void | Promise<void>;
  onPrefixTextChange: (value: string) => void;
  onRunWithoutSave: () => void | Promise<void>;
  onSelectHit: (id: number) => void;
  onYaraBinChange: (value: string) => void;
  onYaraEnabledChange: (value: boolean) => void;
  onYaraRulesChange: (value: string) => void;
  onYaraTimeoutMsChange: (value: number) => void;
}

export function ThreatHuntingWorkbenchPanel({
  actionBusy,
  backendConnected,
  configBusy,
  hits,
  huntBusy,
  prefixText,
  selected,
  selectedHit,
  statusText,
  yaraBin,
  yaraEnabled,
  yaraRules,
  yaraTimeoutMs,
  onApplyConfigAndRun,
  onJumpToPacket,
  onLoadConfig,
  onOpenRelatedStream,
  onPrefixTextChange,
  onRunWithoutSave,
  onSelectHit,
  onYaraBinChange,
  onYaraEnabledChange,
  onYaraRulesChange,
  onYaraTimeoutMsChange,
}: ThreatHuntingWorkbenchPanelProps) {
  return (
    <div className="flex min-h-0 min-w-0 flex-1 flex-col overflow-hidden rounded-[28px] border border-slate-200 bg-white/92 shadow-[0_24px_80px_-48px_rgba(15,23,42,0.45)] backdrop-blur">
      <ThreatHuntingConfigPanel
        backendConnected={backendConnected}
        configBusy={configBusy}
        huntBusy={huntBusy}
        prefixText={prefixText}
        statusText={statusText}
        yaraBin={yaraBin}
        yaraEnabled={yaraEnabled}
        yaraRules={yaraRules}
        yaraTimeoutMs={yaraTimeoutMs}
        onApplyConfigAndRun={onApplyConfigAndRun}
        onLoadConfig={onLoadConfig}
        onPrefixTextChange={onPrefixTextChange}
        onRunWithoutSave={onRunWithoutSave}
        onYaraBinChange={onYaraBinChange}
        onYaraEnabledChange={onYaraEnabledChange}
        onYaraRulesChange={onYaraRulesChange}
        onYaraTimeoutMsChange={onYaraTimeoutMsChange}
      />

      <div className="flex min-h-0 flex-1 flex-col">
        <ThreatHuntingHitsTable hits={hits} selectedHit={selectedHit} onSelectHit={onSelectHit} />
        {selected && (
          <ThreatHuntingHitDetailPanel
            actionBusy={actionBusy}
            selected={selected}
            onJumpToPacket={onJumpToPacket}
            onOpenRelatedStream={onOpenRelatedStream}
          />
        )}
      </div>
    </div>
  );
}

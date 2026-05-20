import { AlertTriangle, RefreshCw, Square } from "lucide-react";
import {
  describeCapturePreloadDiagnostics,
  type CapturePreloadDiagnostics,
} from "../../state/capturePreloadDiagnostics";

interface WorkspacePreloadProgressProps {
  preloadProcessed: number;
  preloadTotal: number;
  totalPackets: number;
  diagnostics: CapturePreloadDiagnostics | null;
  elapsedMs: number;
  onRetryConfirm: () => void;
  onStop: () => void;
}

export function WorkspacePreloadProgress({
  preloadProcessed,
  preloadTotal,
  totalPackets,
  diagnostics,
  elapsedMs,
  onRetryConfirm,
  onStop,
}: WorkspacePreloadProgressProps) {
  const hasDeterministicPreloadProgress = preloadTotal > 0;
  const preloadPercent = hasDeterministicPreloadProgress
    ? Math.max(0, Math.min(100, Math.floor((preloadProcessed / preloadTotal) * 100)))
    : 0;
  const diagnosticMessage = describeCapturePreloadDiagnostics(diagnostics);
  const showDiagnostics =
    elapsedMs >= 5000 ||
    diagnostics?.phase === "backend_parsing" ||
    diagnostics?.phase === "backend_committing" ||
    diagnostics?.phase === "backend_failed" ||
    diagnostics?.phase === "committed_empty" ||
    diagnostics?.phase === "status_failed" ||
    diagnostics?.phase === "path_mismatch";
  const showDetailedDiagnostics = elapsedMs >= 20000;
  return (
    <div className="gshark-tile-toolbar border-b border-blue-100 px-3 py-2">
      <div className="mb-1 flex items-center justify-between text-[11px] text-muted-foreground">
        <span>正在预加载全部流量</span>
        <span>
          {hasDeterministicPreloadProgress
            ? `${preloadProcessed.toLocaleString()} / ${Math.max(preloadTotal, totalPackets).toLocaleString()} (${preloadPercent}%)`
            : `已入库 ${Math.max(preloadProcessed, totalPackets).toLocaleString()} 包，正在继续解析...`}
        </span>
      </div>
      <div className="h-2 w-full overflow-hidden rounded bg-muted">
        {hasDeterministicPreloadProgress ? (
          <div className="h-full bg-blue-600 transition-all" style={{ width: `${preloadPercent}%` }} />
        ) : (
          <div className="h-full w-1/3 animate-pulse rounded bg-blue-600/80" />
        )}
      </div>
      {showDiagnostics && diagnostics && (
        <PreloadDiagnosticsPanel
          diagnostics={diagnostics}
          diagnosticMessage={diagnosticMessage}
          showDetailedDiagnostics={showDetailedDiagnostics}
          onRetryConfirm={onRetryConfirm}
          onStop={onStop}
        />
      )}
    </div>
  );
}

function PreloadDiagnosticsPanel({
  diagnostics,
  diagnosticMessage,
  showDetailedDiagnostics,
  onRetryConfirm,
  onStop,
}: {
  diagnostics: CapturePreloadDiagnostics;
  diagnosticMessage: string;
  showDetailedDiagnostics: boolean;
  onRetryConfirm: () => void;
  onStop: () => void;
}) {
  return (
    <div className="mt-2 rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-[11px] text-amber-900">
      <div className="flex items-start gap-2">
        <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
        <div className="min-w-0 flex-1">
          <div className="font-semibold">{diagnosticMessage || "后端已开始加载，正在确认数据页和抓包状态。"}</div>
          {showDetailedDiagnostics && <PreloadDiagnosticDetails diagnostics={diagnostics} />}
        </div>
        <PreloadDiagnosticActions onRetryConfirm={onRetryConfirm} onStop={onStop} />
      </div>
    </div>
  );
}

function PreloadDiagnosticDetails({ diagnostics }: { diagnostics: CapturePreloadDiagnostics }) {
  return (
    <div className="mt-1 space-y-0.5 font-mono text-[10px] text-amber-950/80">
      <div>
        phase={diagnostics.phase} pageTransport={diagnostics.pageTransport} statusTransport=
        {diagnostics.statusTransport}
      </div>
      <div>
        page={diagnostics.pageItems}/{diagnostics.pageTotal} statusPackets={diagnostics.statusPacketCount}
      </div>
      {diagnostics.loadPhase && (
        <div>
          load={diagnostics.loadPhase} profile={diagnostics.loadParserProfile || "-"} processed=
          {diagnostics.loadProcessed}/{diagnostics.loadEstimatedTotal || "-"} accepted={diagnostics.loadAccepted}{" "}
          staged=
          {diagnostics.loadStagedCount}
        </div>
      )}
      {diagnostics.enrichmentPhase && (
        <div>
          enrichment={diagnostics.enrichmentPhase} processed={diagnostics.enrichmentProcessed} updated=
          {diagnostics.enrichmentUpdated}
        </div>
      )}
      <div className="break-all">opened={diagnostics.openedPath || "-"}</div>
      <div className="break-all">status={diagnostics.statusPath || "-"}</div>
      {diagnostics.loadPath && <div className="break-all">load={diagnostics.loadPath}</div>}
      {diagnostics.loadLastError && <div className="break-all">loadError={diagnostics.loadLastError}</div>}
      {diagnostics.enrichmentLastError && (
        <div className="break-all">enrichmentError={diagnostics.enrichmentLastError}</div>
      )}
    </div>
  );
}

function PreloadDiagnosticActions({ onRetryConfirm, onStop }: { onRetryConfirm: () => void; onStop: () => void }) {
  return (
    <div className="flex shrink-0 gap-1">
      <button
        type="button"
        className="inline-flex h-7 items-center gap-1 rounded-sm border border-amber-300 bg-transparent px-2 font-semibold text-amber-900 transition hover:bg-amber-50/45"
        onClick={onRetryConfirm}
      >
        <RefreshCw className="h-3.5 w-3.5" />
        重新确认
      </button>
      <button
        type="button"
        className="inline-flex h-7 items-center gap-1 rounded-sm border border-slate-300 bg-transparent px-2 font-semibold text-slate-700 transition hover:bg-slate-50/45"
        onClick={onStop}
      >
        <Square className="h-3.5 w-3.5" />
        停止
      </button>
    </div>
  );
}

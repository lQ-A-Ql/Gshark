import { Button } from "../../components/ui/button";
import type { SMB3SessionCandidate } from "../../core/types";
import { ErrorBlock, Field } from "../ui";

interface SMB3SessionCandidateSelectorProps {
  candidates: SMB3SessionCandidate[];
  error: string;
  hasCapture: boolean;
  loading: boolean;
  onRefresh: () => void | Promise<void>;
  onSelectCandidate: (frameNumber: string) => void;
  selectedFrame: string;
  summary: string;
}

export function SMB3SessionCandidateSelector({
  candidates,
  error,
  hasCapture,
  loading,
  onRefresh,
  onSelectCandidate,
  selectedFrame,
  summary,
}: SMB3SessionCandidateSelectorProps) {
  return (
    <>
      <Field label="Session 候选选择器">
        <div className="space-y-3">
          <div className="flex items-center justify-between gap-3 rounded-xl border border-indigo-100 bg-indigo-50/50 px-3 py-2.5">
            <div className="min-w-0">
              <div className="text-[12px] font-semibold uppercase tracking-[0.18em] text-indigo-500">Session 候选</div>
              <div className="mt-1 text-[13px] text-slate-600">
                {loading
                  ? "正在扫描当前抓包中的 SMB3 Session 候选..."
                  : candidates.length > 0
                    ? "点击候选卡片后自动回填除哈希外的字段"
                    : "暂无可选候选"}
              </div>
            </div>
            <Button
              type="button"
              variant="outline"
              size="sm"
              data-testid="smb-session-candidate-refresh"
              onClick={() => void onRefresh()}
              disabled={!hasCapture || loading}
              className="shrink-0 border-indigo-200 bg-white text-indigo-700 hover:bg-indigo-50"
            >
              刷新候选
            </Button>
          </div>

          <div
            data-testid="smb-session-candidate-select"
            aria-disabled={!hasCapture || loading || candidates.length === 0}
            className={`rounded-xl border p-3 transition-colors ${
              !hasCapture || candidates.length === 0 ? "border-slate-200 bg-slate-50" : "border-indigo-100 bg-white"
            }`}
          >
            {candidates.length > 0 ? (
              <div className="grid max-h-64 gap-2 overflow-auto pr-1">
                {candidates.map((candidate) => (
                  <SMB3SessionCandidateCard
                    key={`${candidate.frameNumber}-${candidate.sessionId || "unknown"}`}
                    candidate={candidate}
                    onSelectCandidate={onSelectCandidate}
                    selected={selectedFrame === candidate.frameNumber}
                  />
                ))}
              </div>
            ) : (
              <div className="rounded-lg border border-dashed border-slate-200 bg-white px-3 py-6 text-center text-[13px] text-slate-500">
                {hasCapture ? "未在当前抓包中发现可用的 SMB3 Session 候选" : "未加载抓包，请先在主工作区导入文件"}
              </div>
            )}
          </div>
        </div>
      </Field>
      {!error && (
        <div className="rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-[12px] text-slate-600">
          {summary}
        </div>
      )}
      {error && <ErrorBlock message={error} />}
    </>
  );
}

function SMB3SessionCandidateCard({
  candidate,
  onSelectCandidate,
  selected,
}: {
  candidate: SMB3SessionCandidate;
  onSelectCandidate: (frameNumber: string) => void;
  selected: boolean;
}) {
  const sessionLabel = candidate.sessionId || "未知 SessionId";
  const userLabel = candidate.domain
    ? `${candidate.domain}\\${candidate.username || "未知用户"}`
    : candidate.username || "未知用户";
  return (
    <button
      type="button"
      data-testid={`smb-session-candidate-${candidate.frameNumber}`}
      onClick={() => onSelectCandidate(candidate.frameNumber)}
      className={`rounded-xl border px-3 py-3 text-left transition-all ${
        selected
          ? "border-indigo-400 bg-indigo-50 shadow-sm ring-2 ring-indigo-100"
          : "border-slate-200 bg-slate-50/70 hover:border-indigo-200 hover:bg-indigo-50/40"
      }`}
    >
      <div className="flex flex-wrap items-center gap-2">
        <span className="rounded-md border border-indigo-200 bg-indigo-50 px-2 py-1 font-mono text-[11px] font-semibold text-indigo-700">
          {sessionLabel}
        </span>
        <span
          className={`rounded-md px-2 py-1 text-[11px] font-semibold ${
            candidate.complete ? "bg-emerald-100 text-emerald-700" : "bg-amber-100 text-amber-700"
          }`}
        >
          {candidate.complete ? "材料完整" : "待补字段"}
        </span>
        <span className="text-[11px] text-slate-500">帧 #{candidate.frameNumber}</span>
        {candidate.timestamp && <span className="text-[11px] text-slate-500">{candidate.timestamp}</span>}
      </div>
      <div className="mt-2 text-[13px] font-semibold text-slate-800">{userLabel}</div>
      <div className="mt-1 break-all font-mono text-[12px] text-slate-600">
        {candidate.src || "?"} {"->"} {candidate.dst || "?"}
      </div>
    </button>
  );
}

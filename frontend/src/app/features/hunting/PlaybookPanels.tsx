import type { HuntingPlaybook, PlaybookRunResult, SavedSearch, Hypothesis } from "../../core/types/huntingPlaybook";

// ---------------------------------------------------------------------------
// Playbook list panel
// ---------------------------------------------------------------------------

interface PlaybookListPanelProps {
  playbooks: HuntingPlaybook[];
  selected: string | null;
  running: boolean;
  onSelect: (id: string) => void;
  onRun: (id: string) => void;
  onDelete: (id: string) => void;
}

export function PlaybookListPanel({
  playbooks,
  selected,
  running,
  onSelect,
  onRun,
  onDelete,
}: PlaybookListPanelProps) {
  if (playbooks.length === 0) {
    return (
      <div className="meow-tile p-4 text-center text-muted-foreground">
        暂无剧本。点击上方"新建剧本"创建第一个威胁狩猎剧本。
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-1">
      {playbooks.map((pb) => (
        <div
          key={pb.id}
          className={`meow-tile cursor-pointer p-3 transition-colors ${
            selected === pb.id ? "meow-tile-strong border-primary" : "hover:bg-accent/50"
          }`}
          onClick={() => onSelect(pb.id)}
        >
          <div className="flex items-center justify-between">
            <div className="flex-1 min-w-0">
              <div className="font-medium truncate">{pb.name}</div>
              {pb.description && (
                <div className="text-xs text-muted-foreground truncate mt-0.5">
                  {pb.description}
                </div>
              )}
              <div className="flex items-center gap-2 mt-1">
                <span
                  className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${
                    pb.status === "complete"
                      ? "bg-green-500/10 text-green-500"
                      : pb.status === "running"
                        ? "bg-blue-500/10 text-blue-500"
                        : pb.status === "failed"
                          ? "bg-red-500/10 text-red-500"
                          : "bg-muted text-muted-foreground"
                  }`}
                >
                  {pb.status}
                </span>
                <span className="text-xs text-muted-foreground">
                  {pb.steps.length} 步骤
                </span>
              </div>
            </div>
            <div className="flex items-center gap-1 ml-2">
              <button
                className="meow-btn meow-btn-ghost meow-btn-sm"
                disabled={running}
                onClick={(e) => {
                  e.stopPropagation();
                  onRun(pb.id);
                }}
                title="执行剧本"
              >
                ▶
              </button>
              <button
                className="meow-btn meow-btn-ghost meow-btn-sm text-destructive"
                onClick={(e) => {
                  e.stopPropagation();
                  onDelete(pb.id);
                }}
                title="删除剧本"
              >
                ✕
              </button>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Playbook detail panel
// ---------------------------------------------------------------------------

interface PlaybookDetailPanelProps {
  playbook: HuntingPlaybook;
  lastRun: PlaybookRunResult | null;
  running: boolean;
  onRun: (id: string) => void;
}

export function PlaybookDetailPanel({
  playbook,
  lastRun,
  running,
  onRun,
}: PlaybookDetailPanelProps) {
  return (
    <div className="meow-tile p-4 flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <h3 className="font-semibold text-lg">{playbook.name}</h3>
        <button
          className="meow-btn meow-btn-primary meow-btn-sm"
          disabled={running}
          onClick={() => onRun(playbook.id)}
        >
          {running ? "执行中..." : "执行剧本"}
        </button>
      </div>

      {playbook.description && (
        <p className="text-sm text-muted-foreground">{playbook.description}</p>
      )}

      {/* Steps */}
      <div>
        <h4 className="text-sm font-medium mb-2">执行步骤</h4>
        <div className="flex flex-col gap-1">
          {playbook.steps.map((step, i) => (
            <div
              key={step.id}
              className="flex items-center gap-2 text-sm p-2 rounded bg-muted/50"
            >
              <span className="text-muted-foreground font-mono">{i + 1}.</span>
              <span className="flex-1">{step.name}</span>
              <span className="text-xs text-muted-foreground bg-muted px-2 py-0.5 rounded">
                {step.type}
              </span>
              {!step.enabled && (
                <span className="text-xs text-muted-foreground">已禁用</span>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Last run results */}
      {lastRun && (
        <div>
          <h4 className="text-sm font-medium mb-2">上次执行结果</h4>
          <div className="grid grid-cols-3 gap-2 text-sm">
            <div className="p-2 rounded bg-muted/50">
              <div className="text-muted-foreground text-xs">状态</div>
              <div className="font-medium">{lastRun.status}</div>
            </div>
            <div className="p-2 rounded bg-muted/50">
              <div className="text-muted-foreground text-xs">命中</div>
              <div className="font-medium">{lastRun.totalHits}</div>
            </div>
            <div className="p-2 rounded bg-muted/50">
              <div className="text-muted-foreground text-xs">耗时</div>
              <div className="font-medium">{lastRun.durationMs}ms</div>
            </div>
          </div>

          {/* Step results */}
          <div className="mt-2 flex flex-col gap-1">
            {lastRun.stepResults.map((sr) => (
              <div
                key={sr.stepId}
                className="flex items-center gap-2 text-sm p-1.5 rounded bg-muted/30"
              >
                <span
                  className={`inline-block w-2 h-2 rounded-full ${
                    sr.status === "pass"
                      ? "bg-green-500"
                      : sr.status === "fail"
                        ? "bg-red-500"
                        : sr.status === "error"
                          ? "bg-yellow-500"
                          : "bg-muted-foreground/30"
                  }`}
                />
                <span className="flex-1">{sr.stepName}</span>
                <span className="text-xs text-muted-foreground">{sr.hitsCount} 命中</span>
                <span className="text-xs text-muted-foreground">{sr.durationMs}ms</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Saved search panel
// ---------------------------------------------------------------------------

interface SavedSearchPanelProps {
  searches: SavedSearch[];
  onExecute: (id: string) => void;
  onDelete: (id: string) => void;
}

export function SavedSearchPanel({ searches, onExecute, onDelete }: SavedSearchPanelProps) {
  if (searches.length === 0) {
    return (
      <div className="meow-tile p-4 text-center text-muted-foreground text-sm">
        暂无保存的搜索。
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-1">
      {searches.map((ss) => (
        <div key={ss.id} className="meow-tile p-3">
          <div className="flex items-center justify-between">
            <div className="flex-1 min-w-0">
              <div className="font-medium text-sm truncate">{ss.name}</div>
              <div className="text-xs text-muted-foreground font-mono truncate">
                {ss.query}
              </div>
              {ss.hitCount !== undefined && ss.hitCount > 0 && (
                <div className="text-xs text-muted-foreground mt-0.5">
                  {ss.hitCount} 条命中
                </div>
              )}
            </div>
            <div className="flex items-center gap-1 ml-2">
              <button
                className="meow-btn meow-btn-ghost meow-btn-sm"
                onClick={() => onExecute(ss.id)}
                title="执行搜索"
              >
                ▶
              </button>
              <button
                className="meow-btn meow-btn-ghost meow-btn-sm text-destructive"
                onClick={() => onDelete(ss.id)}
                title="删除搜索"
              >
                ✕
              </button>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Hypothesis panel
// ---------------------------------------------------------------------------

interface HypothesisPanelProps {
  hypotheses: Hypothesis[];
  onUpdateStatus: (id: string, status: string, conclusion?: string) => void;
}

export function HypothesisPanel({ hypotheses, onUpdateStatus }: HypothesisPanelProps) {
  if (hypotheses.length === 0) {
    return (
      <div className="meow-tile p-4 text-center text-muted-foreground text-sm">
        暂无假设。创建假设以驱动威胁狩猎调查。
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-2">
      {hypotheses.map((h) => (
        <div key={h.id} className="meow-tile p-3">
          <div className="flex items-start justify-between">
            <div className="flex-1 min-w-0">
              <div className="font-medium text-sm">{h.title}</div>
              {h.description && (
                <div className="text-xs text-muted-foreground mt-0.5">
                  {h.description}
                </div>
              )}
              <div className="flex items-center gap-2 mt-1">
                <span
                  className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${
                    h.status === "confirmed"
                      ? "bg-green-500/10 text-green-500"
                      : h.status === "refuted"
                        ? "bg-red-500/10 text-red-500"
                        : h.status === "investigating"
                          ? "bg-blue-500/10 text-blue-500"
                          : "bg-muted text-muted-foreground"
                  }`}
                >
                  {h.status}
                </span>
                {h.evidence && h.evidence.length > 0 && (
                  <span className="text-xs text-muted-foreground">
                    {h.evidence.length} 条证据
                  </span>
                )}
              </div>
            </div>
          </div>

          {/* Evidence list */}
          {h.evidence && h.evidence.length > 0 && (
            <div className="mt-2 flex flex-col gap-1">
              {h.evidence.map((ev) => (
                <div
                  key={ev.id}
                  className="text-xs p-1.5 rounded bg-muted/30 flex items-center gap-2"
                >
                  <span
                    className={`inline-block w-1.5 h-1.5 rounded-full ${
                      ev.strength === "supports"
                        ? "bg-green-500"
                        : ev.strength === "contradicts"
                          ? "bg-red-500"
                          : "bg-muted-foreground/30"
                    }`}
                  />
                  <span className="flex-1">{ev.description}</span>
                  <span className="text-muted-foreground">{ev.source}</span>
                </div>
              ))}
            </div>
          )}

          {/* Status actions */}
          {h.status === "open" && (
            <div className="mt-2 flex gap-1">
              <button
                className="meow-btn meow-btn-ghost meow-btn-sm text-xs"
                onClick={() => onUpdateStatus(h.id, "investigating")}
              >
                开始调查
              </button>
            </div>
          )}
          {h.status === "investigating" && (
            <div className="mt-2 flex gap-1">
              <button
                className="meow-btn meow-btn-ghost meow-btn-sm text-xs text-green-500"
                onClick={() => onUpdateStatus(h.id, "confirmed")}
              >
                确认
              </button>
              <button
                className="meow-btn meow-btn-ghost meow-btn-sm text-xs text-red-500"
                onClick={() => onUpdateStatus(h.id, "refuted")}
              >
                否定
              </button>
              <button
                className="meow-btn meow-btn-ghost meow-btn-sm text-xs"
                onClick={() => onUpdateStatus(h.id, "inconclusive")}
              >
                无法确定
              </button>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

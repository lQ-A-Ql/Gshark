import { ChevronLeft, ChevronRight, Pause, Play } from "lucide-react";
import { AnalysisStatCard as StatCard } from "../../components/analysis/AnalysisPrimitives";
import type { USBKeyboardEvent } from "../../core/types";
import { UsbHidEmptyState } from "./UsbHidEmptyState";

export function KeyboardReplay({
  currentEvent,
  currentIndex,
  isPlaying,
  replayText,
  total,
  onCursorChange,
  onPrev,
  onNext,
  onTogglePlay,
}: {
  currentEvent: USBKeyboardEvent | null;
  currentIndex: number;
  isPlaying: boolean;
  replayText: string;
  total: number;
  onCursorChange: (value: number) => void;
  onPrev: () => void;
  onNext: () => void;
  onTogglePlay: () => void;
}) {
  if (total === 0) {
    return <UsbHidEmptyState>暂无键盘行为</UsbHidEmptyState>;
  }

  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-border bg-[linear-gradient(180deg,#eff6ff,#f8fafc)] p-4">
        <KeyboardReplayControls
          currentIndex={currentIndex}
          isPlaying={isPlaying}
          total={total}
          onCursorChange={onCursorChange}
          onNext={onNext}
          onPrev={onPrev}
          onTogglePlay={onTogglePlay}
        />
        <pre className="mt-4 max-h-[180px] overflow-auto whitespace-pre-wrap break-all rounded-lg border border-border bg-slate-950 px-3 py-3 font-mono text-xs leading-5 text-slate-100">
          {replayText}
        </pre>
      </div>

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-4">
        <StatCard title="当前包号" value={currentEvent ? String(currentEvent.packetId) : "--"} />
        <StatCard title="当前时间" value={currentEvent?.time || "--"} />
        <StatCard title="按下键" value={currentEvent?.pressedKeys.join(", ") || "--"} />
        <StatCard title="释放键" value={currentEvent?.releasedKeys.join(", ") || "--"} />
      </div>

      <div className="rounded-lg border border-border bg-background px-3 py-3 text-xs text-muted-foreground">
        <div className="font-medium text-foreground">{currentEvent?.summary || "当前事件无摘要"}</div>
        <div className="mt-1">
          文本输出：
          {currentEvent?.text ? (
            <span className="font-mono text-foreground">{JSON.stringify(currentEvent.text)}</span>
          ) : (
            "--"
          )}
        </div>
      </div>
    </div>
  );
}

function KeyboardReplayControls({
  currentIndex,
  isPlaying,
  total,
  onCursorChange,
  onPrev,
  onNext,
  onTogglePlay,
}: {
  currentIndex: number;
  isPlaying: boolean;
  total: number;
  onCursorChange: (value: number) => void;
  onPrev: () => void;
  onNext: () => void;
  onTogglePlay: () => void;
}) {
  return (
    <>
      <div className="flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={onPrev}
          className="inline-flex h-9 w-9 items-center justify-center rounded-full border border-border bg-card text-foreground hover:bg-accent"
        >
          <ChevronLeft className="h-4 w-4" />
        </button>
        <button
          type="button"
          onClick={onTogglePlay}
          className="inline-flex h-9 w-9 items-center justify-center rounded-full border border-blue-500 bg-blue-600 text-white hover:bg-blue-700"
        >
          {isPlaying ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
        </button>
        <button
          type="button"
          onClick={onNext}
          className="inline-flex h-9 w-9 items-center justify-center rounded-full border border-border bg-card text-foreground hover:bg-accent"
        >
          <ChevronRight className="h-4 w-4" />
        </button>
        <div className="ml-auto text-xs text-muted-foreground">
          第 <span className="font-mono text-foreground">{Math.min(currentIndex + 1, total)}</span> /{" "}
          <span className="font-mono text-foreground">{total}</span> 条
        </div>
      </div>

      <div className="mt-4">
        <input
          type="range"
          min={0}
          max={Math.max(total - 1, 0)}
          step={1}
          value={Math.min(currentIndex, Math.max(total - 1, 0))}
          onChange={(event) => onCursorChange(Number(event.target.value))}
          className="h-2 w-full cursor-pointer appearance-none rounded-lg bg-slate-200 accent-blue-600"
        />
      </div>
    </>
  );
}

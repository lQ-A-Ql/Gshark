import { ChevronLeft, ChevronRight, Pause, Play, Route } from "lucide-react";
import type { ReactNode } from "react";
import { AnalysisStatCard as StatCard } from "../../components/analysis/AnalysisPrimitives";
import type { USBKeyboardEvent, USBMouseEvent } from "../../core/types";

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
    return <EmptyState>暂无键盘行为</EmptyState>;
  }

  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-border bg-[linear-gradient(180deg,#eff6ff,#f8fafc)] p-4">
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

export function MouseTrajectory({ events }: { events: USBMouseEvent[] }) {
  if (events.length === 0) {
    return <EmptyState>暂无鼠标轨迹数据</EmptyState>;
  }

  const width = 680;
  const height = 320;
  const points = normalizeMousePoints(events, width, height);
  const polyline = points.map((point) => `${point.x},${point.y}`).join(" ");
  const start = polyline.split(" ")[0];
  const end = polyline.split(" ").at(-1);

  return (
    <div className="space-y-3">
      <div className="overflow-hidden rounded-xl border border-border bg-[radial-gradient(circle_at_top,#dbeafe,transparent_60%),linear-gradient(180deg,#f8fafc,#eef2ff)]">
        <svg viewBox={`0 0 ${width} ${height}`} className="h-[320px] w-full">
          <defs>
            <pattern id="mouse-grid" width="24" height="24" patternUnits="userSpaceOnUse">
              <path d="M 24 0 L 0 0 0 24" fill="none" stroke="rgba(148,163,184,0.18)" strokeWidth="1" />
            </pattern>
          </defs>
          <rect width={width} height={height} fill="url(#mouse-grid)" />
          <polyline
            fill="none"
            stroke="#2563eb"
            strokeWidth="2.5"
            strokeLinejoin="round"
            strokeLinecap="round"
            points={polyline}
          />
          {start && <circle cx={start.split(",")[0]} cy={start.split(",")[1]} r="5" fill="#16a34a" />}
          {end && <circle cx={end.split(",")[0]} cy={end.split(",")[1]} r="5" fill="#dc2626" />}
        </svg>
      </div>
      <div className="flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
        <span className="inline-flex items-center gap-1">
          <span className="h-2.5 w-2.5 rounded-full bg-emerald-600" /> 起点
        </span>
        <span className="inline-flex items-center gap-1">
          <span className="h-2.5 w-2.5 rounded-full bg-rose-600" /> 终点
        </span>
        <span className="inline-flex items-center gap-1">
          <Route className="h-3.5 w-3.5" /> 轨迹基于相对位移累计
        </span>
      </div>
    </div>
  );
}

export function MouseHeatmap({ events }: { events: USBMouseEvent[] }) {
  if (events.length === 0) {
    return <EmptyState>暂无鼠标热区数据</EmptyState>;
  }

  const width = 680;
  const height = 320;
  const points = normalizeMousePoints(events, width, height);
  const bucketSize = 18;
  const density = new Map<string, { x: number; y: number; count: number; clicks: number }>();

  points.forEach((point, index) => {
    const bucketX = Math.round(point.x / bucketSize) * bucketSize;
    const bucketY = Math.round(point.y / bucketSize) * bucketSize;
    const key = `${bucketX}:${bucketY}`;
    const current = density.get(key) ?? { x: bucketX, y: bucketY, count: 0, clicks: 0 };
    current.count += 1;
    if ((events[index]?.pressedButtons.length ?? 0) + (events[index]?.releasedButtons.length ?? 0) > 0) {
      current.clicks += 1;
    }
    density.set(key, current);
  });

  const hotspots = Array.from(density.values());
  const maxCount = Math.max(1, ...hotspots.map((item) => item.count));

  return (
    <div className="space-y-3">
      <div className="overflow-hidden rounded-xl border border-border bg-[radial-gradient(circle_at_top,#bfdbfe,transparent_55%),linear-gradient(180deg,#f8fafc,#eef2ff)]">
        <svg viewBox={`0 0 ${width} ${height}`} className="h-[320px] w-full">
          <rect width={width} height={height} fill="rgba(255,255,255,0.3)" />
          {hotspots.map((item) => {
            const radius = 8 + (item.count / maxCount) * 18;
            const opacity = 0.18 + (item.count / maxCount) * 0.55;
            return (
              <circle
                key={`${item.x}-${item.y}`}
                cx={item.x}
                cy={item.y}
                r={radius}
                fill={`rgba(37,99,235,${opacity})`}
              />
            );
          })}
          {hotspots
            .filter((item) => item.clicks > 0)
            .map((item) => (
              <circle
                key={`click-${item.x}-${item.y}`}
                cx={item.x}
                cy={item.y}
                r={6 + Math.min(item.clicks, 4) * 2}
                fill="rgba(220,38,38,0.55)"
                stroke="rgba(185,28,28,0.9)"
                strokeWidth="1.5"
              />
            ))}
        </svg>
      </div>
      <div className="flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
        <span className="inline-flex items-center gap-1">
          <span className="h-2.5 w-2.5 rounded-full bg-blue-600" /> 停留密度
        </span>
        <span className="inline-flex items-center gap-1">
          <span className="h-2.5 w-2.5 rounded-full bg-rose-600" /> 点击热点
        </span>
      </div>
    </div>
  );
}

export function MouseBehaviorList({ rows }: { rows: USBMouseEvent[] }) {
  if (rows.length === 0) {
    return <EmptyState>暂无鼠标行为</EmptyState>;
  }
  return (
    <div className="max-h-[320px] space-y-2 overflow-auto">
      {rows.map((row) => (
        <div
          key={`${row.packetId}-${row.positionX}-${row.positionY}`}
          className="rounded-lg border border-border bg-background px-3 py-2 text-xs"
        >
          <div className="flex items-center justify-between gap-2">
            <span className="font-mono text-muted-foreground">
              #{row.packetId} {row.time}
            </span>
            <span className="rounded border border-border px-2 py-0.5 text-[11px]">{mouseActionBadge(row)}</span>
          </div>
          <div className="mt-1 text-foreground">{row.summary}</div>
          <div className="mt-1 font-mono text-[11px] text-muted-foreground">
            pos=({row.positionX}, {row.positionY}) / delta=({row.xDelta}, {row.yDelta})
          </div>
        </div>
      ))}
    </div>
  );
}

export function keyboardReplayToken(event: USBKeyboardEvent) {
  if (event.text) {
    return event.text;
  }
  if (event.pressedKeys.length > 0 || event.releasedKeys.length > 0) {
    return `[${event.summary}] `;
  }
  return "";
}

function mouseActionBadge(row: USBMouseEvent) {
  if (row.pressedButtons.length > 0) return `press ${row.pressedButtons.join(", ")}`;
  if (row.releasedButtons.length > 0) return `release ${row.releasedButtons.join(", ")}`;
  if (row.wheelVertical !== 0 || row.wheelHorizontal !== 0) return "wheel";
  if (row.xDelta !== 0 || row.yDelta !== 0) return "move";
  return "event";
}

function normalizeMousePoints(events: USBMouseEvent[], width: number, height: number) {
  const points = events.map((event) => ({ x: event.positionX, y: event.positionY }));
  const xs = points.map((point) => point.x);
  const ys = points.map((point) => point.y);
  const minX = Math.min(...xs);
  const maxX = Math.max(...xs);
  const minY = Math.min(...ys);
  const maxY = Math.max(...ys);
  const spanX = Math.max(1, maxX - minX);
  const spanY = Math.max(1, maxY - minY);

  return points.map((point) => ({
    x: ((point.x - minX) / spanX) * (width - 40) + 20,
    y: height - (((point.y - minY) / spanY) * (height - 40) + 20),
  }));
}

function EmptyState({ children }: { children: ReactNode }) {
  return (
    <div className="rounded border border-dashed border-border px-3 py-6 text-center text-xs text-muted-foreground">
      {children}
    </div>
  );
}

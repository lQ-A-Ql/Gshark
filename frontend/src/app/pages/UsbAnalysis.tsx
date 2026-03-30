import { ChevronLeft, ChevronRight, Keyboard, MousePointer2, Pause, Play, RefreshCw, Route, Usb, Workflow } from "lucide-react";
import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import type { TrafficBucket, USBAnalysis as USBAnalysisData, USBKeyboardEvent, USBMouseEvent, USBPacketRecord } from "../core/types";
import { bridge } from "../integrations/wailsBridge";
import { useSentinel } from "../state/SentinelContext";

type UsbTab = "keyboard" | "mouse" | "other";

const EMPTY_ANALYSIS: USBAnalysisData = {
  totalUSBPackets: 0,
  keyboardPackets: 0,
  mousePackets: 0,
  otherUSBPackets: 0,
  protocols: [],
  transferTypes: [],
  directions: [],
  devices: [],
  endpoints: [],
  setupRequests: [],
  records: [],
  keyboardEvents: [],
  mouseEvents: [],
  otherRecords: [],
  notes: [],
};

const usbAnalysisCache = new Map<string, USBAnalysisData>();

export default function UsbAnalysis() {
  const { backendConnected, isPreloadingCapture, fileMeta, totalPackets } = useSentinel();
  const cacheKey = useMemo(() => {
    if (!fileMeta.path) return "";
    return `${fileMeta.path}::${totalPackets}`;
  }, [fileMeta.path, totalPackets]);
  const [analysis, setAnalysis] = useState<USBAnalysisData>(EMPTY_ANALYSIS);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [activeTab, setActiveTab] = useState<UsbTab>("keyboard");
  const keyboardDevices = useMemo(
    () => Array.from(new Set(analysis.keyboardEvents.map((item) => item.device || item.endpoint).filter(Boolean))),
    [analysis.keyboardEvents],
  );
  const mouseDevices = useMemo(
    () => Array.from(new Set(analysis.mouseEvents.map((item) => item.device || item.endpoint).filter(Boolean))),
    [analysis.mouseEvents],
  );
  const [activeKeyboardDevice, setActiveKeyboardDevice] = useState("");
  const [keyboardCursor, setKeyboardCursor] = useState(0);
  const [isKeyboardPlaying, setIsKeyboardPlaying] = useState(false);
  const [activeMouseDevice, setActiveMouseDevice] = useState("");

  const refreshAnalysis = useCallback((force = false) => {
    if (!backendConnected) {
      setLoading(false);
      setError("");
      setAnalysis(EMPTY_ANALYSIS);
      return;
    }
    if (!force && cacheKey && usbAnalysisCache.has(cacheKey)) {
      setAnalysis(usbAnalysisCache.get(cacheKey) ?? EMPTY_ANALYSIS);
      setLoading(false);
      setError("");
      return;
    }

    setLoading(true);
    setError("");
    void bridge
      .getUSBAnalysis()
      .then((payload) => {
        if (cacheKey) {
          usbAnalysisCache.set(cacheKey, payload);
        }
        setAnalysis(payload);
      })
      .catch((err) => {
        setError(err instanceof Error ? err.message : "USB 分析加载失败");
        setAnalysis(EMPTY_ANALYSIS);
      })
      .finally(() => {
        setLoading(false);
      });
  }, [backendConnected, cacheKey]);

  useEffect(() => {
    if (isPreloadingCapture) return;
    refreshAnalysis();
  }, [isPreloadingCapture, refreshAnalysis]);

  useEffect(() => {
    if (keyboardDevices.length === 0) {
      setActiveKeyboardDevice("");
      return;
    }
    setActiveKeyboardDevice((prev) => (prev && keyboardDevices.includes(prev) ? prev : keyboardDevices[0]));
  }, [keyboardDevices]);

  useEffect(() => {
    if (mouseDevices.length === 0) {
      setActiveMouseDevice("");
      return;
    }
    setActiveMouseDevice((prev) => (prev && mouseDevices.includes(prev) ? prev : mouseDevices[0]));
  }, [mouseDevices]);

  const filteredKeyboardEvents = useMemo(() => {
    if (!activeKeyboardDevice) return analysis.keyboardEvents;
    return analysis.keyboardEvents.filter((item) => (item.device || item.endpoint) === activeKeyboardDevice);
  }, [activeKeyboardDevice, analysis.keyboardEvents]);

  const filteredMouseEvents = useMemo(() => {
    if (!activeMouseDevice) return analysis.mouseEvents;
    return analysis.mouseEvents.filter((item) => (item.device || item.endpoint) === activeMouseDevice);
  }, [activeMouseDevice, analysis.mouseEvents]);

  useEffect(() => {
    setKeyboardCursor((prev) => Math.min(prev, Math.max(filteredKeyboardEvents.length - 1, 0)));
    setIsKeyboardPlaying(false);
  }, [filteredKeyboardEvents]);

  useEffect(() => {
    if (!isKeyboardPlaying || filteredKeyboardEvents.length <= 1) return;
    if (keyboardCursor >= filteredKeyboardEvents.length - 1) {
      setIsKeyboardPlaying(false);
      return;
    }
    const timer = window.setTimeout(() => {
      setKeyboardCursor((prev) => {
        if (prev >= filteredKeyboardEvents.length - 1) {
          setIsKeyboardPlaying(false);
          return prev;
        }
        return prev + 1;
      });
    }, 480);
    return () => window.clearTimeout(timer);
  }, [filteredKeyboardEvents.length, isKeyboardPlaying, keyboardCursor]);

  const keyboardStats = useMemo(() => {
    const uniqueKeys = new Set(filteredKeyboardEvents.flatMap((item) => item.keys));
    return {
      printableCount: filteredKeyboardEvents.filter((item) => Boolean(item.text && item.text.length > 0)).length,
      comboCount: filteredKeyboardEvents.filter((item) => item.modifiers.length > 0).length,
      uniqueKeyCount: uniqueKeys.size,
    };
  }, [filteredKeyboardEvents]);

  const mouseStats = useMemo(() => {
    let distance = 0;
    let clickCount = 0;
    let wheelCount = 0;
    for (const event of filteredMouseEvents) {
      distance += Math.hypot(event.xDelta, event.yDelta);
      if (event.buttons.length > 0) {
        clickCount += event.buttons.length;
      }
      if (event.wheelVertical !== 0 || event.wheelHorizontal !== 0) {
        wheelCount += 1;
      }
    }
    return {
      distance: Math.round(distance),
      clickCount,
      wheelCount,
    };
  }, [filteredMouseEvents]);

  const currentKeyboardEvent = filteredKeyboardEvents[keyboardCursor] ?? null;
  const keyboardTextPreview = useMemo(() => {
    const text = filteredKeyboardEvents
      .map((item) => item.text ?? "")
      .join("")
      .replace(/\n/g, "↵\n")
      .replace(/\t/g, "⇥");
    return text || "(未解析到可打印字符，仍可查看下方按键事件表)";
  }, [filteredKeyboardEvents]);
  const keyboardReplayText = useMemo(() => {
    if (filteredKeyboardEvents.length === 0) {
      return "(未解析到键盘事件)";
    }
    const text = filteredKeyboardEvents
      .slice(0, keyboardCursor + 1)
      .map((item) => keyboardReplayToken(item))
      .join("")
      .replace(/\n/g, "↵\n")
      .replace(/\t/g, "⇥");
    return text || "(当前事件未产生可打印字符)";
  }, [filteredKeyboardEvents, keyboardCursor]);

  return (
    <div className="flex h-full flex-col overflow-auto bg-background p-4 text-foreground">
      <div className="mb-4 flex items-center gap-2 text-lg font-semibold">
        <Usb className="h-5 w-5 text-blue-600" />
        USB HID 分析
        <span className="rounded border border-border bg-accent px-2 py-0.5 text-xs font-medium text-muted-foreground">
          键盘 / 鼠标 / 其余 USB
        </span>
        <button
          className="ml-2 inline-flex items-center gap-1 rounded border border-border bg-card px-2 py-1 text-xs text-muted-foreground hover:bg-accent hover:text-foreground"
          onClick={() => refreshAnalysis(true)}
        >
          <RefreshCw className="h-3.5 w-3.5" />
          刷新
        </button>
      </div>

      {loading && (
        <div className="mb-3 rounded border border-border bg-card px-3 py-2 text-xs text-muted-foreground">
          正在解析 USB / HID 数据...
        </div>
      )}

      {!loading && error && (
        <div className="mb-3 rounded border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-700">{error}</div>
      )}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
        <StatCard title="USB 包总数" value={analysis.totalUSBPackets.toLocaleString()} />
        <StatCard title="键盘事件" value={analysis.keyboardPackets.toLocaleString()} />
        <StatCard title="鼠标事件" value={analysis.mousePackets.toLocaleString()} />
        <StatCard title="其余 USB" value={analysis.otherUSBPackets.toLocaleString()} />
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Panel title="协议分布">
          <BucketChart data={analysis.protocols} color="bg-blue-500" />
        </Panel>
        <Panel title="传输类型">
          <BucketChart data={analysis.transferTypes} color="bg-emerald-500" />
        </Panel>
        <Panel title="分析提示">
          <div className="space-y-2 text-sm">
            {analysis.notes.length === 0 ? (
              <div className="rounded border border-dashed border-border px-3 py-3 text-muted-foreground">当前抓包未识别到可展示的 USB HID 活动。</div>
            ) : (
              analysis.notes.map((note, index) => (
                <div key={`${note}-${index}`} className="flex items-start gap-2 rounded border border-border bg-background px-3 py-2">
                  <Workflow className="mt-0.5 h-4 w-4 shrink-0 text-blue-600" />
                  <span>{note}</span>
                </div>
              ))
            )}
          </div>
        </Panel>
      </div>

      <div className="mt-4 flex flex-wrap items-center gap-2">
        <TabButton active={activeTab === "keyboard"} onClick={() => setActiveTab("keyboard")} icon={<Keyboard className="h-4 w-4" />}>
          键盘
        </TabButton>
        <TabButton active={activeTab === "mouse"} onClick={() => setActiveTab("mouse")} icon={<MousePointer2 className="h-4 w-4" />}>
          鼠标
        </TabButton>
        <TabButton active={activeTab === "other"} onClick={() => setActiveTab("other")} icon={<Usb className="h-4 w-4" />}>
          其余 USB
        </TabButton>
      </div>

      {activeTab === "keyboard" && (
        <div className="mt-4 space-y-4">
          <DeviceChips
            devices={keyboardDevices}
            activeDevice={activeKeyboardDevice}
            emptyLabel="未检测到键盘设备"
            onSelect={setActiveKeyboardDevice}
          />

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
            <StatCard title="当前设备事件" value={filteredKeyboardEvents.length.toLocaleString()} />
            <StatCard title="可打印事件" value={keyboardStats.printableCount.toLocaleString()} />
            <StatCard title="组合键事件" value={keyboardStats.comboCount.toLocaleString()} />
            <StatCard title="唯一按键" value={keyboardStats.uniqueKeyCount.toLocaleString()} />
          </div>

          <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1.15fr)_minmax(0,0.85fr)]">
            <Panel title="键盘输入回放">
              <KeyboardReplay
                currentEvent={currentKeyboardEvent}
                currentIndex={keyboardCursor}
                isPlaying={isKeyboardPlaying}
                replayText={keyboardReplayText}
                total={filteredKeyboardEvents.length}
                onCursorChange={setKeyboardCursor}
                onNext={() => setKeyboardCursor((prev) => Math.min(prev + 1, Math.max(filteredKeyboardEvents.length - 1, 0)))}
                onPrev={() => setKeyboardCursor((prev) => Math.max(prev - 1, 0))}
                onTogglePlay={() => {
                  if (filteredKeyboardEvents.length <= 1) return;
                  setIsKeyboardPlaying((prev) => {
                    if (keyboardCursor >= filteredKeyboardEvents.length - 1 && !prev) {
                      setKeyboardCursor(0);
                    }
                    return !prev;
                  });
                }}
              />
            </Panel>
            <Panel title="完整输入文本流">
              <pre className="max-h-[260px] overflow-auto whitespace-pre-wrap break-all rounded-md border border-border bg-background px-3 py-3 font-mono text-xs leading-5">
                {keyboardTextPreview}
              </pre>
            </Panel>
          </div>

          <Panel title={`键盘事件 (${filteredKeyboardEvents.length})`}>
            <KeyboardEventTable rows={filteredKeyboardEvents} />
          </Panel>
        </div>
      )}

      {activeTab === "mouse" && (
        <div className="mt-4 space-y-4">
          <DeviceChips
            devices={mouseDevices}
            activeDevice={activeMouseDevice}
            emptyLabel="未检测到鼠标设备"
            onSelect={setActiveMouseDevice}
          />

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
            <StatCard title="鼠标事件" value={filteredMouseEvents.length.toLocaleString()} />
            <StatCard title="轨迹总路程" value={`${mouseStats.distance}`} />
            <StatCard title="按钮动作" value={`${mouseStats.clickCount}`} />
            <StatCard title="滚轮事件" value={`${mouseStats.wheelCount}`} />
          </div>

          <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
            <Panel title="鼠标轨迹图">
              <MouseTrajectory events={filteredMouseEvents} />
            </Panel>
            <Panel title="鼠标热区图">
              <MouseHeatmap events={filteredMouseEvents} />
            </Panel>
          </div>

          <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,0.9fr)]">
            <Panel title="最近鼠标行为">
              <MouseEventList rows={filteredMouseEvents.slice(-16).reverse()} />
            </Panel>
            <Panel title="行为摘要">
              <div className="grid grid-cols-2 gap-3">
                <StatCard title="起点" value={filteredMouseEvents[0] ? `${filteredMouseEvents[0].positionX}, ${filteredMouseEvents[0].positionY}` : "--"} />
                <StatCard
                  title="终点"
                  value={
                    filteredMouseEvents.length > 0
                      ? `${filteredMouseEvents[filteredMouseEvents.length - 1].positionX}, ${filteredMouseEvents[filteredMouseEvents.length - 1].positionY}`
                      : "--"
                  }
                />
                <StatCard
                  title="点击事件"
                  value={filteredMouseEvents.filter((item) => item.buttons.length > 0).length.toLocaleString()}
                />
                <StatCard
                  title="拖拽倾向"
                  value={
                    filteredMouseEvents.some((item) => item.buttons.length > 0 && (item.xDelta !== 0 || item.yDelta !== 0))
                      ? "检测到"
                      : "未见明显拖拽"
                  }
                />
              </div>
            </Panel>
          </div>

          <Panel title={`鼠标事件明细 (${filteredMouseEvents.length})`}>
            <MouseEventTable rows={filteredMouseEvents} />
          </Panel>
        </div>
      )}

      {activeTab === "other" && (
        <div className="mt-4 space-y-4">
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
            <StatCard title="其余 USB 包" value={analysis.otherUSBPackets.toLocaleString()} />
            <StatCard title="设备数" value={String(new Set(analysis.otherRecords.map((item) => joinParts(item.busId, item.deviceAddress)).filter((item) => item !== "--")).size)} />
            <StatCard title="端点数" value={String(new Set(analysis.otherRecords.map((item) => item.endpoint).filter(Boolean)).size)} />
            <StatCard title="Setup 请求" value={String(analysis.otherRecords.filter((item) => Boolean(item.setupRequest)).length)} />
          </div>

          <Panel title={`其余 USB 记录 (${analysis.otherRecords.length})`}>
            <USBRecordTable rows={analysis.otherRecords} />
          </Panel>
        </div>
      )}
    </div>
  );
}

function TabButton({
  active,
  onClick,
  icon,
  children,
}: {
  active: boolean;
  onClick: () => void;
  icon: ReactNode;
  children: ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      className={`inline-flex items-center gap-2 rounded-full border px-4 py-2 text-sm transition-colors ${active ? "border-blue-500 bg-blue-50 text-blue-700" : "border-border bg-card text-muted-foreground hover:bg-accent hover:text-foreground"}`}
    >
      {icon}
      {children}
    </button>
  );
}

function DeviceChips({
  devices,
  activeDevice,
  emptyLabel,
  onSelect,
}: {
  devices: string[];
  activeDevice: string;
  emptyLabel: string;
  onSelect: (device: string) => void;
}) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      {devices.length === 0 ? (
        <span className="rounded border border-dashed border-border px-3 py-1.5 text-xs text-muted-foreground">{emptyLabel}</span>
      ) : (
        devices.map((device) => (
          <button
            key={device}
            onClick={() => onSelect(device)}
            className={`rounded-full border px-3 py-1.5 text-xs transition-colors ${activeDevice === device ? "border-blue-500 bg-blue-50 text-blue-700" : "border-border bg-card text-muted-foreground hover:bg-accent hover:text-foreground"}`}
          >
            {device}
          </button>
        ))
      )}
    </div>
  );
}

function KeyboardReplay({
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
    return <EmptyState>暂无键盘事件</EmptyState>;
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
        <StatCard title="当前修饰键" value={currentEvent?.modifiers.join(", ") || "--"} />
        <StatCard title="当前按键" value={currentEvent?.keys.join(", ") || "--"} />
      </div>

      <div className="rounded-lg border border-border bg-background px-3 py-3 text-xs text-muted-foreground">
        <div className="font-medium text-foreground">{currentEvent?.summary || "当前事件无摘要"}</div>
        <div className="mt-1">文本输出：{currentEvent?.text ? <span className="font-mono text-foreground">{JSON.stringify(currentEvent.text)}</span> : "--"}</div>
      </div>
    </div>
  );
}

function MouseTrajectory({ events }: { events: USBMouseEvent[] }) {
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
          <polyline fill="none" stroke="#2563eb" strokeWidth="2.5" strokeLinejoin="round" strokeLinecap="round" points={polyline} />
          {start && <circle cx={start.split(",")[0]} cy={start.split(",")[1]} r="5" fill="#16a34a" />}
          {end && <circle cx={end.split(",")[0]} cy={end.split(",")[1]} r="5" fill="#dc2626" />}
        </svg>
      </div>
      <div className="flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
        <span className="inline-flex items-center gap-1"><span className="h-2.5 w-2.5 rounded-full bg-emerald-600" /> 起点</span>
        <span className="inline-flex items-center gap-1"><span className="h-2.5 w-2.5 rounded-full bg-rose-600" /> 终点</span>
        <span className="inline-flex items-center gap-1"><Route className="h-3.5 w-3.5" /> 轨迹基于相对位移累计</span>
      </div>
    </div>
  );
}

function MouseHeatmap({ events }: { events: USBMouseEvent[] }) {
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
    if (events[index]?.buttons.length) {
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
            return <circle key={`${item.x}-${item.y}`} cx={item.x} cy={item.y} r={radius} fill={`rgba(37,99,235,${opacity})`} />;
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
        <span className="inline-flex items-center gap-1"><span className="h-2.5 w-2.5 rounded-full bg-blue-600" /> 停留密度</span>
        <span className="inline-flex items-center gap-1"><span className="h-2.5 w-2.5 rounded-full bg-rose-600" /> 点击热点</span>
      </div>
    </div>
  );
}

function MouseEventList({ rows }: { rows: USBMouseEvent[] }) {
  if (rows.length === 0) {
    return <EmptyState>暂无鼠标事件</EmptyState>;
  }
  return (
    <div className="max-h-[320px] space-y-2 overflow-auto">
      {rows.map((row) => (
        <div key={`${row.packetId}-${row.positionX}-${row.positionY}`} className="rounded-lg border border-border bg-background px-3 py-2 text-xs">
          <div className="flex items-center justify-between gap-2">
            <span className="font-mono text-muted-foreground">#{row.packetId} {row.time}</span>
            <span className="rounded border border-border px-2 py-0.5 text-[11px]">{row.buttons.join(", ") || "move"}</span>
          </div>
          <div className="mt-1 text-foreground">{row.summary}</div>
          <div className="mt-1 font-mono text-[11px] text-muted-foreground">pos=({row.positionX}, {row.positionY}) / delta=({row.xDelta}, {row.yDelta})</div>
        </div>
      ))}
    </div>
  );
}

function KeyboardEventTable({ rows }: { rows: USBKeyboardEvent[] }) {
  return (
    <div className="max-h-[520px] overflow-auto">
      <table className="w-full table-fixed border-collapse text-left text-xs">
        <thead className="sticky top-0 bg-accent/90 text-muted-foreground shadow-[0_1px_0_0_var(--color-border)]">
          <tr>
            <th className="w-20 px-3 py-2">包号</th>
            <th className="w-28 px-3 py-2">时间</th>
            <th className="w-40 px-3 py-2">设备</th>
            <th className="w-28 px-3 py-2">端点</th>
            <th className="w-40 px-3 py-2">修饰键</th>
            <th className="w-40 px-3 py-2">按键</th>
            <th className="w-20 px-3 py-2">文本</th>
            <th className="px-3 py-2">摘要</th>
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 ? (
            <tr>
              <td colSpan={8} className="px-3 py-6 text-center text-muted-foreground">暂无键盘事件</td>
            </tr>
          ) : (
            rows.map((row) => (
              <tr key={`${row.packetId}-${row.summary}`} className="border-b border-border/70 align-top">
                <td className="px-3 py-2 font-mono text-muted-foreground">{row.packetId}</td>
                <td className="px-3 py-2 font-mono">{row.time || "--"}</td>
                <td className="px-3 py-2">{row.device || "--"}</td>
                <td className="px-3 py-2 font-mono">{row.endpoint || "--"}</td>
                <td className="px-3 py-2">{row.modifiers.join(", ") || "--"}</td>
                <td className="px-3 py-2">{row.keys.join(", ") || "--"}</td>
                <td className="px-3 py-2 font-mono whitespace-pre-wrap">{row.text || "--"}</td>
                <td className="px-3 py-2">{row.summary || "--"}</td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}

function MouseEventTable({ rows }: { rows: USBMouseEvent[] }) {
  return (
    <div className="max-h-[520px] overflow-auto">
      <table className="w-full table-fixed border-collapse text-left text-xs">
        <thead className="sticky top-0 bg-accent/90 text-muted-foreground shadow-[0_1px_0_0_var(--color-border)]">
          <tr>
            <th className="w-20 px-3 py-2">包号</th>
            <th className="w-28 px-3 py-2">时间</th>
            <th className="w-40 px-3 py-2">设备</th>
            <th className="w-28 px-3 py-2">端点</th>
            <th className="w-28 px-3 py-2">按钮</th>
            <th className="w-20 px-3 py-2">dX</th>
            <th className="w-20 px-3 py-2">dY</th>
            <th className="w-20 px-3 py-2">滚轮V</th>
            <th className="w-20 px-3 py-2">滚轮H</th>
            <th className="w-24 px-3 py-2">X</th>
            <th className="w-24 px-3 py-2">Y</th>
            <th className="px-3 py-2">摘要</th>
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 ? (
            <tr>
              <td colSpan={12} className="px-3 py-6 text-center text-muted-foreground">暂无鼠标事件</td>
            </tr>
          ) : (
            rows.map((row) => (
              <tr key={`${row.packetId}-${row.positionX}-${row.positionY}`} className="border-b border-border/70 align-top">
                <td className="px-3 py-2 font-mono text-muted-foreground">{row.packetId}</td>
                <td className="px-3 py-2 font-mono">{row.time || "--"}</td>
                <td className="px-3 py-2">{row.device || "--"}</td>
                <td className="px-3 py-2 font-mono">{row.endpoint || "--"}</td>
                <td className="px-3 py-2">{row.buttons.join(", ") || "--"}</td>
                <td className="px-3 py-2 font-mono">{row.xDelta}</td>
                <td className="px-3 py-2 font-mono">{row.yDelta}</td>
                <td className="px-3 py-2 font-mono">{row.wheelVertical}</td>
                <td className="px-3 py-2 font-mono">{row.wheelHorizontal}</td>
                <td className="px-3 py-2 font-mono">{row.positionX}</td>
                <td className="px-3 py-2 font-mono">{row.positionY}</td>
                <td className="px-3 py-2">{row.summary || "--"}</td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}

function USBRecordTable({ rows }: { rows: USBPacketRecord[] }) {
  return (
    <div className="max-h-[560px] overflow-auto">
      <table className="w-full table-fixed border-collapse text-left text-xs">
        <thead className="sticky top-0 bg-accent/90 text-muted-foreground shadow-[0_1px_0_0_var(--color-border)]">
          <tr>
            <th className="w-20 px-3 py-2">包号</th>
            <th className="w-28 px-3 py-2">时间</th>
            <th className="w-24 px-3 py-2">协议</th>
            <th className="w-28 px-3 py-2">设备</th>
            <th className="w-28 px-3 py-2">端点</th>
            <th className="w-20 px-3 py-2">方向</th>
            <th className="w-24 px-3 py-2">传输</th>
            <th className="w-24 px-3 py-2">URB</th>
            <th className="w-24 px-3 py-2">状态</th>
            <th className="w-20 px-3 py-2">长度</th>
            <th className="w-28 px-3 py-2">Setup</th>
            <th className="px-3 py-2">摘要</th>
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 ? (
            <tr>
              <td colSpan={12} className="px-3 py-6 text-center text-muted-foreground">暂无其他 USB 记录</td>
            </tr>
          ) : (
            rows.map((item) => (
              <tr key={`${item.packetId}-${item.endpoint}-${item.summary}`} className="border-b border-border/70 align-top">
                <td className="px-3 py-2 font-mono text-muted-foreground">{item.packetId}</td>
                <td className="px-3 py-2 font-mono">{item.time || "--"}</td>
                <td className="px-3 py-2">{item.protocol || "--"}</td>
                <td className="px-3 py-2">{joinParts(item.busId, item.deviceAddress)}</td>
                <td className="px-3 py-2 font-mono">{item.endpoint || "--"}</td>
                <td className="px-3 py-2">{item.direction || "--"}</td>
                <td className="px-3 py-2">{item.transferType || "--"}</td>
                <td className="px-3 py-2">{item.urbType || "--"}</td>
                <td className="px-3 py-2">{item.status || "--"}</td>
                <td className="px-3 py-2 font-mono">{item.dataLength}</td>
                <td className="px-3 py-2">{item.setupRequest || "--"}</td>
                <td className="px-3 py-2">
                  <div>{item.summary || "--"}</div>
                  {item.payloadPreview && (
                    <div className="mt-1 break-all font-mono text-[11px] text-muted-foreground">{item.payloadPreview}</div>
                  )}
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}

function keyboardReplayToken(event: USBKeyboardEvent) {
  if (event.text) {
    return event.text;
  }
  return `[${event.summary}] `;
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

function joinParts(busId: string, deviceAddress: string) {
  const parts = [busId && `bus ${busId}`, deviceAddress && `dev ${deviceAddress}`].filter(Boolean);
  return parts.length > 0 ? parts.join(" / ") : "--";
}

function EmptyState({ children }: { children: ReactNode }) {
  return <div className="rounded border border-dashed border-border px-3 py-6 text-center text-xs text-muted-foreground">{children}</div>;
}

function StatCard({ title, value }: { title: string; value: string }) {
  return (
    <div className="rounded-xl border border-border bg-card p-4 shadow-sm">
      <div className="mb-2 text-xs text-muted-foreground">{title}</div>
      <div className="text-lg font-semibold">{value}</div>
    </div>
  );
}

function Panel({ title, children, className = "" }: { title: string; children: ReactNode; className?: string }) {
  return (
    <div className={`rounded-xl border border-border bg-card p-4 shadow-sm ${className}`.trim()}>
      <div className="mb-3 text-sm font-semibold">{title}</div>
      {children}
    </div>
  );
}

function BucketChart({ data, color }: { data: TrafficBucket[]; color: string }) {
  const max = Math.max(1, ...data.map((item) => item.count));
  if (data.length === 0) {
    return <EmptyState>暂无数据</EmptyState>;
  }
  return (
    <div className="max-h-[420px] overflow-auto pr-1">
      <div className="space-y-2">
        {data.map((row) => (
          <div key={row.label} className="grid grid-cols-[220px_1fr_72px] items-center gap-2 text-xs">
            <div className="truncate text-muted-foreground" title={row.label}>{row.label}</div>
            <div className="h-2 rounded bg-accent">
              <div className={`h-2 rounded ${color}`} style={{ width: `${Math.max(2, (row.count / max) * 100)}%` }} />
            </div>
            <div className="text-right font-mono">{row.count}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

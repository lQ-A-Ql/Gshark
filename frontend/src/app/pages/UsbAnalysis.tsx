import { ChevronLeft, ChevronRight, HardDrive, Keyboard, Pause, Play, Route, Usb, Workflow } from "lucide-react";
import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import { AnalysisHero } from "../components/AnalysisHero";
import { PageShell } from "../components/PageShell";
import {
  AnalysisBucketChart as BucketChart,
  AnalysisDataTable as DataTable,
  AnalysisPanel as Panel,
  AnalysisStatCard as StatCard,
} from "../components/analysis/AnalysisPrimitives";
import type {
  USBAnalysis as USBAnalysisData,
  USBKeyboardEvent,
  USBMassStorageOperation,
  USBMouseEvent,
  USBPacketRecord,
} from "../core/types";
import { useUsbAnalysis } from "../features/usb/useUsbAnalysis";
import { useSentinel } from "../state/SentinelContext";

type UsbPrimaryTab = "hid" | "mass-storage" | "other";
type HidSubTab = "keyboard" | "mouse";
type MassStorageSubTab = "overview" | "read" | "write";
type OtherSubTab = "overview" | "control" | "raw";

const USB_PROTOCOL_TAGS = ["HID", "Mass Storage", "其他"];
const USB_TABLE_WRAPPER_CLASS = "border-slate-200 bg-white shadow-sm";
const USB_TABLE_HEADER_CLASS = "bg-gradient-to-r from-slate-100 to-blue-50 text-slate-700";
const USB_TABLE_ROW_CLASS = "last:border-b-0 odd:bg-white even:bg-slate-50/45 hover:bg-blue-50/45";
const USB_MONO_CELL_CLASS = "font-mono text-slate-600";

export default function UsbAnalysis() {
  const { backendConnected, isPreloadingCapture, fileMeta, totalPackets, captureRevision } = useSentinel();
  const { analysis, loading, error, refreshAnalysis } = useUsbAnalysis({
    backendConnected,
    isPreloadingCapture,
    filePath: fileMeta.path,
    totalPackets,
    captureRevision,
  });

  const [activePrimaryTab, setActivePrimaryTab] = useState<UsbPrimaryTab>("hid");
  const [activeHidSubTab, setActiveHidSubTab] = useState<HidSubTab>("keyboard");
  const [activeMassStorageSubTab, setActiveMassStorageSubTab] = useState<MassStorageSubTab>("overview");
  const [activeOtherSubTab, setActiveOtherSubTab] = useState<OtherSubTab>("overview");
  const [activeKeyboardDevice, setActiveKeyboardDevice] = useState("");
  const [keyboardCursor, setKeyboardCursor] = useState(0);
  const [isKeyboardPlaying, setIsKeyboardPlaying] = useState(false);
  const [activeMouseDevice, setActiveMouseDevice] = useState("");
  const [activeMassStorageDevice, setActiveMassStorageDevice] = useState("all");
  const [activeMassStorageLUN, setActiveMassStorageLUN] = useState("all");

  const hidKeyboardEvents = useMemo(
    () => (analysis.hid.keyboardEvents.length > 0 ? analysis.hid.keyboardEvents : analysis.keyboardEvents),
    [analysis.hid.keyboardEvents, analysis.keyboardEvents],
  );
  const hidMouseEvents = useMemo(
    () => (analysis.hid.mouseEvents.length > 0 ? analysis.hid.mouseEvents : analysis.mouseEvents),
    [analysis.hid.mouseEvents, analysis.mouseEvents],
  );
  const hidNotes = analysis.hid.notes.length > 0 ? analysis.hid.notes : analysis.notes;
  const otherRecords = useMemo(
    () => (analysis.other.records.length > 0 ? analysis.other.records : analysis.otherRecords),
    [analysis.other.records, analysis.otherRecords],
  );
  const controlRecords = analysis.other.controlRecords;
  const otherNotes = analysis.other.notes.length > 0 ? analysis.other.notes : analysis.notes;
  const readOperations = analysis.massStorage.readOperations;
  const writeOperations = analysis.massStorage.writeOperations;
  const massStorageNotes = analysis.massStorage.notes.length > 0 ? analysis.massStorage.notes : analysis.notes;
  const allMassStorageOperations = useMemo(() => [...readOperations, ...writeOperations], [readOperations, writeOperations]);

  useEffect(() => {
    setActivePrimaryTab((prev) => (domainHasData(analysis, prev) ? prev : pickDefaultPrimaryTab(analysis)));
    setActiveHidSubTab((prev) => {
      if (prev === "keyboard" && hidKeyboardEvents.length > 0) return prev;
      if (prev === "mouse" && hidMouseEvents.length > 0) return prev;
      return hidKeyboardEvents.length > 0 ? "keyboard" : "mouse";
    });
  }, [analysis, hidKeyboardEvents.length, hidMouseEvents.length]);

  const keyboardDevices = useMemo(() => uniqueStrings(hidKeyboardEvents.map((item) => item.device || item.endpoint).filter(Boolean)), [hidKeyboardEvents]);
  const mouseDevices = useMemo(() => uniqueStrings(hidMouseEvents.map((item) => item.device || item.endpoint).filter(Boolean)), [hidMouseEvents]);
  const massStorageDevices = useMemo(() => uniqueStrings(allMassStorageOperations.map((item) => item.device).filter(Boolean)), [allMassStorageOperations]);
  const massStorageLUNs = useMemo(() => uniqueStrings(allMassStorageOperations.map((item) => item.lun).filter(Boolean)), [allMassStorageOperations]);

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

  useEffect(() => {
    if (massStorageDevices.length === 0) {
      setActiveMassStorageDevice("all");
      return;
    }
    setActiveMassStorageDevice((prev) => (prev === "all" || massStorageDevices.includes(prev) ? prev : "all"));
  }, [massStorageDevices]);

  useEffect(() => {
    if (massStorageLUNs.length === 0) {
      setActiveMassStorageLUN("all");
      return;
    }
    setActiveMassStorageLUN((prev) => (prev === "all" || massStorageLUNs.includes(prev) ? prev : "all"));
  }, [massStorageLUNs]);

  const filteredKeyboardEvents = useMemo(() => {
    if (!activeKeyboardDevice) return hidKeyboardEvents;
    return hidKeyboardEvents.filter((item) => (item.device || item.endpoint) === activeKeyboardDevice);
  }, [activeKeyboardDevice, hidKeyboardEvents]);

  const filteredMouseEvents = useMemo(() => {
    if (!activeMouseDevice) return hidMouseEvents;
    return hidMouseEvents.filter((item) => (item.device || item.endpoint) === activeMouseDevice);
  }, [activeMouseDevice, hidMouseEvents]);

  const massStorageFilter = useCallback(
    (rows: USBMassStorageOperation[]) =>
      rows.filter((item) => {
        const deviceMatch = activeMassStorageDevice === "all" || item.device === activeMassStorageDevice;
        const lunMatch = activeMassStorageLUN === "all" || item.lun === activeMassStorageLUN;
        return deviceMatch && lunMatch;
      }),
    [activeMassStorageDevice, activeMassStorageLUN],
  );
  const filteredReadOperations = useMemo(() => massStorageFilter(readOperations), [massStorageFilter, readOperations]);
  const filteredWriteOperations = useMemo(() => massStorageFilter(writeOperations), [massStorageFilter, writeOperations]);

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
    const uniqueKeys = new Set(filteredKeyboardEvents.flatMap((item) => [...item.keys, ...item.pressedKeys, ...item.releasedKeys]));
    return {
      printableCount: filteredKeyboardEvents.filter((item) => Boolean(item.text && item.text.length > 0)).length,
      comboCount: filteredKeyboardEvents.filter((item) => item.modifiers.length > 0).length,
      uniqueKeyCount: uniqueKeys.size,
    };
  }, [filteredKeyboardEvents]);

  const mouseStats = useMemo(() => {
    let distance = 0;
    let buttonActions = 0;
    let wheelCount = 0;
    for (const event of filteredMouseEvents) {
      distance += Math.hypot(event.xDelta, event.yDelta);
      buttonActions += event.pressedButtons.length + event.releasedButtons.length;
      if (event.wheelVertical !== 0 || event.wheelHorizontal !== 0) {
        wheelCount += 1;
      }
    }
    return {
      distance: Math.round(distance),
      buttonActions,
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
    return text || "(未解析到可打印字符，仍可查看下方按键行为表)";
  }, [filteredKeyboardEvents]);
  const keyboardReplayText = useMemo(() => {
    if (filteredKeyboardEvents.length === 0) {
      return "(未解析到键盘行为)";
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
    <PageShell className="bg-[radial-gradient(circle_at_top,rgba(34,211,238,0.26),transparent_36%),linear-gradient(180deg,#f0fdff_0%,#f6faff_44%,#f8fafc_100%)]">
      <AnalysisHero
        icon={<Usb className="h-5 w-5" />}
        title="USB 行为分析"
        subtitle="USB BEHAVIOR ANALYTICS"
        description="按 HID、Mass Storage 与其他 USB 域统一编排页面，分别查看键入行为、鼠标按键行为、闪存读写与控制请求。"
        tags={USB_PROTOCOL_TAGS}
        tagsLabel="分析域"
        theme="cyan"
        onRefresh={() => refreshAnalysis(true)}
      />

      {loading && <Banner tone="muted">正在解析 USB / HID / Mass Storage 数据...</Banner>}
      {!loading && error && <Banner tone="warning">{error}</Banner>}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
        <StatCard title="USB 包总数" value={analysis.totalUSBPackets.toLocaleString()} />
        <StatCard title="HID" value={String(analysis.hidPackets || analysis.keyboardPackets + analysis.mousePackets)} />
        <StatCard title="Mass Storage" value={String(analysis.massStoragePackets)} />
        <StatCard title="其他" value={analysis.otherUSBPackets.toLocaleString()} />
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Panel title="协议分布">
          <BucketChart data={analysis.protocols} barClassName="bg-blue-500" />
        </Panel>
        <Panel title="传输类型">
          <BucketChart data={analysis.transferTypes} barClassName="bg-emerald-500" />
        </Panel>
        <Panel title="分析提示">
          <NotesList notes={analysis.notes} emptyLabel="当前抓包未识别到可展示的 USB 行为。" />
        </Panel>
      </div>

      <div className="mt-4 flex flex-wrap items-center gap-2">
        <PrimaryTabButton active={activePrimaryTab === "hid"} onClick={() => setActivePrimaryTab("hid")} icon={<Keyboard className="h-4 w-4" />}>
          HID
        </PrimaryTabButton>
        <PrimaryTabButton active={activePrimaryTab === "mass-storage"} onClick={() => setActivePrimaryTab("mass-storage")} icon={<HardDrive className="h-4 w-4" />}>
          Mass Storage
        </PrimaryTabButton>
        <PrimaryTabButton active={activePrimaryTab === "other"} onClick={() => setActivePrimaryTab("other")} icon={<Usb className="h-4 w-4" />}>
          其他
        </PrimaryTabButton>
      </div>

      {activePrimaryTab === "hid" && (
        <div className="mt-4 space-y-4">
          <div className="flex flex-wrap items-center gap-2">
            <SecondaryTabButton active={activeHidSubTab === "keyboard"} onClick={() => setActiveHidSubTab("keyboard")}>
              键盘
            </SecondaryTabButton>
            <SecondaryTabButton active={activeHidSubTab === "mouse"} onClick={() => setActiveHidSubTab("mouse")}>
              鼠标
            </SecondaryTabButton>
          </div>

          {activeHidSubTab === "keyboard" && (
            <>
              <DeviceChips
                devices={keyboardDevices}
                activeDevice={activeKeyboardDevice}
                emptyLabel="未检测到键盘设备"
                onSelect={setActiveKeyboardDevice}
              />

              <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
                <StatCard title="当前设备事件" value={filteredKeyboardEvents.length.toLocaleString()} />
                <StatCard title="可打印输入" value={keyboardStats.printableCount.toLocaleString()} />
                <StatCard title="组合键事件" value={keyboardStats.comboCount.toLocaleString()} />
                <StatCard title="唯一按键" value={keyboardStats.uniqueKeyCount.toLocaleString()} />
              </div>

              <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1.15fr)_minmax(0,0.85fr)]">
                <Panel title="键入行为">
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
                <Panel title="完整文本流">
                  <pre className="max-h-[260px] overflow-auto whitespace-pre-wrap break-all rounded-md border border-border bg-background px-3 py-3 font-mono text-xs leading-5">
                    {keyboardTextPreview}
                  </pre>
                </Panel>
              </div>

              <Panel title={`按键行为 (${filteredKeyboardEvents.length})`}>
                <KeyboardEventTable rows={filteredKeyboardEvents} />
              </Panel>
              <Panel title="HID 提示">
                <NotesList notes={hidNotes} emptyLabel="暂无 HID 提示" />
              </Panel>
            </>
          )}

          {activeHidSubTab === "mouse" && (
            <>
              <DeviceChips
                devices={mouseDevices}
                activeDevice={activeMouseDevice}
                emptyLabel="未检测到鼠标设备"
                onSelect={setActiveMouseDevice}
              />

              <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
                <StatCard title="事件数" value={filteredMouseEvents.length.toLocaleString()} />
                <StatCard title="轨迹总路程" value={`${mouseStats.distance}`} />
                <StatCard title="按钮动作数" value={`${mouseStats.buttonActions}`} />
                <StatCard title="滚轮事件数" value={`${mouseStats.wheelCount}`} />
              </div>

              <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
                <Panel title="轨迹图">
                  <MouseTrajectory events={filteredMouseEvents} />
                </Panel>
                <Panel title="按键行为">
                  <MouseBehaviorList rows={filteredMouseEvents.slice(-18).reverse()} />
                </Panel>
              </div>

              <Panel title="热区图">
                <MouseHeatmap events={filteredMouseEvents} />
              </Panel>

              <Panel title={`行为明细表 (${filteredMouseEvents.length})`}>
                <MouseEventTable rows={filteredMouseEvents} />
              </Panel>
            </>
          )}
        </div>
      )}

      {activePrimaryTab === "mass-storage" && (
        <div className="mt-4 space-y-4">
          <div className="flex flex-wrap items-center gap-2">
            <SecondaryTabButton active={activeMassStorageSubTab === "overview"} onClick={() => setActiveMassStorageSubTab("overview")}>
              概览
            </SecondaryTabButton>
            <SecondaryTabButton active={activeMassStorageSubTab === "read"} onClick={() => setActiveMassStorageSubTab("read")}>
              读请求
            </SecondaryTabButton>
            <SecondaryTabButton active={activeMassStorageSubTab === "write"} onClick={() => setActiveMassStorageSubTab("write")}>
              写请求
            </SecondaryTabButton>
          </div>

          {activeMassStorageSubTab === "overview" && (
            <>
              <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
                <StatCard title="总存储包" value={analysis.massStorage.totalPackets.toLocaleString()} />
                <StatCard title="读请求数" value={analysis.massStorage.readPackets.toLocaleString()} />
                <StatCard title="写请求数" value={analysis.massStorage.writePackets.toLocaleString()} />
                <StatCard title="LUN 数" value={String(analysis.massStorage.luns.length)} />
              </div>

              <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
                <Panel title="命令分布">
                  <BucketChart data={analysis.massStorage.commands} barClassName="bg-cyan-500" />
                </Panel>
                <Panel title="设备分布">
                  <BucketChart data={analysis.massStorage.devices} barClassName="bg-violet-500" />
                </Panel>
                <Panel title="分析提示">
                  <NotesList notes={massStorageNotes} emptyLabel="暂无存储域提示" />
                </Panel>
              </div>
            </>
          )}

          {(activeMassStorageSubTab === "read" || activeMassStorageSubTab === "write") && (
            <>
              <MassStorageFilters
                devices={massStorageDevices}
                luns={massStorageLUNs}
                activeDevice={activeMassStorageDevice}
                activeLun={activeMassStorageLUN}
                onDeviceChange={setActiveMassStorageDevice}
                onLunChange={setActiveMassStorageLUN}
              />
              <Panel title={activeMassStorageSubTab === "read" ? `读请求 (${filteredReadOperations.length})` : `写请求 (${filteredWriteOperations.length})`}>
                <MassStorageOperationTable rows={activeMassStorageSubTab === "read" ? filteredReadOperations : filteredWriteOperations} />
              </Panel>
            </>
          )}
        </div>
      )}

      {activePrimaryTab === "other" && (
        <div className="mt-4 space-y-4">
          <div className="flex flex-wrap items-center gap-2">
            <SecondaryTabButton active={activeOtherSubTab === "overview"} onClick={() => setActiveOtherSubTab("overview")}>
              概览
            </SecondaryTabButton>
            <SecondaryTabButton active={activeOtherSubTab === "control"} onClick={() => setActiveOtherSubTab("control")}>
              控制请求
            </SecondaryTabButton>
            <SecondaryTabButton active={activeOtherSubTab === "raw"} onClick={() => setActiveOtherSubTab("raw")}>
              原始记录
            </SecondaryTabButton>
          </div>

          {activeOtherSubTab === "overview" && (
            <>
              <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
                <StatCard title="其他 USB 包" value={analysis.other.totalPackets.toLocaleString()} />
                <StatCard title="设备数" value={String(analysis.other.devices.length)} />
                <StatCard title="端点数" value={String(analysis.other.endpoints.length)} />
                <StatCard title="Setup 请求数" value={String(analysis.other.setupRequests.reduce((sum, item) => sum + item.count, 0))} />
              </div>

              <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
                <Panel title="设备分布">
                  <BucketChart data={analysis.other.devices} barClassName="bg-amber-500" />
                </Panel>
                <Panel title="端点分布">
                  <BucketChart data={analysis.other.endpoints} barClassName="bg-slate-500" />
                </Panel>
                <Panel title="Setup 请求分布">
                  <BucketChart data={analysis.other.setupRequests} barClassName="bg-rose-500" />
                </Panel>
              </div>

              <Panel title="其他域提示">
                <NotesList notes={otherNotes} emptyLabel="暂无其他域提示" />
              </Panel>
            </>
          )}

          {activeOtherSubTab === "control" && (
            <Panel title={`控制请求 (${controlRecords.length})`}>
              <ControlRequestTable rows={controlRecords} />
            </Panel>
          )}

          {activeOtherSubTab === "raw" && (
            <Panel title={`原始记录 (${otherRecords.length})`}>
              <USBRecordTable rows={otherRecords} />
            </Panel>
          )}
        </div>
      )}
    </PageShell>
  );
}

function domainHasData(analysis: USBAnalysisData, tab: UsbPrimaryTab) {
  switch (tab) {
    case "hid":
      return (
        analysis.hidPackets > 0 ||
        analysis.keyboardPackets > 0 ||
        analysis.mousePackets > 0 ||
        analysis.keyboardEvents.length > 0 ||
        analysis.mouseEvents.length > 0 ||
        analysis.hid.keyboardEvents.length > 0 ||
        analysis.hid.mouseEvents.length > 0 ||
        analysis.hid.devices.length > 0
      );
    case "mass-storage":
      return (
        analysis.massStoragePackets > 0 ||
        analysis.massStorage.totalPackets > 0 ||
        analysis.massStorage.readOperations.length > 0 ||
        analysis.massStorage.writeOperations.length > 0 ||
        analysis.massStorage.devices.length > 0 ||
        analysis.massStorage.commands.length > 0
      );
    case "other":
      return (
        analysis.otherUSBPackets > 0 ||
        analysis.other.totalPackets > 0 ||
        analysis.otherRecords.length > 0 ||
        analysis.other.records.length > 0 ||
        analysis.other.controlRecords.length > 0 ||
        analysis.other.setupRequests.length > 0
      );
    default:
      return false;
  }
}

function pickDefaultPrimaryTab(analysis: USBAnalysisData): UsbPrimaryTab {
  if (domainHasData(analysis, "hid")) return "hid";
  if (domainHasData(analysis, "mass-storage")) return "mass-storage";
  return "other";
}

function PrimaryTabButton({
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
      type="button"
      onClick={onClick}
      className={`inline-flex items-center gap-2 rounded-full border px-4 py-2 text-sm transition-colors ${active ? "border-blue-500 bg-blue-50 text-blue-700" : "border-border bg-card text-muted-foreground hover:bg-accent hover:text-foreground"}`}
    >
      {icon}
      {children}
    </button>
  );
}

function SecondaryTabButton({ active, onClick, children }: { active: boolean; onClick: () => void; children: ReactNode }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`rounded-full border px-3 py-1.5 text-xs transition-colors ${active ? "border-cyan-500 bg-cyan-50 text-cyan-700" : "border-border bg-card text-muted-foreground hover:bg-accent hover:text-foreground"}`}
    >
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
            type="button"
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
    return <EmptyState>暂无键盘行为</EmptyState>;
  }

  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-border bg-[linear-gradient(180deg,#eff6ff,#f8fafc)] p-4">
        <div className="flex flex-wrap items-center gap-2">
          <button type="button" onClick={onPrev} className="inline-flex h-9 w-9 items-center justify-center rounded-full border border-border bg-card text-foreground hover:bg-accent">
            <ChevronLeft className="h-4 w-4" />
          </button>
          <button type="button" onClick={onTogglePlay} className="inline-flex h-9 w-9 items-center justify-center rounded-full border border-blue-500 bg-blue-600 text-white hover:bg-blue-700">
            {isPlaying ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
          </button>
          <button type="button" onClick={onNext} className="inline-flex h-9 w-9 items-center justify-center rounded-full border border-border bg-card text-foreground hover:bg-accent">
            <ChevronRight className="h-4 w-4" />
          </button>
          <div className="ml-auto text-xs text-muted-foreground">
            第 <span className="font-mono text-foreground">{Math.min(currentIndex + 1, total)}</span> / <span className="font-mono text-foreground">{total}</span> 条
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
            return <circle key={`${item.x}-${item.y}`} cx={item.x} cy={item.y} r={radius} fill={`rgba(37,99,235,${opacity})`} />;
          })}
          {hotspots.filter((item) => item.clicks > 0).map((item) => (
            <circle key={`click-${item.x}-${item.y}`} cx={item.x} cy={item.y} r={6 + Math.min(item.clicks, 4) * 2} fill="rgba(220,38,38,0.55)" stroke="rgba(185,28,28,0.9)" strokeWidth="1.5" />
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

function MouseBehaviorList({ rows }: { rows: USBMouseEvent[] }) {
  if (rows.length === 0) {
    return <EmptyState>暂无鼠标行为</EmptyState>;
  }
  return (
    <div className="max-h-[320px] space-y-2 overflow-auto">
      {rows.map((row) => (
        <div key={`${row.packetId}-${row.positionX}-${row.positionY}`} className="rounded-lg border border-border bg-background px-3 py-2 text-xs">
          <div className="flex items-center justify-between gap-2">
            <span className="font-mono text-muted-foreground">#{row.packetId} {row.time}</span>
            <span className="rounded border border-border px-2 py-0.5 text-[11px]">{mouseActionBadge(row)}</span>
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
    <DataTable<USBKeyboardEvent>
      data={rows}
      rowKey={(row, index) => `${row.packetId}-${row.summary}-${index}`}
      maxHeightClassName="max-h-[520px]"
      wrapperClassName={USB_TABLE_WRAPPER_CLASS}
      headerClassName={USB_TABLE_HEADER_CLASS}
      tableClassName="min-w-[1180px]"
      rowClassName={USB_TABLE_ROW_CLASS}
      emptyText="暂无键盘行为"
      columns={[
        { key: "packet", header: "包号", widthClassName: "w-20", cellClassName: USB_MONO_CELL_CLASS, render: (row) => row.packetId },
        { key: "time", header: "时间", widthClassName: "w-28", cellClassName: USB_MONO_CELL_CLASS, render: (row) => row.time || "--" },
        { key: "device", header: "设备", widthClassName: "w-40", render: (row) => row.device || row.endpoint || "--" },
        { key: "modifiers", header: "当前修饰键", widthClassName: "w-28", render: (row) => row.modifiers.join(", ") || "--" },
        { key: "pressedModifiers", header: "按下修饰键", widthClassName: "w-28", render: (row) => row.pressedModifiers.join(", ") || "--" },
        { key: "releasedModifiers", header: "释放修饰键", widthClassName: "w-28", render: (row) => row.releasedModifiers.join(", ") || "--" },
        { key: "keys", header: "当前按键", widthClassName: "w-32", render: (row) => row.keys.join(", ") || "--" },
        { key: "pressedKeys", header: "按下键", widthClassName: "w-32", render: (row) => row.pressedKeys.join(", ") || "--" },
        { key: "releasedKeys", header: "释放键", widthClassName: "w-32", render: (row) => row.releasedKeys.join(", ") || "--" },
        { key: "text", header: "文本", widthClassName: "w-24", cellClassName: "whitespace-pre-wrap font-mono text-slate-600", render: (row) => row.text || "--" },
        { key: "summary", header: "摘要", render: (row) => row.summary || "--" },
      ]}
    />
  );
}

function MouseEventTable({ rows }: { rows: USBMouseEvent[] }) {
  return (
    <DataTable<USBMouseEvent>
      data={rows}
      rowKey={(row, index) => `${row.packetId}-${row.positionX}-${row.positionY}-${index}`}
      maxHeightClassName="max-h-[520px]"
      wrapperClassName={USB_TABLE_WRAPPER_CLASS}
      headerClassName={USB_TABLE_HEADER_CLASS}
      tableClassName="min-w-[1260px]"
      rowClassName={USB_TABLE_ROW_CLASS}
      emptyText="暂无鼠标行为"
      columns={[
        { key: "packet", header: "包号", widthClassName: "w-20", cellClassName: USB_MONO_CELL_CLASS, render: (row) => row.packetId },
        { key: "time", header: "时间", widthClassName: "w-28", cellClassName: USB_MONO_CELL_CLASS, render: (row) => row.time || "--" },
        { key: "device", header: "设备", widthClassName: "w-36", render: (row) => row.device || row.endpoint || "--" },
        { key: "buttons", header: "当前按钮", widthClassName: "w-28", render: (row) => row.buttons.join(", ") || "--" },
        { key: "pressedButtons", header: "按下按钮", widthClassName: "w-28", render: (row) => row.pressedButtons.join(", ") || "--" },
        { key: "releasedButtons", header: "释放按钮", widthClassName: "w-28", render: (row) => row.releasedButtons.join(", ") || "--" },
        { key: "xDelta", header: "dX", widthClassName: "w-20", cellClassName: USB_MONO_CELL_CLASS, render: (row) => row.xDelta },
        { key: "yDelta", header: "dY", widthClassName: "w-20", cellClassName: USB_MONO_CELL_CLASS, render: (row) => row.yDelta },
        { key: "wheelVertical", header: "滚轮V", widthClassName: "w-20", cellClassName: USB_MONO_CELL_CLASS, render: (row) => row.wheelVertical },
        { key: "wheelHorizontal", header: "滚轮H", widthClassName: "w-20", cellClassName: USB_MONO_CELL_CLASS, render: (row) => row.wheelHorizontal },
        { key: "positionX", header: "X", widthClassName: "w-24", cellClassName: USB_MONO_CELL_CLASS, render: (row) => row.positionX },
        { key: "positionY", header: "Y", widthClassName: "w-24", cellClassName: USB_MONO_CELL_CLASS, render: (row) => row.positionY },
        { key: "summary", header: "摘要", render: (row) => row.summary || "--" },
      ]}
    />
  );
}

function MassStorageFilters({
  devices,
  luns,
  activeDevice,
  activeLun,
  onDeviceChange,
  onLunChange,
}: {
  devices: string[];
  luns: string[];
  activeDevice: string;
  activeLun: string;
  onDeviceChange: (value: string) => void;
  onLunChange: (value: string) => void;
}) {
  return (
    <div className="grid grid-cols-1 gap-4 rounded-xl border border-border bg-card p-4 shadow-sm md:grid-cols-2">
      <SelectField label="设备" value={activeDevice} onChange={onDeviceChange} options={["all", ...devices]} labels={{ all: "全部设备" }} />
      <SelectField label="LUN" value={activeLun} onChange={onLunChange} options={["all", ...luns]} labels={{ all: "全部 LUN" }} />
    </div>
  );
}

function SelectField({
  label,
  value,
  onChange,
  options,
  labels = {},
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  options: string[];
  labels?: Record<string, string>;
}) {
  return (
    <label className="flex flex-col gap-2 text-xs text-muted-foreground">
      <span>{label}</span>
      <select value={value} onChange={(event) => onChange(event.target.value)} className="rounded-lg border border-border bg-background px-3 py-2 text-sm text-foreground outline-none ring-0 transition-colors focus:border-blue-500">
        {options.map((option) => (
          <option key={option} value={option}>
            {labels[option] ?? option}
          </option>
        ))}
      </select>
    </label>
  );
}

function MassStorageOperationTable({ rows }: { rows: USBMassStorageOperation[] }) {
  return (
    <DataTable<USBMassStorageOperation>
      data={rows}
      rowKey={(row, index) => `${row.packetId}-${row.requestFrame}-${row.responseFrame}-${index}`}
      maxHeightClassName="max-h-[560px]"
      wrapperClassName={USB_TABLE_WRAPPER_CLASS}
      headerClassName={USB_TABLE_HEADER_CLASS}
      tableClassName="min-w-[1180px]"
      rowClassName={USB_TABLE_ROW_CLASS}
      emptyText="暂无读写行为记录"
      columns={[
        { key: "packet", header: "包号", widthClassName: "w-20", cellClassName: USB_MONO_CELL_CLASS, render: (row) => row.packetId },
        { key: "time", header: "时间", widthClassName: "w-24", cellClassName: USB_MONO_CELL_CLASS, render: (row) => row.time || "--" },
        { key: "device", header: "设备", widthClassName: "w-36", render: (row) => row.device || "--" },
        { key: "endpoint", header: "端点", widthClassName: "w-24", cellClassName: USB_MONO_CELL_CLASS, render: (row) => row.endpoint || "--" },
        { key: "lun", header: "LUN", widthClassName: "w-20", render: (row) => row.lun || "--" },
        { key: "command", header: "命令", widthClassName: "w-28", render: (row) => row.command || "--" },
        { key: "length", header: "长度", widthClassName: "w-16", cellClassName: USB_MONO_CELL_CLASS, render: (row) => row.transferLength },
        { key: "status", header: "状态", widthClassName: "w-20", render: (row) => row.status || "--" },
        { key: "requestFrame", header: "请求帧", widthClassName: "w-20", cellClassName: USB_MONO_CELL_CLASS, render: (row) => row.requestFrame ?? "--" },
        { key: "responseFrame", header: "响应帧", widthClassName: "w-20", cellClassName: USB_MONO_CELL_CLASS, render: (row) => row.responseFrame ?? "--" },
        { key: "latency", header: "延迟", widthClassName: "w-20", cellClassName: USB_MONO_CELL_CLASS, render: (row) => row.latencyMs == null ? "--" : `${row.latencyMs.toFixed(2)} ms` },
        {
          key: "summary",
          header: "摘要",
          render: (row) => (
            <div>
              <div>{row.summary || "--"}</div>
              {row.dataResidue != null && row.dataResidue > 0 && <div className="mt-1 font-mono text-[11px] text-amber-600">residue={row.dataResidue}</div>}
            </div>
          ),
        },
      ]}
    />
  );
}

function ControlRequestTable({ rows }: { rows: USBPacketRecord[] }) {
  return (
    <DataTable<USBPacketRecord>
      data={rows}
      rowKey={(row, index) => `${row.packetId}-${row.summary}-${index}`}
      maxHeightClassName="max-h-[560px]"
      wrapperClassName={USB_TABLE_WRAPPER_CLASS}
      headerClassName={USB_TABLE_HEADER_CLASS}
      tableClassName="min-w-[880px]"
      rowClassName={USB_TABLE_ROW_CLASS}
      emptyText="暂无控制请求"
      columns={[
        { key: "packet", header: "包号", widthClassName: "w-20", cellClassName: USB_MONO_CELL_CLASS, render: (row) => row.packetId },
        { key: "time", header: "时间", widthClassName: "w-28", cellClassName: USB_MONO_CELL_CLASS, render: (row) => row.time || "--" },
        { key: "device", header: "设备", widthClassName: "w-24", render: (row) => joinParts(row.busId, row.deviceAddress) },
        { key: "direction", header: "方向", widthClassName: "w-24", render: (row) => row.direction || "--" },
        { key: "status", header: "状态", widthClassName: "w-28", render: (row) => row.status || "--" },
        { key: "setup", header: "Setup 请求", widthClassName: "w-44", render: (row) => row.setupRequest || "--" },
        {
          key: "summary",
          header: "摘要 / Payload",
          render: (row) => (
            <div>
              <div>{row.summary || "--"}</div>
              {row.payloadPreview && <div className="mt-1 break-all font-mono text-[11px] text-slate-500">{row.payloadPreview}</div>}
            </div>
          ),
        },
      ]}
    />
  );
}

function USBRecordTable({ rows }: { rows: USBPacketRecord[] }) {
  return (
    <DataTable<USBPacketRecord>
      data={rows}
      rowKey={(item, index) => `${item.packetId}-${item.endpoint}-${item.summary}-${index}`}
      maxHeightClassName="max-h-[560px]"
      wrapperClassName={USB_TABLE_WRAPPER_CLASS}
      headerClassName={USB_TABLE_HEADER_CLASS}
      tableClassName="min-w-[1160px]"
      rowClassName={USB_TABLE_ROW_CLASS}
      emptyText="暂无其他 USB 记录"
      columns={[
        { key: "packet", header: "包号", widthClassName: "w-20", cellClassName: USB_MONO_CELL_CLASS, render: (item) => item.packetId },
        { key: "time", header: "时间", widthClassName: "w-28", cellClassName: USB_MONO_CELL_CLASS, render: (item) => item.time || "--" },
        { key: "protocol", header: "协议", widthClassName: "w-24", render: (item) => item.protocol || "--" },
        { key: "device", header: "设备", widthClassName: "w-28", render: (item) => joinParts(item.busId, item.deviceAddress) },
        { key: "endpoint", header: "端点", widthClassName: "w-28", cellClassName: USB_MONO_CELL_CLASS, render: (item) => item.endpoint || "--" },
        { key: "direction", header: "方向", widthClassName: "w-20", render: (item) => item.direction || "--" },
        { key: "transfer", header: "传输", widthClassName: "w-24", render: (item) => item.transferType || "--" },
        { key: "urb", header: "URB", widthClassName: "w-24", render: (item) => item.urbType || "--" },
        { key: "status", header: "状态", widthClassName: "w-24", render: (item) => item.status || "--" },
        { key: "length", header: "长度", widthClassName: "w-20", cellClassName: USB_MONO_CELL_CLASS, render: (item) => item.dataLength },
        { key: "setup", header: "Setup", widthClassName: "w-28", render: (item) => item.setupRequest || "--" },
        {
          key: "summary",
          header: "摘要",
          render: (item) => (
            <div>
              <div>{item.summary || "--"}</div>
              {item.payloadPreview && <div className="mt-1 break-all font-mono text-[11px] text-slate-500">{item.payloadPreview}</div>}
            </div>
          ),
        },
      ]}
    />
  );
}

function NotesList({ notes, emptyLabel }: { notes: string[]; emptyLabel: string }) {
  if (notes.length === 0) {
    return <EmptyState>{emptyLabel}</EmptyState>;
  }
  return (
    <div className="space-y-2 text-sm">
      {notes.map((note, index) => (
        <div key={`${note}-${index}`} className="flex items-start gap-2 rounded border border-border bg-background px-3 py-2">
          <Workflow className="mt-0.5 h-4 w-4 shrink-0 text-blue-600" />
          <span>{note}</span>
        </div>
      ))}
    </div>
  );
}

function keyboardReplayToken(event: USBKeyboardEvent) {
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

function uniqueStrings(values: string[]) {
  return Array.from(new Set(values));
}

function joinParts(busId: string, deviceAddress: string) {
  const parts = [busId && `bus ${busId}`, deviceAddress && `dev ${deviceAddress}`].filter(Boolean);
  return parts.length > 0 ? parts.join(" / ") : "--";
}

function EmptyState({ children }: { children: ReactNode }) {
  return <div className="rounded border border-dashed border-border px-3 py-6 text-center text-xs text-muted-foreground">{children}</div>;
}

function Banner({ children, tone }: { children: ReactNode; tone: "muted" | "warning" }) {
  const className = tone === "warning"
    ? "mb-3 rounded border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-700"
    : "mb-3 rounded border border-border bg-card px-3 py-2 text-xs text-muted-foreground";
  return <div className={className}>{children}</div>;
}



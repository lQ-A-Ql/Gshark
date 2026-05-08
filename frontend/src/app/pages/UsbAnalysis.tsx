import { HardDrive, Keyboard, Usb, Workflow } from "lucide-react";
import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import { AnalysisHero } from "../components/AnalysisHero";
import { PageShell } from "../components/PageShell";
import {
  AnalysisBucketChart as BucketChart,
  AnalysisPanel as Panel,
  AnalysisStatCard as StatCard,
} from "../components/analysis/AnalysisPrimitives";
import type { USBAnalysis as USBAnalysisData, USBMassStorageOperation } from "../core/types";
import {
  KeyboardReplay,
  MouseBehaviorList,
  MouseHeatmap,
  MouseTrajectory,
  keyboardReplayToken,
} from "../features/usb/UsbHidPanels";
import {
  ControlRequestTable,
  KeyboardEventTable,
  MassStorageFilters,
  MassStorageOperationTable,
  MouseEventTable,
  USBRecordTable,
} from "../features/usb/UsbTables";
import { useUsbAnalysis } from "../features/usb/useUsbAnalysis";
import { useSentinel } from "../state/SentinelContext";

type UsbPrimaryTab = "hid" | "mass-storage" | "other";
type HidSubTab = "keyboard" | "mouse";
type MassStorageSubTab = "overview" | "read" | "write";
type OtherSubTab = "overview" | "control" | "raw";

const USB_PROTOCOL_TAGS = ["HID", "Mass Storage", "其他"];

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
  const allMassStorageOperations = useMemo(
    () => [...readOperations, ...writeOperations],
    [readOperations, writeOperations],
  );

  useEffect(() => {
    setActivePrimaryTab((prev) => (domainHasData(analysis, prev) ? prev : pickDefaultPrimaryTab(analysis)));
    setActiveHidSubTab((prev) => {
      if (prev === "keyboard" && hidKeyboardEvents.length > 0) return prev;
      if (prev === "mouse" && hidMouseEvents.length > 0) return prev;
      return hidKeyboardEvents.length > 0 ? "keyboard" : "mouse";
    });
  }, [analysis, hidKeyboardEvents.length, hidMouseEvents.length]);

  const keyboardDevices = useMemo(
    () => uniqueStrings(hidKeyboardEvents.map((item) => item.device || item.endpoint).filter(Boolean)),
    [hidKeyboardEvents],
  );
  const mouseDevices = useMemo(
    () => uniqueStrings(hidMouseEvents.map((item) => item.device || item.endpoint).filter(Boolean)),
    [hidMouseEvents],
  );
  const massStorageDevices = useMemo(
    () => uniqueStrings(allMassStorageOperations.map((item) => item.device).filter(Boolean)),
    [allMassStorageOperations],
  );
  const massStorageLUNs = useMemo(
    () => uniqueStrings(allMassStorageOperations.map((item) => item.lun).filter(Boolean)),
    [allMassStorageOperations],
  );

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
  const filteredWriteOperations = useMemo(
    () => massStorageFilter(writeOperations),
    [massStorageFilter, writeOperations],
  );

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
    const uniqueKeys = new Set(
      filteredKeyboardEvents.flatMap((item) => [...item.keys, ...item.pressedKeys, ...item.releasedKeys]),
    );
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
        <PrimaryTabButton
          active={activePrimaryTab === "hid"}
          onClick={() => setActivePrimaryTab("hid")}
          icon={<Keyboard className="h-4 w-4" />}
        >
          HID
        </PrimaryTabButton>
        <PrimaryTabButton
          active={activePrimaryTab === "mass-storage"}
          onClick={() => setActivePrimaryTab("mass-storage")}
          icon={<HardDrive className="h-4 w-4" />}
        >
          Mass Storage
        </PrimaryTabButton>
        <PrimaryTabButton
          active={activePrimaryTab === "other"}
          onClick={() => setActivePrimaryTab("other")}
          icon={<Usb className="h-4 w-4" />}
        >
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
                    onNext={() =>
                      setKeyboardCursor((prev) => Math.min(prev + 1, Math.max(filteredKeyboardEvents.length - 1, 0)))
                    }
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
            <SecondaryTabButton
              active={activeMassStorageSubTab === "overview"}
              onClick={() => setActiveMassStorageSubTab("overview")}
            >
              概览
            </SecondaryTabButton>
            <SecondaryTabButton
              active={activeMassStorageSubTab === "read"}
              onClick={() => setActiveMassStorageSubTab("read")}
            >
              读请求
            </SecondaryTabButton>
            <SecondaryTabButton
              active={activeMassStorageSubTab === "write"}
              onClick={() => setActiveMassStorageSubTab("write")}
            >
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
              <Panel
                title={
                  activeMassStorageSubTab === "read"
                    ? `读请求 (${filteredReadOperations.length})`
                    : `写请求 (${filteredWriteOperations.length})`
                }
              >
                <MassStorageOperationTable
                  rows={activeMassStorageSubTab === "read" ? filteredReadOperations : filteredWriteOperations}
                />
              </Panel>
            </>
          )}
        </div>
      )}

      {activePrimaryTab === "other" && (
        <div className="mt-4 space-y-4">
          <div className="flex flex-wrap items-center gap-2">
            <SecondaryTabButton
              active={activeOtherSubTab === "overview"}
              onClick={() => setActiveOtherSubTab("overview")}
            >
              概览
            </SecondaryTabButton>
            <SecondaryTabButton
              active={activeOtherSubTab === "control"}
              onClick={() => setActiveOtherSubTab("control")}
            >
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
                <StatCard
                  title="Setup 请求数"
                  value={String(analysis.other.setupRequests.reduce((sum, item) => sum + item.count, 0))}
                />
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

function SecondaryTabButton({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: ReactNode;
}) {
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
        <span className="rounded border border-dashed border-border px-3 py-1.5 text-xs text-muted-foreground">
          {emptyLabel}
        </span>
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

function NotesList({ notes, emptyLabel }: { notes: string[]; emptyLabel: string }) {
  if (notes.length === 0) {
    return <EmptyState>{emptyLabel}</EmptyState>;
  }
  return (
    <div className="space-y-2 text-sm">
      {notes.map((note, index) => (
        <div
          key={`${note}-${index}`}
          className="flex items-start gap-2 rounded border border-border bg-background px-3 py-2"
        >
          <Workflow className="mt-0.5 h-4 w-4 shrink-0 text-blue-600" />
          <span>{note}</span>
        </div>
      ))}
    </div>
  );
}

function uniqueStrings(values: string[]) {
  return Array.from(new Set(values));
}

function EmptyState({ children }: { children: ReactNode }) {
  return (
    <div className="rounded border border-dashed border-border px-3 py-6 text-center text-xs text-muted-foreground">
      {children}
    </div>
  );
}

function Banner({ children, tone }: { children: ReactNode; tone: "muted" | "warning" }) {
  const className =
    tone === "warning"
      ? "mb-3 rounded border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-700"
      : "mb-3 rounded border border-border bg-card px-3 py-2 text-xs text-muted-foreground";
  return <div className={className}>{children}</div>;
}

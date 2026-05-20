import { useEffect, useMemo, useState } from "react";
import { AnalysisPanel as Panel, AnalysisStatCard as StatCard } from "../../components/analysis/AnalysisPrimitives";
import { Input } from "../../components/ui/input";
import { SelectField } from "../../components/ui/select";
import type { USBAnalysis, USBHIDSourceMode } from "../../core/types";
import { DeviceChips, NotesList } from "./UsbAnalysisControls";
import { MouseBehaviorList, MouseHeatmap, MouseTrajectoryView } from "./UsbHidPanels";
import { MouseEventTable } from "./UsbTables";
import { MOUSE_TRAJECTORY_HEIGHT, MOUSE_TRAJECTORY_WIDTH } from "./UsbMouseTrajectory";
import { buildMouseTrajectoryGeometry } from "./usbMouseGeometry";
import type { useUsbHidState } from "./useUsbHidState";

const HID_EVENT_LIMIT_MIN = 500;
const HID_EVENT_LIMIT_MAX = 100000;

const HID_SOURCE_OPTIONS: Array<{ value: USBHIDSourceMode; label: string; description: string }> = [
  { value: "auto", label: "自动", description: "按评分选择最佳 HID 字段" },
  { value: "usbhid", label: "usbhid.data", description: "USB HID dissector 数据" },
  { value: "capdata", label: "usb.capdata", description: "USB 捕获原始 payload" },
  { value: "btatt", label: "btatt.value", description: "蓝牙 HID payload" },
  { value: "raw", label: "raw fallback", description: "兜底原始流量候选" },
];

type UsbHidState = ReturnType<typeof useUsbHidState>;

export function UsbMousePanel({
  analysis,
  hidEventLimit,
  hidSource,
  onHidEventLimitChange,
  onHidSourceChange,
  state,
}: {
  analysis: USBAnalysis;
  hidEventLimit: number;
  hidSource: USBHIDSourceMode;
  onHidEventLimitChange: (limit: number) => void;
  onHidSourceChange: (source: USBHIDSourceMode) => void;
  state: UsbHidState;
}) {
  const trajectoryGeometry = useMemo(
    () =>
      buildMouseTrajectoryGeometry(
        state.filteredMouseEvents,
        MOUSE_TRAJECTORY_WIDTH,
        MOUSE_TRAJECTORY_HEIGHT,
        "recovered",
        "aspect",
      ),
    [state.filteredMouseEvents],
  );

  return (
    <>
      <HIDSourceSelector
        analysis={analysis}
        hidEventLimit={hidEventLimit}
        hidSource={hidSource}
        onHidEventLimitChange={onHidEventLimitChange}
        onHidSourceChange={onHidSourceChange}
      />
      <DeviceChips
        activeDevice={state.activeMouseDevice}
        devices={state.mouseDevices}
        emptyLabel="未检测到鼠标设备"
        onSelect={state.setActiveMouseDevice}
      />
      <div className="grid grid-cols-1 gap-0 lg:grid-cols-4">
        <StatCard title="事件数" value={state.filteredMouseEvents.length.toLocaleString()} />
        <StatCard title="轨迹总路程" value={`${state.mouseStats.distance}`} />
        <StatCard title="按钮动作数" value={`${state.mouseStats.buttonActions}`} />
        <StatCard title="滚轮事件数" value={`${state.mouseStats.wheelCount}`} />
      </div>
      <div className="grid grid-cols-1 gap-0 xl:grid-cols-2">
        <Panel title="混合轨迹图">
          {analysis.hidEventsTruncated ? (
            <div className="mb-3 rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-xs font-medium text-amber-700">
              轨迹已按事件上限截断
            </div>
          ) : null}
          <MouseTrajectoryView
            coordinateMode="recovered"
            events={state.filteredMouseEvents}
            geometry={trajectoryGeometry}
            scaleMode="aspect"
          />
        </Panel>
        <Panel title="按键行为">
          <MouseBehaviorList rows={state.filteredMouseEvents.slice(-18).reverse()} />
        </Panel>
      </div>
      <Panel title="热区图">
        <MouseHeatmap coordinateMode="recovered" events={state.filteredMouseEvents} />
      </Panel>
      <MouseSplitTrajectories events={state.filteredMouseEvents} geometry={trajectoryGeometry} />
      <Panel title="HID 数据源提示">
        <NotesList notes={analysis.hidSourceNotes} emptyLabel="暂无 HID 数据源提示" />
      </Panel>
      <Panel title={`行为明细表 (${state.filteredMouseEvents.length})`}>
        <MouseEventTable rows={state.filteredMouseEvents} resetKey={state.activeMouseDevice} />
      </Panel>
    </>
  );
}

function HIDSourceSelector({
  analysis,
  hidEventLimit,
  hidSource,
  onHidEventLimitChange,
  onHidSourceChange,
}: {
  analysis: USBAnalysis;
  hidEventLimit: number;
  hidSource: USBHIDSourceMode;
  onHidEventLimitChange: (limit: number) => void;
  onHidSourceChange: (source: USBHIDSourceMode) => void;
}) {
  const [draftLimit, setDraftLimit] = useState(String(hidEventLimit));

  useEffect(() => {
    setDraftLimit(String(hidEventLimit));
  }, [hidEventLimit]);

  const submitLimit = () => {
    const trimmed = draftLimit.trim();
    if (!/^\d+$/.test(trimmed)) {
      setDraftLimit(String(hidEventLimit));
      return;
    }
    const nextLimit = clampHIDEventLimit(Number(trimmed));
    setDraftLimit(String(nextLimit));
    if (nextLimit !== hidEventLimit) {
      onHidEventLimitChange(nextLimit);
    }
  };

  return (
    <div className="gshark-tile-toolbar space-y-3 px-3 py-3">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">HID 数据源</div>
          <div className="mt-1 text-sm text-foreground">
            当前：{analysis.hidSelectedSource ?? "未选择"} {analysis.hidSourceMode ? `(${analysis.hidSourceMode})` : ""}
          </div>
          {analysis.hidSourceCandidates.length > 0 && (
            <div className="mt-1 text-xs text-muted-foreground">候选：{analysis.hidSourceCandidates.join(" / ")}</div>
          )}
        </div>
        <div className="grid w-full gap-3 sm:w-auto sm:grid-cols-[minmax(190px,220px)_140px]">
          <SelectField
            fieldClassName="min-w-0"
            label="数据源"
            options={HID_SOURCE_OPTIONS}
            size="sm"
            tone="cyan"
            value={hidSource}
            onValueChange={(value) => onHidSourceChange(value as USBHIDSourceMode)}
          />
          <label className="flex flex-col gap-1.5 text-xs text-muted-foreground">
            <span className="font-semibold text-slate-600">事件上限</span>
            <Input
              aria-label="HID 事件上限"
              className="h-8 rounded-sm text-xs"
              inputMode="numeric"
              value={draftLimit}
              onBlur={submitLimit}
              onChange={(event) => setDraftLimit(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") {
                  event.currentTarget.blur();
                }
              }}
            />
          </label>
        </div>
      </div>
      {analysis.hidEventsTruncated ? (
        <div className="rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-xs leading-5 text-amber-800">
          HID 事件已达到当前上限 {analysis.hidEventLimit || hidEventLimit}。鼠标总事件{" "}
          {analysis.hidMouseEventsTotal.toLocaleString()}，键盘总事件 {analysis.hidKeyboardEventsTotal.toLocaleString()}
          ；可增加事件上限后重新加载完整轨迹。
        </div>
      ) : null}
    </div>
  );
}

function clampHIDEventLimit(limit: number) {
  if (limit < HID_EVENT_LIMIT_MIN) return HID_EVENT_LIMIT_MIN;
  if (limit > HID_EVENT_LIMIT_MAX) return HID_EVENT_LIMIT_MAX;
  return limit;
}

function MouseSplitTrajectories({
  events,
  geometry,
}: {
  events: UsbHidState["filteredMouseEvents"];
  geometry: ReturnType<typeof buildMouseTrajectoryGeometry>;
}) {
  return (
    <div className="grid grid-cols-1 gap-0 xl:grid-cols-3">
      <Panel title="左键轨迹图">
        <MouseTrajectoryView
          coordinateMode="recovered"
          emptyLabel="暂无左键轨迹数据"
          events={events}
          filterKind="left"
          geometry={geometry}
          renderMode="points"
          scaleMode="aspect"
        />
      </Panel>
      <Panel title="右键轨迹图">
        <MouseTrajectoryView
          coordinateMode="recovered"
          emptyLabel="暂无右键轨迹数据"
          events={events}
          filterKind="right"
          geometry={geometry}
          renderMode="points"
          scaleMode="aspect"
        />
      </Panel>
      <Panel title="无按键轨迹图">
        <MouseTrajectoryView
          coordinateMode="recovered"
          emptyLabel="暂无无按键轨迹数据"
          events={events}
          filterKind="none"
          geometry={geometry}
          renderMode="points"
          scaleMode="aspect"
        />
      </Panel>
    </div>
  );
}

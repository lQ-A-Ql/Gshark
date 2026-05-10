import { AnalysisPanel as Panel, AnalysisStatCard as StatCard } from "../../components/analysis/AnalysisPrimitives";
import type { USBAnalysis } from "../../core/types";
import { DeviceChips, NotesList, SecondaryTabButton } from "./UsbAnalysisControls";
import { KeyboardReplay, MouseBehaviorList, MouseHeatmap, MouseTrajectory } from "./UsbHidPanels";
import { KeyboardEventTable, MouseEventTable } from "./UsbTables";
import { useUsbHidState } from "./useUsbHidState";

export function UsbHidPanel({ analysis }: { analysis: USBAnalysis }) {
  const state = useUsbHidState(analysis);

  return (
    <div className="mt-4 space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <SecondaryTabButton
          active={state.activeSubTab === "keyboard"}
          onClick={() => state.setActiveSubTab("keyboard")}
        >
          键盘
        </SecondaryTabButton>
        <SecondaryTabButton active={state.activeSubTab === "mouse"} onClick={() => state.setActiveSubTab("mouse")}>
          鼠标
        </SecondaryTabButton>
      </div>

      {state.activeSubTab === "keyboard" ? <UsbKeyboardPanel state={state} /> : <UsbMousePanel state={state} />}
    </div>
  );
}

type UsbHidState = ReturnType<typeof useUsbHidState>;

function UsbKeyboardPanel({ state }: { state: UsbHidState }) {
  return (
    <>
      <DeviceChips
        devices={state.keyboardDevices}
        activeDevice={state.activeKeyboardDevice}
        emptyLabel="未检测到键盘设备"
        onSelect={state.setActiveKeyboardDevice}
      />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
        <StatCard title="当前设备事件" value={state.filteredKeyboardEvents.length.toLocaleString()} />
        <StatCard title="可打印输入" value={state.keyboardStats.printableCount.toLocaleString()} />
        <StatCard title="组合键事件" value={state.keyboardStats.comboCount.toLocaleString()} />
        <StatCard title="唯一按键" value={state.keyboardStats.uniqueKeyCount.toLocaleString()} />
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1.15fr)_minmax(0,0.85fr)]">
        <Panel title="键入行为">
          <KeyboardReplay
            currentEvent={state.currentKeyboardEvent}
            currentIndex={state.keyboardCursor}
            isPlaying={state.isKeyboardPlaying}
            replayText={state.keyboardReplayText}
            total={state.filteredKeyboardEvents.length}
            onCursorChange={state.setKeyboardCursor}
            onNext={() =>
              state.setKeyboardCursor((prev) =>
                Math.min(prev + 1, Math.max(state.filteredKeyboardEvents.length - 1, 0)),
              )
            }
            onPrev={() => state.setKeyboardCursor((prev) => Math.max(prev - 1, 0))}
            onTogglePlay={state.toggleKeyboardPlay}
          />
        </Panel>
        <Panel title="完整文本流">
          <pre className="max-h-[260px] overflow-auto whitespace-pre-wrap break-all rounded-md border border-border bg-background px-3 py-3 font-mono text-xs leading-5">
            {state.keyboardTextPreview}
          </pre>
        </Panel>
      </div>

      <Panel title={`按键行为 (${state.filteredKeyboardEvents.length})`}>
        <KeyboardEventTable rows={state.filteredKeyboardEvents} />
      </Panel>
      <Panel title="HID 提示">
        <NotesList notes={state.notes} emptyLabel="暂无 HID 提示" />
      </Panel>
    </>
  );
}

function UsbMousePanel({ state }: { state: UsbHidState }) {
  return (
    <>
      <DeviceChips
        devices={state.mouseDevices}
        activeDevice={state.activeMouseDevice}
        emptyLabel="未检测到鼠标设备"
        onSelect={state.setActiveMouseDevice}
      />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
        <StatCard title="事件数" value={state.filteredMouseEvents.length.toLocaleString()} />
        <StatCard title="轨迹总路程" value={`${state.mouseStats.distance}`} />
        <StatCard title="按钮动作数" value={`${state.mouseStats.buttonActions}`} />
        <StatCard title="滚轮事件数" value={`${state.mouseStats.wheelCount}`} />
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Panel title="轨迹图">
          <MouseTrajectory events={state.filteredMouseEvents} />
        </Panel>
        <Panel title="按键行为">
          <MouseBehaviorList rows={state.filteredMouseEvents.slice(-18).reverse()} />
        </Panel>
      </div>

      <Panel title="热区图">
        <MouseHeatmap events={state.filteredMouseEvents} />
      </Panel>

      <Panel title={`行为明细表 (${state.filteredMouseEvents.length})`}>
        <MouseEventTable rows={state.filteredMouseEvents} />
      </Panel>
    </>
  );
}

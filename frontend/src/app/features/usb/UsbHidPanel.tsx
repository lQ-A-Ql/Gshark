import { AnalysisPanel as Panel, AnalysisStatCard as StatCard } from "../../components/analysis/AnalysisPrimitives";
import type { USBAnalysis, USBHIDSourceMode } from "../../core/types";
import { DeviceChips, NotesList, SecondaryTabButton } from "./UsbAnalysisControls";
import { KeyboardEditedText, KeyboardReplay } from "./UsbHidPanels";
import { UsbMousePanel } from "./UsbMousePanel";
import { KeyboardEventTable } from "./UsbTables";
import { useUsbHidState } from "./useUsbHidState";

export function UsbHidPanel({
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
  const state = useUsbHidState(analysis);

  return (
    <div className="mt-0 space-y-0">
      <div className="flex flex-wrap items-center gap-px">
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

      {state.activeSubTab === "keyboard" ? (
        <UsbKeyboardPanel state={state} />
      ) : (
        <UsbMousePanel
          analysis={analysis}
          hidEventLimit={hidEventLimit}
          hidSource={hidSource}
          onHidEventLimitChange={onHidEventLimitChange}
          onHidSourceChange={onHidSourceChange}
          state={state}
        />
      )}
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

      <div className="grid grid-cols-1 gap-0 lg:grid-cols-4">
        <StatCard title="当前设备事件" value={state.filteredKeyboardEvents.length.toLocaleString()} />
        <StatCard title="可打印输入" value={state.keyboardStats.printableCount.toLocaleString()} />
        <StatCard title="组合键事件" value={state.keyboardStats.comboCount.toLocaleString()} />
        <StatCard title="唯一按键" value={state.keyboardStats.uniqueKeyCount.toLocaleString()} />
      </div>

      <div className="grid grid-cols-1 gap-0 xl:grid-cols-[minmax(0,1.15fr)_minmax(0,0.85fr)]">
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
          <pre className="gshark-soft-fill max-h-[260px] overflow-auto whitespace-pre-wrap break-all px-3 py-3 font-mono text-xs leading-5">
            {state.keyboardTextPreview}
          </pre>
        </Panel>
      </div>

      <KeyboardEditedText text={state.keyboardEditedText.text} deleted={state.keyboardEditedText.deleted} />

      <Panel title={`按键行为 (${state.filteredKeyboardEvents.length})`}>
        <KeyboardEventTable rows={state.filteredKeyboardEvents} resetKey={state.activeKeyboardDevice} />
      </Panel>
      <Panel title="HID 提示">
        <NotesList notes={state.notes} emptyLabel="暂无 HID 提示" />
      </Panel>
    </>
  );
}

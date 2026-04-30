import { useMemo, type Ref } from "react";
import { Panel } from "react-resizable-panels";
import { FileText } from "lucide-react";
import type { Packet } from "../../core/types";

export function HexAsciiPanel({
  packet,
  frameBytes,
  selectedByteRange,
  selectedByteOffset,
  panelRef,
  onSelectByte,
}: {
  packet: Packet | null;
  frameBytes: number[];
  selectedByteRange: [number, number] | null;
  selectedByteOffset: number | null;
  panelRef: Ref<HTMLDivElement>;
  onSelectByte: (offset: number) => void;
}) {
  const rows = useMemo(() => buildHexRows(frameBytes), [frameBytes]);

  return (
    <Panel defaultSize={50} minSize={20} className="flex flex-col bg-white/95">
      <div className="flex shrink-0 items-center gap-2 border-b border-slate-200 bg-gradient-to-r from-amber-50 via-white to-slate-50 px-4 py-2 text-[13px] font-semibold text-slate-800">
        <FileText className="h-4 w-4 text-amber-600" /> 十六进制与 ASCII 视图
        {packet && (
          <span className="ml-2 rounded-full border border-blue-100 bg-blue-50 px-2.5 py-0.5 text-[11px] font-semibold text-blue-600">
            Packet #{packet.id}
          </span>
        )}
      </div>
      <div ref={panelRef} className="flex-1 overflow-auto p-3 font-mono text-[12.5px] leading-5">
        {frameBytes.length === 0 ? (
          <div className="rounded-2xl border border-dashed border-slate-200 bg-slate-50/80 px-4 py-6 text-sm text-slate-500">
            暂无 hex 数据
          </div>
        ) : (
          <div className="w-max min-w-full space-y-1">
            {rows.map((row) => (
              <HexAsciiRow
                key={row.offset}
                row={row}
                selectedByteRange={selectedByteRange}
                selectedByteOffset={selectedByteOffset}
                onSelectByte={onSelectByte}
              />
            ))}
          </div>
        )}
      </div>
    </Panel>
  );
}

function HexAsciiRow({
  row,
  selectedByteRange,
  selectedByteOffset,
  onSelectByte,
}: {
  row: ReturnType<typeof buildHexRows>[number];
  selectedByteRange: [number, number] | null;
  selectedByteOffset: number | null;
  onSelectByte: (offset: number) => void;
}) {
  return (
    <div className="grid grid-cols-[3.25rem_22.1rem_11.9rem] items-start gap-2 rounded-lg px-1.5 py-0.5 text-slate-800 hover:bg-slate-50">
      <span className="pt-px text-[11px] font-semibold text-slate-400">{row.offset}</span>
      <span className="flex gap-px whitespace-nowrap">
        {row.bytes.map((item) => (
          <HexByteButton
            key={item.index}
            item={item}
            selectedByteRange={selectedByteRange}
            selectedByteOffset={selectedByteOffset}
            tone="hex"
            onSelectByte={onSelectByte}
          />
        ))}
      </span>
      <span className="flex gap-px whitespace-nowrap border-l border-slate-200 pl-2">
        {row.bytes.map((item) => (
          <HexByteButton
            key={`ascii-${item.index}`}
            item={item}
            selectedByteRange={selectedByteRange}
            selectedByteOffset={selectedByteOffset}
            tone="ascii"
            onSelectByte={onSelectByte}
          />
        ))}
      </span>
    </div>
  );
}

function HexByteButton({
  item,
  selectedByteRange,
  selectedByteOffset,
  tone,
  onSelectByte,
}: {
  item: { index: number; hex: string; ascii: string };
  selectedByteRange: [number, number] | null;
  selectedByteOffset: number | null;
  tone: "hex" | "ascii";
  onSelectByte: (offset: number) => void;
}) {
  const inRange = selectedByteRange && item.index >= selectedByteRange[0] && item.index <= selectedByteRange[1];
  const isCursor = selectedByteOffset === item.index;
  const textClass = isCursor
    ? "bg-blue-700 text-white shadow-sm"
    : inRange
      ? "bg-amber-100 text-amber-800 ring-1 ring-amber-200"
      : tone === "hex"
        ? "text-slate-800 hover:bg-cyan-50 hover:text-cyan-700"
        : "text-slate-500 hover:bg-slate-100 hover:text-slate-800";
  const sizeClass = tone === "hex"
    ? "w-[1.32rem] px-0"
    : "w-[0.72rem] px-0";

  return (
    <button
      type="button"
      data-byte={item.index}
      className={`inline-flex items-center justify-center rounded py-0.5 text-[12.5px] leading-5 font-normal transition-colors font-mono ${sizeClass} ${textClass}`}
      onClick={() => onSelectByte(item.index)}
    >
      {tone === "hex" ? item.hex : item.ascii}
    </button>
  );
}

function buildHexRows(bytes: number[]) {
  const rows: { offset: string; bytes: { index: number; hex: string; ascii: string }[] }[] = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const slice = bytes.slice(i, i + 16);
    rows.push({
      offset: i.toString(16).padStart(4, "0"),
      bytes: slice.map((value, idx) => ({
        index: i + idx,
        hex: value.toString(16).padStart(2, "0"),
        ascii: value >= 32 && value <= 126 ? String.fromCharCode(value) : ".",
      })),
    });
  }
  return rows;
}

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
    <Panel defaultSize={50} minSize={20} className="flex flex-col bg-card">
      <div className="flex shrink-0 items-center gap-2 border-b border-border bg-accent/40 px-3 py-1.5 text-xs font-semibold text-foreground">
        <FileText className="h-4 w-4 text-amber-600" /> 十六进制与 ASCII 视图
        {packet && (
          <span className="ml-2 rounded bg-blue-50 px-2 py-0.5 text-[10px] text-blue-600">
            Packet #{packet.id}
          </span>
        )}
      </div>
      <div ref={panelRef} className="flex-1 overflow-auto p-3 font-mono text-xs leading-5">
        {frameBytes.length === 0 ? (
          <div className="text-muted-foreground">暂无 hex 数据</div>
        ) : (
          <div className="space-y-0.5">
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
    <div className="grid grid-cols-[44px_1fr_136px] gap-1 text-foreground">
      <span className="text-muted-foreground">{row.offset}</span>
      <span>
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
      <span>
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
    ? "bg-blue-700 text-white"
    : inRange
      ? "bg-amber-100 text-amber-800"
      : tone === "hex"
        ? "text-foreground"
        : "text-muted-foreground";

  return (
    <button
      data-byte={item.index}
      className={`inline-block rounded px-[1px] text-[11px] leading-4 font-normal ${tone === "hex" ? "font-mono" : ""} ${textClass}`}
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

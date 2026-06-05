import { useMemo, type Ref } from "react";
import { Panel } from "react-resizable-panels";
import { FileText } from "lucide-react";
import type { Packet } from "../../core/types";
import { StatusHint, WorkbenchChip } from "../DesignSystem";

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
  const fingerprintRows = packet ? buildFingerprintRows(packet) : [];
  const showFingerprintUnavailable = packet ? isTLSLikePacket(packet) && fingerprintRows.length === 0 : false;

  return (
    <Panel defaultSize={50} minSize={20} className="meow-tile flex flex-col">
      <div className="meow-tile-header meow-workbench-panel flex shrink-0 items-center gap-2 px-4 py-2 text-[13px] font-semibold text-slate-800">
        <span className="meow-diffuse-chip meow-evidence-accent p-1.5 text-amber-600">
          <FileText className="h-4 w-4" />
        </span>
        十六进制与 ASCII 视图
        {packet && (
          <span className="meow-diffuse-chip meow-evidence-accent ml-2 px-2.5 py-0.5 text-[11px] font-semibold text-blue-600">
            Packet #{packet.id}
          </span>
        )}
      </div>
      {packet ? (
        <div className="border-b border-[var(--meow-tile-divider)] px-3 py-2.5">
          {fingerprintRows.length > 0 ? (
            <div className="space-y-2">
              <div className="flex flex-wrap items-center gap-2">
                <WorkbenchChip>JA3 / JA3S</WorkbenchChip>
                <span className="text-[11px] text-slate-500">TLS 指纹来自当前选中数据包已有字段。</span>
              </div>
              <div className="grid gap-2">
                {fingerprintRows.map((row) => (
                  <div key={row.label} className="meow-soft-fill flex flex-col gap-1 px-3 py-2">
                    <div className="text-[11px] font-medium tracking-[0.12em] text-slate-500">{row.label}</div>
                    <div className="break-all font-mono text-[12px] leading-5 text-slate-800">{row.value}</div>
                  </div>
                ))}
              </div>
            </div>
          ) : showFingerprintUnavailable ? (
            <StatusHint tone="slate" className="px-3 py-2">
              当前 TLS / HTTPS 数据包未提供 JA3 或 JA3S 指纹；仅在后端已解析到 `tls_fingerprint` 时显示。
            </StatusHint>
          ) : null}
        </div>
      ) : null}
      <div ref={panelRef} className="flex-1 overflow-auto p-3 font-mono text-[12.5px] leading-5">
        {frameBytes.length === 0 ? (
          <div className="meow-soft-fill px-4 py-6 text-sm text-slate-500">暂无 hex 数据</div>
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

function buildFingerprintRows(packet: Packet) {
  const fingerprint = packet.tlsFingerprint;
  if (!fingerprint) return [];
  return [
    { label: "JA3 Hash", value: fingerprint.ja3Hash },
    { label: "JA3S Hash", value: fingerprint.ja3sHash },
    { label: "JA3 Raw", value: fingerprint.ja3Raw },
    { label: "JA3S Raw", value: fingerprint.ja3sRaw },
  ].filter((row): row is { label: string; value: string } => Boolean(row.value));
}

function isTLSLikePacket(packet: Packet) {
  const protocolText = `${packet.proto} ${packet.displayProtocol ?? ""}`.toLowerCase();
  return protocolText.includes("tls") || protocolText.includes("https");
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
    <div className="grid grid-cols-[3.25rem_22.1rem_11.9rem] items-start gap-2 px-1.5 py-0.5 text-slate-800 transition-colors hover:bg-[var(--meow-table-hover-bg)]">
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
      <span className="flex gap-px whitespace-nowrap border-l border-[var(--meow-tile-divider)] pl-2">
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
    ? "bg-blue-700/78 text-white shadow-[0_0_18px_rgba(37,99,235,0.16)]"
    : inRange
      ? "bg-amber-100/55 text-amber-800 ring-1 ring-amber-200/30"
      : tone === "hex"
        ? "text-slate-800 hover:bg-cyan-50/50 hover:text-cyan-700"
        : "text-slate-500 hover:bg-slate-100/45 hover:text-slate-800";
  const sizeClass = tone === "hex" ? "w-[1.32rem] px-0" : "w-[0.72rem] px-0";

  return (
    <button
      type="button"
      data-byte={item.index}
      className={`inline-flex items-center justify-center rounded-sm py-0.5 text-[12.5px] leading-5 font-normal transition-colors font-mono ${sizeClass} ${textClass}`}
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

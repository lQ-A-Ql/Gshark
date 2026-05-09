import type { Packet } from "../core/types";

export type CommFailureLevel = "critical" | "major" | "warn" | null;
export type ColumnId = "id" | "time" | "src" | "dst" | "proto" | "length" | "info";

export interface ColumnSpec {
  id: ColumnId;
  label: string;
  width: number;
  visible: boolean;
}

const COLUMN_STORAGE_KEY = "gshark.packet-table.columns.v1";

export const DEFAULT_COLUMNS: ColumnSpec[] = [
  { id: "id", label: "No.", width: 72, visible: true },
  { id: "time", label: "Time", width: 170, visible: true },
  { id: "src", label: "Source", width: 220, visible: true },
  { id: "dst", label: "Destination", width: 220, visible: true },
  { id: "proto", label: "Protocol", width: 100, visible: true },
  { id: "length", label: "Length", width: 90, visible: true },
  { id: "info", label: "Info", width: 420, visible: true },
];

export function loadSavedColumns(): ColumnSpec[] {
  if (typeof window === "undefined") return DEFAULT_COLUMNS;

  try {
    const raw = window.localStorage.getItem(COLUMN_STORAGE_KEY);
    if (!raw) return DEFAULT_COLUMNS;

    const parsed = JSON.parse(raw) as Partial<ColumnSpec>[];
    if (!Array.isArray(parsed)) return DEFAULT_COLUMNS;

    const merged = DEFAULT_COLUMNS.map((defaults) => {
      const saved = parsed.find((item) => item.id === defaults.id);
      if (!saved) return defaults;
      return {
        ...defaults,
        label: typeof saved.label === "string" && saved.label.trim() ? saved.label : defaults.label,
        width: typeof saved.width === "number" && Number.isFinite(saved.width) ? Math.max(64, saved.width) : defaults.width,
        visible: typeof saved.visible === "boolean" ? saved.visible : defaults.visible,
      };
    });

    if (merged.every((col) => !col.visible)) {
      return DEFAULT_COLUMNS;
    }
    return merged;
  } catch {
    return DEFAULT_COLUMNS;
  }
}

export function saveColumns(columns: ColumnSpec[]) {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(COLUMN_STORAGE_KEY, JSON.stringify(columns));
}

export function getCommunicationFailureLevel(packet: Packet): CommFailureLevel {
  const info = `${packet.info ?? ""} ${packet.payload ?? ""}`.toLowerCase();
  const tlsLike = packet.proto === "TLS" || packet.proto === "HTTPS" || info.includes("tls") || info.includes("ssl");
  const tlsFail =
    tlsLike &&
    (info.includes("handshake failure") ||
      info.includes("fatal alert") ||
      info.includes("decrypt error") ||
      info.includes("bad certificate") ||
      info.includes("unknown ca") ||
      info.includes("certificate unknown") ||
      info.includes("protocol version"));
  if (tlsFail) return "critical";

  const tcpFail =
    info.includes("tcp reset") ||
    info.includes("[rst") ||
    info.includes("retransmission") ||
    info.includes("duplicate ack") ||
    info.includes("out-of-order") ||
    info.includes("previous segment not captured") ||
    info.includes("connection refused") ||
    info.includes("timeout");
  if (tcpFail) return "major";

  const dnsFail =
    info.includes("nxdomain") ||
    info.includes("servfail") ||
    info.includes("refused") ||
    info.includes("format error") ||
    info.includes("no such name");
  if (dnsFail) return "warn";

  const httpFail =
    /http\/\d\.\d\s+5\d\d/.test(info) ||
    /http\/\d\.\d\s+4\d\d/.test(info) ||
    info.includes("bad gateway") ||
    info.includes("gateway timeout") ||
    info.includes("service unavailable");
  if (httpFail) return "major";

  const icmpFail = info.includes("destination unreachable") || info.includes("time-to-live exceeded") || info.includes("ttl exceeded");
  if (icmpFail) return "warn";

  return null;
}

export function renderPacketCell(packet: Packet, colId: ColumnId) {
  const protocolLabel = packet.displayProtocol?.trim() || packet.proto;
  switch (colId) {
    case "id": {
      const failureLevel = getCommunicationFailureLevel(packet);
      return (
        <div className="px-3 py-1.5 tabular-nums">
          <span className="inline-flex items-center gap-1">
            {failureLevel && (
              <span className={`inline-block h-2 w-2 rounded-full ${failureDotClass(failureLevel)}`} title="通讯异常" />
            )}
            <span>{packet.id}</span>
          </span>
        </div>
      );
    }
    case "time":
      return <div className="px-3 py-1.5 whitespace-nowrap font-mono font-normal">{packet.time}</div>;
    case "src":
      return (
        <div className="px-3 py-1.5 truncate">
          {packet.src}:{packet.srcPort}
        </div>
      );
    case "dst":
      return (
        <div className="px-3 py-1.5 truncate">
          {packet.dst}:{packet.dstPort}
        </div>
      );
    case "proto":
      return <div className="px-3 py-1.5">{protocolLabel}</div>;
    case "length":
      return <div className="px-3 py-1.5 tabular-nums">{packet.length}</div>;
    case "info":
    default:
      return <div className="px-3 py-1.5 truncate">{packet.info}</div>;
  }
}

function failureDotClass(level: Exclude<CommFailureLevel, null>) {
  if (level === "critical") return "bg-rose-600";
  if (level === "major") return "bg-orange-500";
  return "bg-amber-500";
}

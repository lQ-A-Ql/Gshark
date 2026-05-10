import type { Packet } from "../../core/types";
import { asPacket } from "../mappers/packetStreamMapper";

type JsonRequest = <T>(path: string, init?: RequestInit) => Promise<T>;

export interface OpenFileResult {
  filePath: string;
  fileSize: number;
  fileName: string;
}

export interface PacketsPageResult {
  items: Packet[];
  nextCursor: number;
  total: number;
  hasMore: boolean;
  filtering?: boolean;
}

export interface CaptureStatus {
  filePath: string;
  hasCapture: boolean;
  packetCount: number;
}

export interface PacketLocateResult {
  packetId: number;
  cursor: number;
  total: number;
  found: boolean;
}

interface CaptureDesktopBinding {
  OpenCaptureDialog?: () => Promise<OpenFileResult | null | undefined>;
}

export interface CaptureClient {
  openPcapFile(): Promise<OpenFileResult>;
  startStreamingPackets(filePath: string, filter: string, signal?: AbortSignal): Promise<void>;
  stopStreamingPackets(): Promise<void>;
  prepareCaptureReplacement(): Promise<void>;
  closeCapture(): Promise<void>;
  getCaptureStatus(signal?: AbortSignal): Promise<CaptureStatus>;
  listPackets(): Promise<Packet[]>;
  listPacketsPage(cursor: number, limit: number, filter?: string, signal?: AbortSignal): Promise<PacketsPageResult>;
  locatePacketPage(packetId: number, limit: number, filter?: string, signal?: AbortSignal): Promise<PacketLocateResult>;
  getPacket(packetId: number, signal?: AbortSignal): Promise<Packet>;
}

export function createCaptureClient(
  request: JsonRequest,
  getDesktopApp: () => CaptureDesktopBinding | undefined,
): CaptureClient {
  return {
    async openPcapFile() {
      const desktopApp = getDesktopApp();
      if (desktopApp?.OpenCaptureDialog) {
        const result = await desktopApp.OpenCaptureDialog();
        if (!result?.filePath) {
          throw new Error("未选择文件");
        }
        return {
          filePath: String(result.filePath),
          fileSize: Number(result.fileSize ?? 0),
          fileName: String(result.fileName ?? String(result.filePath).split(/[\\/]/).pop() ?? "capture.pcapng"),
        };
      }

      const file = await selectLocalFile();
      const form = new FormData();
      form.append("file", file, file.name);

      const result = await request<OpenFileResult>("/api/capture/upload", {
        method: "POST",
        body: form,
      });

      return {
        filePath: result.filePath,
        fileSize: Number(result.fileSize ?? file.size),
        fileName: result.fileName ?? file.name,
      };
    },

    async startStreamingPackets(filePath: string, filter: string, signal?: AbortSignal) {
      await request("/api/capture/start", {
        method: "POST",
        signal,
        body: JSON.stringify({
          file_path: filePath,
          display_filter: filter,
          max_packets: 0,
          emit_packets: false,
          fast_list: true,
        }),
      });
    },

    async stopStreamingPackets() {
      await request("/api/capture/stop", { method: "POST" });
    },

    async prepareCaptureReplacement() {
      await request("/api/capture/prepare-replacement", { method: "POST" });
    },

    async closeCapture() {
      await request("/api/capture/close", { method: "POST" });
    },

    async getCaptureStatus(signal?: AbortSignal) {
      const payload = await request<any>("/api/capture/status", { signal });
      return asCaptureStatus(payload);
    },

    async listPackets() {
      const rows = await request<any[]>("/api/packets");
      return rows.map(asPacket);
    },

    async listPacketsPage(cursor: number, limit: number, filter = "", signal?: AbortSignal) {
      const query = new URLSearchParams({
        cursor: String(cursor),
        limit: String(limit),
      });
      if (filter.trim()) {
        query.set("filter", filter);
      }
      const payload = await request<any>(`/api/packets/page?${query.toString()}`, { signal });
      const rows = Array.isArray(payload.items) ? payload.items : [];
      return {
        items: rows.map(asPacket),
        nextCursor: Number(payload.next_cursor ?? rows.length),
        total: Number(payload.total ?? rows.length),
        hasMore: Boolean(payload.has_more),
        filtering: Boolean(payload.filtering),
      };
    },

    async locatePacketPage(packetId: number, limit: number, filter = "", signal?: AbortSignal) {
      const query = new URLSearchParams({
        id: String(packetId),
        limit: String(limit),
      });
      if (filter.trim()) {
        query.set("filter", filter);
      }
      const payload = await request<any>(`/api/packets/locate?${query.toString()}`, { signal });
      return {
        packetId: Number(payload.packet_id ?? packetId),
        cursor: Number(payload.cursor ?? 0),
        total: Number(payload.total ?? 0),
        found: Boolean(payload.found),
      };
    },

    async getPacket(packetId: number, signal?: AbortSignal) {
      const payload = await request<any>(`/api/packet?id=${encodeURIComponent(String(packetId))}`, { signal });
      return asPacket(payload);
    },
  };
}

export function asCaptureStatus(payload: any): CaptureStatus {
  return {
    filePath: String(payload?.file_path ?? payload?.filePath ?? ""),
    hasCapture: Boolean(payload?.has_capture ?? payload?.hasCapture),
    packetCount: Number(payload?.packet_count ?? payload?.packetCount ?? 0),
  };
}

async function selectLocalFile(): Promise<File> {
  if (typeof document === "undefined") {
    throw new Error("当前环境不支持文件选择");
  }

  return new Promise<File>((resolve, reject) => {
    let settled = false;
    const input = document.createElement("input");
    input.type = "file";
    input.accept = ".pcap,.pcapng,.cap";
    input.style.display = "none";

    const cleanup = () => {
      if (input.parentNode) {
        input.parentNode.removeChild(input);
      }
    };

    input.onchange = () => {
      const file = input.files?.[0];
      cleanup();
      if (!file) {
        settled = true;
        reject(new Error("未选择文件"));
        return;
      }
      settled = true;
      resolve(file);
    };

    document.body.appendChild(input);
    input.click();

    const onFocus = () => {
      window.setTimeout(() => {
        if (!settled) {
          settled = true;
          cleanup();
          reject(new Error("已取消文件选择"));
        }
      }, 300);
      window.removeEventListener("focus", onFocus);
    };

    window.addEventListener("focus", onFocus);

    window.setTimeout(() => {
      if (!settled && (!input.files || input.files.length === 0)) {
        settled = true;
        window.removeEventListener("focus", onFocus);
        cleanup();
        reject(new Error("文件选择超时"));
      }
    }, 120000);
  });
}

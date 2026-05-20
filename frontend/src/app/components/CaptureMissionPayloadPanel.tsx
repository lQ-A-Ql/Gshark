import { ArrowRight } from "lucide-react";
import type { Packet } from "../core/types";

type CapturePayloadShortcutPanelProps = {
  selectedPacket: Packet | null;
  onOpenCurrentStream: () => Promise<void>;
  onOpenMisc: () => void;
};

export function CapturePayloadShortcutPanel({
  selectedPacket,
  onOpenCurrentStream,
  onOpenMisc,
}: CapturePayloadShortcutPanelProps) {
  return (
    <div className="border-t border-[var(--gshark-tile-divider)] p-4 sm:p-5">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="text-sm font-semibold text-slate-900">Payload 快速解码</div>
          <div className="mt-1 text-xs text-slate-500">
            解码与 WebShell 候选识别已收敛到 MISC 工具箱；首屏仅保留当前包上下文和跳转入口，避免工作区过载。
          </div>
        </div>
        {selectedPacket && (
          <div className="flex flex-wrap items-center gap-2">
            <div className="gshark-diffuse-chip gshark-evidence-accent px-3 py-1 text-[11px] text-slate-600">
              Packet #{selectedPacket.id} / {selectedPacket.displayProtocol || selectedPacket.proto}
            </div>
            {selectedPacket.streamId != null && selectedPacket.streamId >= 0 && (
              <button
                onClick={() => void onOpenCurrentStream()}
                className="gshark-control inline-flex items-center gap-2 px-3 py-1.5 text-xs font-medium text-slate-700"
              >
                打开当前关联流
                <ArrowRight className="h-3.5 w-3.5" />
              </button>
            )}
            <button
              onClick={onOpenMisc}
              className="gshark-control-primary inline-flex items-center gap-2 px-3 py-1.5 text-xs font-medium"
            >
              打开 MISC 解码工作台
              <ArrowRight className="h-3.5 w-3.5" />
            </button>
          </div>
        )}
      </div>

      {selectedPacket ? (
        <div className="grid gap-3 xl:grid-cols-[minmax(320px,0.82fr)_minmax(0,1.18fr)]">
          <div className="gshark-tile gshark-evidence-accent p-3.5">
            <div className="text-sm font-semibold text-slate-900">当前数据包上下文</div>
            <div className="mt-2.5 space-y-2 text-xs">
              <InfoRow
                label="端点"
                value={`${selectedPacket.src}:${selectedPacket.srcPort} -> ${selectedPacket.dst}:${selectedPacket.dstPort}`}
                mono
              />
              <InfoRow label="协议" value={selectedPacket.displayProtocol || selectedPacket.proto} />
              <InfoRow label="长度" value={`${selectedPacket.length} bytes`} />
              <InfoRow label="说明" value={selectedPacket.info || "(no info)"} />
            </div>
          </div>
          <div className="gshark-tile gshark-evidence-accent p-3.5">
            <div className="flex items-center justify-between gap-3">
              <div>
                <div className="text-sm font-semibold text-slate-900">Payload 预览</div>
                <div className="mt-1 text-xs text-slate-500">
                  如需识别候选或尝试解码，请在 MISC 工作台中手动粘贴该 payload。
                </div>
              </div>
              <button
                onClick={onOpenMisc}
                className="gshark-control shrink-0 px-3 py-1.5 text-xs font-semibold text-cyan-700 transition"
              >
                去 MISC
              </button>
            </div>
            <pre className="gshark-soft-fill mt-3 max-h-40 overflow-auto whitespace-pre-wrap break-all px-3 py-2 font-mono text-[11px] leading-5 text-slate-600">
              {selectedPacket.payload || "(empty payload)"}
            </pre>
          </div>
        </div>
      ) : (
        <div className="px-4 py-6 text-center text-xs leading-5 text-slate-500">
          选中一条数据包后，这里会展示 payload 预览；完整解码请前往 MISC 工具箱。
        </div>
      )}
    </div>
  );
}

function InfoRow({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="gshark-soft-fill px-3 py-2">
      <div className="text-[11px] font-medium tracking-[0.12em] text-slate-500">{label}</div>
      <div className={`mt-1 break-all text-sm text-slate-900 ${mono ? "font-mono" : ""}`}>{value}</div>
    </div>
  );
}

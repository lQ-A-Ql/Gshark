import { Copy } from "lucide-react";
import { Button } from "../../components/ui/button";
import type { NTLMSessionMaterial } from "../../core/types";
import type { MiscExportFormat } from "../exportResult";
import { ExportButtons, MetaChip } from "../ui";

interface NTLMSessionMaterialDetailsProps {
  copyNotice: string;
  filtered: NTLMSessionMaterial[];
  onCopySelected: () => void | Promise<void>;
  onExport: (format: MiscExportFormat) => void;
  selected: NTLMSessionMaterial | null;
}

export function NTLMSessionMaterialDetails({
  copyNotice,
  filtered,
  onCopySelected,
  onExport,
  selected,
}: NTLMSessionMaterialDetailsProps) {
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <div>
          <div className="text-sm font-semibold text-slate-800">材料详情</div>
          <div className="text-[12px] text-slate-500">统一查看 challenge、NT proof、session key、方向和认证头。</div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <ExportButtons disabled={filtered.length === 0} onExport={onExport} />
          <Button
            variant="outline"
            onClick={() => void onCopySelected()}
            disabled={!selected}
            className="gap-2 bg-white text-slate-700"
          >
            <Copy className="h-4 w-4 text-violet-600" />
            复制当前
          </Button>
        </div>
      </div>

      {copyNotice && (
        <div className="mb-3 rounded-md border border-violet-200 bg-violet-50 px-3 py-2 text-xs text-violet-700">
          {copyNotice}
        </div>
      )}

      {!selected ? (
        <div className="rounded-lg border border-dashed border-slate-200 bg-slate-50 px-3 py-8 text-center text-[13px] text-slate-500">
          请选择左侧的一条 NTLM 材料查看详情。
        </div>
      ) : (
        <div className="space-y-4">
          <div className="flex flex-wrap gap-2">
            <MetaChip label="协议" value={selected.protocol} color="sky" />
            <MetaChip label="方向" value={selected.direction || "--"} color="slate" />
            <MetaChip label="包号" value={`#${selected.frameNumber}`} color="slate" />
            <MetaChip
              label="完整度"
              value={selected.complete ? "完整" : "待补"}
              color={selected.complete ? "emerald" : "rose"}
            />
            {selected.sessionId && <MetaChip label="Session" value={selected.sessionId} color="slate" />}
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            <MaterialField label="用户名" value={selected.userDisplay || selected.username} mono />
            <MaterialField label="域" value={selected.domain} mono />
            <MaterialField
              label="源地址"
              value={selected.src ? `${selected.src}${selected.srcPort ? `:${selected.srcPort}` : ""}` : undefined}
              mono
            />
            <MaterialField
              label="目标地址"
              value={selected.dst ? `${selected.dst}${selected.dstPort ? `:${selected.dstPort}` : ""}` : undefined}
              mono
            />
            <MaterialField label="时间" value={selected.timestamp} mono />
            <MaterialField label="传输标签" value={selected.transport} mono />
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            <MaterialField label="Challenge" value={selected.challenge} mono multiline />
            <MaterialField label="NTProofStr" value={selected.ntProofStr} mono multiline />
            <MaterialField label="Encrypted Session Key" value={selected.encryptedSessionKey} mono multiline />
            <MaterialField label="摘要 / Info" value={selected.info} multiline />
          </div>

          {(selected.authHeader || selected.wwwAuthenticate) && (
            <div className="grid gap-4 md:grid-cols-2">
              <MaterialField label="Authorization" value={selected.authHeader} mono multiline />
              <MaterialField label="WWW-Authenticate" value={selected.wwwAuthenticate} mono multiline />
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function MaterialField({
  label,
  value,
  mono = false,
  multiline = false,
}: {
  label: string;
  value?: string;
  mono?: boolean;
  multiline?: boolean;
}) {
  return (
    <div className="rounded-xl border border-slate-200 bg-slate-50/70 p-3">
      <div className="mb-1 text-[11px] font-semibold uppercase tracking-[0.16em] text-slate-500">{label}</div>
      <div
        className={`break-all text-[13px] text-slate-800 ${mono ? "font-mono" : ""} ${multiline ? "whitespace-pre-wrap" : ""}`}
      >
        {value || "--"}
      </div>
    </div>
  );
}

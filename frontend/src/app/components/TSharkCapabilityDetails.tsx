import type { ToolRuntimeSnapshot } from "../core/types";

type TSharkRuntimeStatus = ToolRuntimeSnapshot["tshark"];

export function TSharkCapabilityDetails({ status }: { status?: TSharkRuntimeStatus | null }) {
  if (!status) return null;
  const missingRequired = status.missingRequiredFields ?? [];
  const missingOptional = status.missingOptionalFields ?? [];
  const hasCapabilityDetails =
    status.version ||
    status.fieldProfile ||
    status.fieldCount ||
    status.capabilityMessage ||
    missingRequired.length > 0 ||
    missingOptional.length > 0;

  if (!hasCapabilityDetails) {
    return null;
  }

  return (
    <div className="rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-[11px] leading-5 text-slate-600">
      <div className="flex flex-wrap gap-1.5">
        <CapabilityChip label="版本" value={status.version} />
        <CapabilityChip label="字段档案" value={status.fieldProfile} />
        <CapabilityChip label="字段数" value={status.fieldCount ? String(status.fieldCount) : undefined} />
      </div>
      {status.capabilityMessage ? <div className="mt-1 break-all">能力探测：{status.capabilityMessage}</div> : null}
      {missingRequired.length > 0 ? (
        <div className="mt-1 break-all text-rose-700">缺少必需字段：{missingRequired.join(", ")}</div>
      ) : null}
      {missingOptional.length > 0 ? (
        <div className="mt-1 break-all text-amber-700">部分分析降级字段：{missingOptional.join(", ")}</div>
      ) : null}
    </div>
  );
}

function CapabilityChip({ label, value }: { label: string; value?: string }) {
  if (!value) {
    return null;
  }
  return (
    <span className="rounded-full border border-slate-200 bg-white px-2 py-0.5 font-medium text-slate-700">
      {label}: {value}
    </span>
  );
}

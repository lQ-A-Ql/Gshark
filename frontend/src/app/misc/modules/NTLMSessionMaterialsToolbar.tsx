import { RefreshCw } from "lucide-react";
import { Button } from "../../components/ui/button";
import { Input } from "../../components/ui/input";
import { ErrorBlock, Field, MetaChip } from "../ui";

export type NTLMSessionProtocolFilter = "ALL" | "HTTP" | "WinRM" | "SMB3" | "NTLM";

interface NTLMSessionMaterialsToolbarProps {
  captureName: string;
  completeCount: number;
  error: string;
  filteredCount: number;
  hasCapture: boolean;
  loading: boolean;
  materialCount: number;
  onProtocolFilterChange: (value: NTLMSessionProtocolFilter) => void;
  onQueryChange: (value: string) => void;
  onRefresh: () => void;
  protocolDomain?: string;
  protocolFilter: NTLMSessionProtocolFilter;
  query: string;
}

const PROTOCOL_FILTERS: NTLMSessionProtocolFilter[] = ["ALL", "HTTP", "WinRM", "SMB3", "NTLM"];

export function NTLMSessionMaterialsToolbar({
  captureName,
  completeCount,
  error,
  filteredCount,
  hasCapture,
  loading,
  materialCount,
  onProtocolFilterChange,
  onQueryChange,
  onRefresh,
  protocolDomain,
  protocolFilter,
  query,
}: NTLMSessionMaterialsToolbarProps) {
  return (
    <>
      <div className="gshark-tile-toolbar flex flex-wrap gap-2 border-violet-100 bg-violet-50/50 p-4 text-[11px]">
        <MetaChip label="抓包" value={hasCapture ? captureName : "未加载"} color={hasCapture ? "sky" : "slate"} />
        <MetaChip label="总材料" value={materialCount} color="slate" />
        <MetaChip label="完整" value={completeCount} color="emerald" />
        <MetaChip
          label="缺字段"
          value={Math.max(0, materialCount - completeCount)}
          color={completeCount === materialCount ? "slate" : "rose"}
        />
        {protocolDomain && <MetaChip label="域" value={protocolDomain} color="slate" />}
      </div>

      <div className="grid gap-4 md:grid-cols-[180px_minmax(0,1fr)_auto]">
        <Field label="协议筛选">
          <div className="relative isolate flex h-10 w-full rounded-md bg-slate-100/90 p-1 ring-1 ring-inset ring-slate-200/50">
            {PROTOCOL_FILTERS.map((item) => (
              <button
                key={item}
                type="button"
                onClick={() => onProtocolFilterChange(item)}
                className={`flex flex-1 items-center justify-center rounded-md text-[12px] font-semibold transition-colors ${
                  protocolFilter === item ? "bg-violet-50 text-violet-700" : "text-slate-500 hover:text-slate-700"
                }`}
              >
                {item === "ALL" ? "全部" : item}
              </button>
            ))}
          </div>
        </Field>
        <Field label="检索材料">
          <Input
            value={query}
            onChange={(event) => onQueryChange(event.target.value)}
            className="font-mono text-sm shadow-sm"
            placeholder="用户名 / challenge / NTProofStr / IP / session id"
          />
        </Field>
        <div className="flex items-end">
          <Button
            type="button"
            variant="outline"
            onClick={onRefresh}
            disabled={!hasCapture || loading}
            className="gap-2 border-violet-200 bg-violet-50 text-violet-700 hover:bg-violet-100"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
            {loading ? "扫描中..." : "刷新"}
          </Button>
        </div>
      </div>

      {!error && (
        <div className="gshark-tile border-slate-200 bg-slate-50 px-3 py-2 text-[12px] text-slate-600">
          {hasCapture
            ? loading
              ? "正在从当前抓包提取 NTLM 会话材料..."
              : `当前筛选命中 ${filteredCount} 条材料，可统一查看 HTTP / WinRM / SMB3 的 NTLM challenge 与 session key。`
            : "未加载抓包，请先在主工作区导入文件"}
        </div>
      )}
      {error && <ErrorBlock message={error} />}
    </>
  );
}

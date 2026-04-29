import { Copy, Filter } from "lucide-react";
import { useState } from "react";
import { Button } from "../components/ui/button";

type CopyTarget = "" | "host" | "uri" | "qname" | "stream" | "filter";
type FilterProtocol = "http" | "dns" | "tcp";

interface FilterActionsProps {
  protocol?: FilterProtocol;
  host?: string;
  uri?: string;
  qname?: string;
  dnsQueryType?: string;
  streamId?: number;
  disabled?: boolean;
  className?: string;
}

const DNS_QUERY_TYPE_NUMBERS: Record<string, number> = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  PTR: 12,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  SRV: 33,
  NULL: 10,
};

function quoteDisplayFilterValue(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

export function FilterActions({
  protocol,
  host,
  uri,
  qname,
  dnsQueryType,
  streamId,
  disabled = false,
  className = "",
}: FilterActionsProps) {
  const [pending, setPending] = useState<CopyTarget>("");
  const [copied, setCopied] = useState<CopyTarget>("");

  const hasHost = !!host?.trim();
  const hasUri = !!uri?.trim();
  const hasQName = !!qname?.trim();
  const hasStream = typeof streamId === "number" && Number.isFinite(streamId) && streamId >= 0;
  const effectiveProtocol: FilterProtocol = protocol ?? (hasStream ? "tcp" : hasQName ? "dns" : "http");
  const hasHttpFilter = effectiveProtocol === "http" && (hasHost || hasUri);
  const hasDnsFilter = effectiveProtocol === "dns" && hasQName;
  const hasTcpFilter = effectiveProtocol === "tcp" && hasStream;
  const hasAnyFilter = hasHttpFilter || hasDnsFilter || hasTcpFilter;
  const actionDisabled = disabled || pending !== "";

  async function copyToClipboard(text: string, target: CopyTarget) {
    if (actionDisabled) return;
    setPending(target);
    try {
      await navigator.clipboard.writeText(text);
      setCopied(target);
      setTimeout(() => setCopied(""), 1500);
    } finally {
      setPending("");
    }
  }

  function buildDisplayFilter(): string {
    const parts: string[] = [];
    if (effectiveProtocol === "http") {
      if (hasHost) {
        parts.push(`http.host == "${quoteDisplayFilterValue(host!.trim())}"`);
      }
      if (hasUri) {
        parts.push(`http.request.uri contains "${quoteDisplayFilterValue(uri!.trim())}"`);
      }
      return parts.join(" && ");
    }
    if (effectiveProtocol === "dns") {
      if (hasQName) {
        parts.push(`dns.qry.name contains "${quoteDisplayFilterValue(qname!.trim())}"`);
      }
      const queryTypeNumber = dnsQueryType ? DNS_QUERY_TYPE_NUMBERS[dnsQueryType.toUpperCase()] : undefined;
      if (queryTypeNumber) {
        parts.push(`dns.qry.type == ${queryTypeNumber}`);
      }
      return parts.join(" && ");
    }
    if (effectiveProtocol === "tcp" && hasStream) {
      return `tcp.stream == ${streamId}`;
    }
    return "";
  }

  const filterTitle =
    effectiveProtocol === "dns"
      ? "生成 DNS 显示过滤器并复制到剪贴板"
      : effectiveProtocol === "tcp"
        ? "生成 TCP Stream 过滤器并复制到剪贴板"
        : "生成 HTTP 显示过滤器并复制到剪贴板";

  return (
    <div className={`flex flex-wrap gap-1.5 ${className}`}>
      {effectiveProtocol === "http" && hasHost && (
        <Button
          type="button"
          size="sm"
          variant="outline"
          onClick={() => void copyToClipboard(host!, "host")}
          disabled={actionDisabled}
          title={`复制 Host: ${host}`}
          className="h-7 gap-1 border-emerald-200 bg-emerald-50 px-2 text-[11px] text-emerald-700 hover:bg-emerald-100"
        >
          <Copy className="h-3 w-3" />
          {copied === "host" ? "已复制" : "Host"}
        </Button>
      )}
      {effectiveProtocol === "http" && hasUri && (
        <Button
          type="button"
          size="sm"
          variant="outline"
          onClick={() => void copyToClipboard(uri!, "uri")}
          disabled={actionDisabled}
          title={`复制 URI: ${uri}`}
          className="h-7 gap-1 border-emerald-200 bg-emerald-50 px-2 text-[11px] text-emerald-700 hover:bg-emerald-100"
        >
          <Copy className="h-3 w-3" />
          {copied === "uri" ? "已复制" : "URI"}
        </Button>
      )}
      {effectiveProtocol === "dns" && hasQName && (
        <Button
          type="button"
          size="sm"
          variant="outline"
          onClick={() => void copyToClipboard(qname!.trim(), "qname")}
          disabled={actionDisabled}
          title={`复制 DNS QName: ${qname}`}
          className="h-7 gap-1 border-sky-200 bg-sky-50 px-2 text-[11px] text-sky-700 hover:bg-sky-100"
        >
          <Copy className="h-3 w-3" />
          {copied === "qname" ? "已复制" : "QName"}
        </Button>
      )}
      {effectiveProtocol === "tcp" && hasStream && (
        <Button
          type="button"
          size="sm"
          variant="outline"
          onClick={() => void copyToClipboard(String(streamId), "stream")}
          disabled={actionDisabled}
          title={`复制 TCP Stream: ${streamId}`}
          className="h-7 gap-1 border-cyan-200 bg-cyan-50 px-2 text-[11px] text-cyan-700 hover:bg-cyan-100"
        >
          <Copy className="h-3 w-3" />
          {copied === "stream" ? "已复制" : "Stream"}
        </Button>
      )}
      {hasAnyFilter && (
        <Button
          type="button"
          size="sm"
          variant="outline"
          onClick={() => void copyToClipboard(buildDisplayFilter(), "filter")}
          disabled={actionDisabled}
          title={filterTitle}
          className="h-7 gap-1 border-violet-200 bg-violet-50 px-2 text-[11px] text-violet-700 hover:bg-violet-100"
        >
          <Filter className="h-3 w-3" />
          {copied === "filter" ? "已复制" : "过滤器"}
        </Button>
      )}
    </div>
  );
}

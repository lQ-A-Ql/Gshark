import type { C2IndicatorRecord } from "../../core/types";
import { FilterActions } from "../../misc/FilterActions";

export function CandidateFilterActions({ item }: { item: C2IndicatorRecord }) {
  const channel = (item.channel ?? "").toLowerCase();
  const indicatorType = (item.indicatorType ?? "").toLowerCase();
  const indicatorValue = item.indicatorValue?.trim() ?? "";
  const isDns = channel === "dns" || indicatorType.includes("dns");
  const isTcpLike = channel === "tcp" || channel === "smb" || channel === "dot" || item.family === "vshell";

  if (isDns) {
    const qname = item.host || indicatorValue;
    return qname ? (
      <FilterActions
        protocol="dns"
        qname={qname}
        dnsQueryType={indicatorValue.toUpperCase().includes("TXT") ? "TXT" : undefined}
      />
    ) : null;
  }
  if (isTcpLike && typeof item.streamId === "number") {
    return <FilterActions protocol="tcp" streamId={item.streamId} />;
  }
  if (item.host || item.uri) {
    return <FilterActions protocol="http" host={item.host} uri={item.uri} />;
  }
  if (typeof item.streamId === "number") {
    return <FilterActions protocol="tcp" streamId={item.streamId} />;
  }
  return null;
}

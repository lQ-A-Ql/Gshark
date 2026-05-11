import { SearchCode, Shield, Sparkles } from "lucide-react";

import { MetricCard } from "../../components/DesignSystem";
import type { ThreatHit } from "../../core/types";
import type { ThreatHuntingStats } from "./ThreatHuntingPanels";

interface ThreatHuntingMetricCardsProps {
  hits: ThreatHit[];
  stats: ThreatHuntingStats;
}

export function ThreatHuntingMetricCards({ hits, stats }: ThreatHuntingMetricCardsProps) {
  const highRiskCount = hits.filter((item) => item.level === "critical" || item.level === "high").length;

  return (
    <div className="mb-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
      <MetricCard
        label="总命中"
        value={hits.length.toLocaleString()}
        hint="当前规则集返回的全部命中"
        icon={<SearchCode className="h-4 w-4 text-blue-600" />}
        tone="blue"
      />
      <MetricCard
        label="高风险"
        value={highRiskCount.toLocaleString()}
        hint="critical / high 级别命中"
        icon={<Shield className="h-4 w-4 text-rose-600" />}
        tone="rose"
      />
      <MetricCard
        label="CTF / 异常"
        value={`${stats.ctf.toLocaleString()} / ${stats.anomaly.toLocaleString()}`}
        hint="Flag 前缀与异常特征命中"
        icon={<Sparkles className="h-4 w-4 text-amber-600" />}
        tone="amber"
      />
    </div>
  );
}

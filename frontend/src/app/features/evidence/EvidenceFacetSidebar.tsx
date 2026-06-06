import { StatusHint, SurfacePanel } from "../../components/DesignSystem";
import type { EvidenceFacetGroups, EvidenceFacetState } from "./evidencePanelRules";
import { confidenceLabel } from "./evidencePanelRules";
import { EvidenceFacetGroup } from "./EvidenceFacetGroup";

interface EvidenceFacetSidebarProps {
  facets: EvidenceFacetState;
  facetGroups: EvidenceFacetGroups;
  onToggleFacet: (group: keyof EvidenceFacetState, value: string) => void;
  onResetFacets: () => void;
}

export function EvidenceFacetSidebar({
  facets,
  facetGroups,
  onToggleFacet,
  onResetFacets,
}: EvidenceFacetSidebarProps) {
  return (
    <SurfacePanel
      title="调查切面"
      description="按现有证据字段组合筛选结果，未提供的字段不会伪造补全。"
      variant="section"
      actions={
        <button type="button" className="meow-control px-3 py-1 text-[11px] text-slate-600" onClick={onResetFacets}>
          清空切面
        </button>
      }
      className="h-full"
      bodyClassName="space-y-3"
    >
      <EvidenceFacetGroup title="来源类型" options={facetGroups.sourceTypes} selected={facets.sourceTypes} onToggle={(value) => onToggleFacet("sourceTypes", value)} />
      <EvidenceFacetGroup title="特征" options={facetGroups.features} selected={facets.features} onToggle={(value) => onToggleFacet("features", value)} />
      <EvidenceFacetGroup title="实体" options={facetGroups.entities} selected={facets.entities} onToggle={(value) => onToggleFacet("entities", value)} />
      <EvidenceFacetGroup
        title="置信标签"
        options={facetGroups.confidenceLabels.map((item) => ({ ...item, label: confidenceLabel(item.value) }))}
        selected={facets.confidenceLabels}
        onToggle={(value) => onToggleFacet("confidenceLabels", value)}
      />
      {facetGroups.features.length === 0 && facetGroups.entities.length === 0 ? (
        <StatusHint tone="slate">当前证据未提供更多 feature/entity 字段，侧栏仅展示已支持的切面。</StatusHint>
      ) : null}
    </SurfacePanel>
  );
}

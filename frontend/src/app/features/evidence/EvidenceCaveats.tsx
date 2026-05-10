import type { UnifiedEvidenceRecord } from "./evidenceSchema";
import { collectEvidenceCaveats } from "./evidencePanelRules";

interface EvidenceCaveatsProps {
  records: UnifiedEvidenceRecord[];
}

export function EvidenceCaveats({ records }: EvidenceCaveatsProps) {
  const caveats = collectEvidenceCaveats(records);
  if (caveats.length === 0) return null;

  return (
    <div className="mt-4 rounded-2xl border border-amber-100 bg-amber-50/60 px-4 py-3 text-[11px] text-amber-700">
      <div className="mb-1 font-semibold">证据使用提示</div>
      <ul className="list-inside list-disc space-y-0.5">
        {caveats.map((caveat) => (
          <li key={caveat}>{caveat}</li>
        ))}
      </ul>
    </div>
  );
}

import { useEffect, useMemo, useState } from "react";
import type { BatchItem } from "./StreamDecoderWorkbenchUtils";

export function useDecoderBatchRange(batchItems?: BatchItem[], selectedBatchIndex?: number) {
  const selectedBatchOrdinal = useMemo(() => {
    if (!batchItems || batchItems.length === 0) return 1;
    const hit = batchItems.findIndex((item) => item.index === selectedBatchIndex);
    return (hit >= 0 ? hit : 0) + 1;
  }, [batchItems, selectedBatchIndex]);
  const [rangeStart, setRangeStart] = useState(() => String(selectedBatchOrdinal));
  const [rangeEnd, setRangeEnd] = useState(() => String(selectedBatchOrdinal));

  useEffect(() => {
    setRangeStart(String(selectedBatchOrdinal));
    setRangeEnd(String(selectedBatchOrdinal));
  }, [selectedBatchOrdinal, batchItems?.length]);

  return { rangeEnd, rangeStart, selectedBatchOrdinal, setRangeEnd, setRangeStart };
}

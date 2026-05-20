import { cn } from "../components/ui/utils";
import { getRawDirectionLabel, type VisibleRawChunk } from "./RawStreamUtils";
import type { RawStreamTone } from "./RawStreamTone";

export function RawDirectionBadge({ chunk, tone }: { chunk: VisibleRawChunk; tone: RawStreamTone }) {
  return (
    <span
      className={cn(
        "gshark-diffuse-chip px-2.5 py-1 text-[11px] font-semibold",
        chunk.direction === "client" ? tone.clientBadge : tone.serverBadge,
      )}
    >
      {getRawDirectionLabel(chunk.direction)}
    </span>
  );
}

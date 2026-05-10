import type { ReactNode } from "react";
import { cn } from "../ui/utils";
import { HighlightedPayloadText } from "./StreamPayloadHighlight";

export function StreamChunkCard({
  directionLabel,
  packetId,
  rendered,
  highlight,
  selected,
  tone,
  onSelect,
  onOpen,
  truncated,
  minHeight = "min-h-[164px]",
  className,
}: {
  directionLabel: ReactNode;
  packetId: number;
  rendered: string;
  highlight?: string;
  selected: boolean;
  tone: string;
  onSelect: () => void;
  onOpen?: () => void;
  truncated?: boolean;
  minHeight?: string;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "flex min-w-0 cursor-pointer flex-col rounded-2xl border px-3 py-2 shadow-sm transition-[border-color,box-shadow,transform] duration-200 hover:-translate-y-0.5 hover:shadow-md",
        minHeight,
        tone,
        selected && "ring-2 ring-violet-200 shadow-[0_18px_38px_rgba(99,102,241,0.14)]",
        className,
      )}
      onClick={onSelect}
    >
      <div className="mb-1 flex items-center justify-between gap-3 text-[11px] font-semibold opacity-80">
        <span className="mr-2 select-none">{directionLabel}</span>
        <span className="shrink-0">packet #{packetId}</span>
      </div>
      <pre className="mt-1 min-w-0 flex-1 overflow-hidden whitespace-pre-wrap break-all text-xs leading-5">
        <HighlightedPayloadText text={rendered} highlight={highlight} />
      </pre>
      {truncated && onOpen ? (
        <div className="mt-2 flex justify-end text-[11px] opacity-80">
          <button
            type="button"
            className="rounded border border-current/20 px-2 py-1 hover:opacity-100"
            onClick={(event) => {
              event.stopPropagation();
              onOpen();
            }}
          >
            查看完整 payload
          </button>
        </div>
      ) : null}
    </div>
  );
}

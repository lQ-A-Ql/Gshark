import type { ReactNode } from "react";
import { cn } from "../ui/utils";
import { HighlightedPayloadText } from "./StreamPayloadHighlight";

export function StreamCurrentChunkPanel({
  title = "当前片段",
  description,
  badge,
  chips = [],
  content,
  highlight,
  emptyText = "选择左侧片段后，可在这里固定查看详情。",
  showOpenButton,
  openButtonLabel = "查看完整 payload",
  onOpen,
  className,
}: {
  title?: ReactNode;
  description?: ReactNode;
  badge?: ReactNode;
  chips?: ReactNode[];
  content?: string | null;
  highlight?: string;
  emptyText?: ReactNode;
  showOpenButton?: boolean;
  openButtonLabel?: string;
  onOpen?: () => void;
  className?: string;
}) {
  const hasContent = Boolean(content);

  return (
    <div
      className={cn(
        "overflow-hidden rounded-[24px] border border-white/80 bg-white/88 p-5 shadow-[0_22px_55px_rgba(148,163,184,0.16)] backdrop-blur-xl",
        className,
      )}
    >
      <div className="mb-4 flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="text-sm font-semibold tracking-tight text-slate-900">{title}</div>
          {description ? <div className="mt-1 text-[11px] leading-5 text-slate-500">{description}</div> : null}
        </div>
        {badge ? <div className="shrink-0">{badge}</div> : null}
      </div>

      {hasContent ? (
        <>
          {chips.length > 0 ? (
            <div className="mb-3 flex flex-wrap gap-2 text-[11px]">
              {chips.map((chip, index) => (
                <span
                  key={index}
                  className="rounded-full border border-slate-200 bg-white/90 px-2.5 py-1 text-slate-500 shadow-sm"
                >
                  {chip}
                </span>
              ))}
            </div>
          ) : null}
          <div className="max-h-[380px] overflow-auto rounded-2xl border border-slate-100 bg-slate-50/75 p-3 shadow-inner shadow-slate-200/40">
            <pre className="whitespace-pre-wrap break-all font-mono text-xs leading-5 text-slate-800">
              <HighlightedPayloadText text={content ?? ""} highlight={highlight} />
            </pre>
          </div>
          {showOpenButton && onOpen ? (
            <button
              type="button"
              className="mt-3 rounded-full border border-slate-200 bg-white/90 px-3 py-1.5 text-xs font-medium text-slate-500 shadow-sm transition-all hover:border-violet-200 hover:bg-violet-50 hover:text-violet-700"
              onClick={onOpen}
            >
              {openButtonLabel}
            </button>
          ) : null}
        </>
      ) : (
        <div className="rounded-2xl border border-dashed border-slate-200 bg-slate-50/70 px-3 py-8 text-center text-xs leading-6 text-slate-500">
          {emptyText}
        </div>
      )}
    </div>
  );
}

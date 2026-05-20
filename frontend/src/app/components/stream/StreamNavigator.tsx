import { cn } from "../ui/utils";

export function StreamNavigator({
  protocolLabel,
  ordinalLabel,
  streamId,
  streamTotal,
  streamInput,
  onStreamInputChange,
  onSubmitStream,
  onPrev,
  onNext,
  hasPrev,
  hasNext,
  disabled,
  className,
}: {
  protocolLabel: string;
  ordinalLabel: string;
  streamId: number;
  streamTotal: number;
  streamInput: string;
  onStreamInputChange: (value: string) => void;
  onSubmitStream: () => void;
  onPrev: () => void;
  onNext: () => void;
  hasPrev: boolean;
  hasNext: boolean;
  disabled?: boolean;
  className?: string;
}) {
  const title = `${protocolLabel} 流总数: ${streamTotal}`;
  return (
    <div className={cn("gshark-stream-control-cluster flex flex-wrap items-center gap-2 px-2 py-1 text-xs", className)}>
      <span className="px-1 text-[11px] font-medium text-muted-foreground">流切换</span>
      <button
        type="button"
        className="gshark-control-ghost min-h-6 min-w-6 px-1.5 py-0.5 text-muted-foreground hover:text-foreground disabled:opacity-40"
        onClick={onPrev}
        disabled={disabled || !hasPrev}
        title={title}
      >
        ‹
      </button>
      <span
        className="gshark-stream-segment min-w-[11rem] px-2 py-0.5 text-center font-mono text-[11px] text-foreground"
        title={title}
      >
        第 {ordinalLabel} 条 / stream eq {streamId}
      </span>
      <button
        type="button"
        className="gshark-control-ghost min-h-6 min-w-6 px-1.5 py-0.5 text-muted-foreground hover:text-foreground disabled:opacity-40"
        onClick={onNext}
        disabled={disabled || !hasNext}
        title={title}
      >
        ›
      </button>
      <input
        value={streamInput}
        onChange={(event) => onStreamInputChange(event.target.value.replace(/[^0-9]/g, ""))}
        onKeyDown={(event) => {
          if (event.key === "Enter") {
            onSubmitStream();
          }
        }}
        className="gshark-stream-value w-16 px-1 py-0.5 text-center font-mono text-[11px] outline-none"
        placeholder="stream"
        title={title}
        disabled={disabled}
      />
    </div>
  );
}

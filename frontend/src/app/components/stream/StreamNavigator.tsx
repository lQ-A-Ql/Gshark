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
    <div
      className={cn(
        "flex flex-wrap items-center gap-2 rounded-md border border-border bg-background px-2 py-1 text-xs",
        className,
      )}
    >
      <span className="text-muted-foreground">流切换</span>
      <button
        type="button"
        className="rounded border border-border bg-accent p-1 text-muted-foreground hover:bg-accent/80 hover:text-foreground disabled:opacity-40"
        onClick={onPrev}
        disabled={disabled || !hasPrev}
        title={title}
      >
        ‹
      </button>
      <span className="min-w-[11rem] px-1 text-center font-mono text-foreground" title={title}>
        第 {ordinalLabel} 条 / stream eq {streamId}
      </span>
      <button
        type="button"
        className="rounded border border-border bg-accent p-1 text-muted-foreground hover:bg-accent/80 hover:text-foreground disabled:opacity-40"
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
        className="w-16 rounded border border-border bg-card px-1 py-0.5 text-center font-mono outline-none"
        placeholder="stream"
        title={title}
        disabled={disabled}
      />
    </div>
  );
}

import { cn } from "../ui/utils";

export function ViewModeToggle<T extends string>({
  label = "显示方式",
  value,
  options,
  onChange,
  className,
}: {
  label?: string;
  value: T;
  options: Array<{ value: T; label: string }>;
  onChange: (value: T) => void;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "gshark-stream-control-cluster flex flex-wrap items-center gap-2 px-2 py-1 text-xs font-medium text-muted-foreground",
        className,
      )}
    >
      <span className="px-1 text-[11px]">{label}:</span>
      <div className="gshark-stream-segment flex p-0.5">
        {options.map((option) => (
          <button
            key={option.value}
            type="button"
            onClick={() => onChange(option.value)}
            className={cn(
              "rounded-sm px-2.5 py-0.5 text-[11px] transition-colors",
              value === option.value
                ? "gshark-control-primary font-semibold text-white"
                : "text-muted-foreground hover:text-foreground",
            )}
          >
            {option.label}
          </button>
        ))}
      </div>
    </div>
  );
}

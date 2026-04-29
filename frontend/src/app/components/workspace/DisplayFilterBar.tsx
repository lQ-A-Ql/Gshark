import type { Ref } from "react";
import { Filter, Play, RefreshCw, XCircle } from "lucide-react";

export function DisplayFilterBar({
  value,
  suggestions,
  inputRef,
  disabled,
  onChange,
  onApply,
  onClear,
  onClearHistory,
}: {
  value: string;
  suggestions: string[];
  inputRef: Ref<HTMLInputElement>;
  disabled: boolean;
  onChange: (value: string) => void;
  onApply: () => void;
  onClear: () => void;
  onClearHistory: () => void;
}) {
  return (
    <div className="flex shrink-0 items-center gap-2 border-b border-border bg-background px-3 py-2">
      <Filter className="h-4 w-4 text-muted-foreground" />
      <span className="text-xs text-muted-foreground">显示过滤器</span>
      <div className="flex flex-1 items-center overflow-hidden rounded-md border border-border bg-card shadow-sm transition-all focus-within:border-blue-500 focus-within:ring-1 focus-within:ring-blue-500">
        <input
          id="display-filter-input"
          list="gshark-filter-suggestions"
          ref={inputRef}
          type="text"
          name="display-filter-input"
          autoComplete="off"
          autoCorrect="off"
          autoCapitalize="none"
          spellCheck={false}
          aria-autocomplete="list"
          value={value}
          onChange={(event) => onChange(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter") onApply();
          }}
          className="flex-1 border-none bg-transparent px-3 py-1 text-xs font-mono text-foreground placeholder:text-muted-foreground focus:outline-none"
          placeholder={'例如: http.request.method == "POST" and ip.addr == 192.168.1.10'}
        />
        <datalist id="gshark-filter-suggestions">
          {suggestions.map((item) => (
            <option key={item} value={item} />
          ))}
        </datalist>
        {value && (
          <button onClick={onClear} className="px-2 text-muted-foreground transition-colors hover:text-rose-500" title="清空过滤">
            <XCircle className="h-4 w-4" />
          </button>
        )}
      </div>
      <button
        onClick={onApply}
        disabled={disabled}
        className="flex items-center gap-1 rounded-md border border-border bg-card px-3 py-1 text-xs text-foreground shadow-sm transition-all hover:bg-accent disabled:opacity-60"
      >
        <Play className="h-3 w-3 text-blue-600" /> 应用
      </button>
      <button
        onClick={onClear}
        disabled={disabled}
        className="flex items-center gap-1 rounded-md border border-border bg-card px-3 py-1 text-xs text-muted-foreground transition-all hover:bg-accent disabled:opacity-60"
      >
        <RefreshCw className="h-3 w-3" /> 清除
      </button>
      <button
        onClick={onClearHistory}
        className="rounded-md border border-border bg-card px-2 py-1 text-[11px] text-muted-foreground transition-all hover:bg-accent"
        title="清空最近过滤历史"
      >
        清空历史
      </button>
    </div>
  );
}

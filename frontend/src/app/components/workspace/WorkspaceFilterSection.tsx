import type { Ref } from "react";
import { DisplayFilterBar } from "./DisplayFilterBar";

type WorkspaceFilterSectionProps = {
  value: string;
  suggestions: string[];
  inputRef: Ref<HTMLInputElement>;
  disabled: boolean;
  errorMessage: string;
  onChange: (value: string) => void;
  onApply: () => void;
  onClear: () => void;
  onClearHistory: () => void;
};

export function WorkspaceFilterSection({
  value,
  suggestions,
  inputRef,
  disabled,
  errorMessage,
  onChange,
  onApply,
  onClear,
  onClearHistory,
}: WorkspaceFilterSectionProps) {
  return (
    <>
      <div className="gshark-tile-toolbar border-b border-blue-100">
        <DisplayFilterBar
          value={value}
          suggestions={suggestions}
          inputRef={inputRef}
          disabled={disabled}
          onChange={onChange}
          onApply={onApply}
          onClear={onClear}
          onClearHistory={onClearHistory}
        />
        <div className="px-3 pb-2 text-[11px] text-slate-500">
          {
            '过滤器已切换为 tshark display filter 原生语法，支持 "http.request"、"tcp.stream eq 3"、"frame.number >= 100"、"ip.addr == 192.168.1.10" 等表达式。'
          }
        </div>
      </div>
      {errorMessage && (
        <div className="shrink-0 border-b border-rose-200 bg-rose-500/10 px-3 py-2 text-[11px] text-rose-700">
          {errorMessage}
        </div>
      )}
    </>
  );
}

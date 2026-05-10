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
      <div className="border-b border-blue-100 bg-white/80 shadow-[0_12px_32px_rgba(148,163,184,0.12)] backdrop-blur-xl">
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

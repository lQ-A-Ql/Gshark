import { Check, ChevronDown } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import type { MiscModuleFormField } from "../../core/types";

export const miscFieldSurfaceClass =
  "border-slate-200/80 bg-gradient-to-br from-white to-slate-50/80 text-slate-900 shadow-[0_1px_0_rgba(15,23,42,0.03),0_10px_24px_rgba(15,23,42,0.04)] transition-all placeholder:text-slate-400 hover:border-cyan-200 hover:bg-white focus:border-cyan-400 focus:bg-white focus:ring-4 focus:ring-cyan-100/70 disabled:cursor-not-allowed disabled:opacity-60";

interface GenericMiscSelectFieldProps {
  field: MiscModuleFormField;
  value: string;
  onChange: (next: string) => void;
  disabled: boolean;
}

export function GenericMiscSelectField({ field, value, onChange, disabled }: GenericMiscSelectFieldProps) {
  const [open, setOpen] = useState(false);
  const [rendered, setRendered] = useState(false);
  const rootRef = useRef<HTMLDivElement | null>(null);
  const closeTimerRef = useRef<number | undefined>(undefined);
  const options = field.options ?? [];
  const selected = options.find((option) => option.value === value);
  const placeholder = field.placeholder ?? "请选择";
  const displayText = selected?.label || placeholder;
  const allOptions = [{ label: placeholder, value: "" }, ...options];

  const clearCloseTimer = () => {
    if (closeTimerRef.current !== undefined) {
      window.clearTimeout(closeTimerRef.current);
      closeTimerRef.current = undefined;
    }
  };

  const openDropdown = () => {
    clearCloseTimer();
    setRendered(true);
    setOpen(true);
  };

  const closeDropdown = () => {
    clearCloseTimer();
    setOpen(false);
    closeTimerRef.current = window.setTimeout(() => {
      setRendered(false);
      closeTimerRef.current = undefined;
    }, 170);
  };

  useEffect(() => () => clearCloseTimer(), []);

  useEffect(() => {
    if (!open) {
      return undefined;
    }
    const handlePointerDown = (event: MouseEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) {
        closeDropdown();
      }
    };
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        closeDropdown();
      }
    };
    document.addEventListener("mousedown", handlePointerDown);
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("mousedown", handlePointerDown);
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [open]);

  useEffect(() => {
    if (disabled) {
      closeDropdown();
    }
  }, [disabled]);

  return (
    <div ref={rootRef} className="relative">
      <div
        role="button"
        tabIndex={disabled ? -1 : 0}
        aria-disabled={disabled}
        aria-expanded={open}
        aria-haspopup="listbox"
        onClick={(event) => {
          event.preventDefault();
          if (!disabled) {
            if (open) {
              closeDropdown();
            } else {
              openDropdown();
            }
          }
        }}
        onKeyDown={(event) => {
          if (disabled) {
            return;
          }
          if (event.key === "Enter" || event.key === " " || event.key === "ArrowDown") {
            event.preventDefault();
            openDropdown();
          }
        }}
        className={`flex h-11 w-full cursor-pointer items-center justify-between gap-3 rounded-xl border px-3.5 text-sm outline-none ${miscFieldSurfaceClass} ${
          open ? "border-cyan-400 bg-white ring-4 ring-cyan-100/70" : ""
        } ${disabled ? "cursor-not-allowed opacity-60" : ""}`}
      >
        <span className={`min-w-0 truncate ${selected ? "text-slate-900" : "text-slate-400"}`}>{displayText}</span>
        <ChevronDown
          className={`h-4 w-4 shrink-0 text-slate-400 transition-transform duration-200 ${
            open ? "rotate-180 text-cyan-500" : ""
          }`}
        />
      </div>

      {rendered ? (
        <div
          role="listbox"
          className={`absolute left-0 right-0 top-full z-50 mt-2 origin-top overflow-hidden rounded-2xl border border-cyan-100 bg-white/95 p-1.5 shadow-[0_22px_55px_rgba(8,145,178,0.18)] ring-1 ring-cyan-50 backdrop-blur ${
            open
              ? "animate-[misc-select-panel-in_180ms_cubic-bezier(0.22,1,0.36,1)_both]"
              : "pointer-events-none animate-[misc-select-panel-out_160ms_cubic-bezier(0.4,0,1,1)_both]"
          }`}
        >
          <div
            className={`pointer-events-none absolute inset-x-0 top-0 h-12 bg-gradient-to-b from-transparent via-cyan-200/35 to-transparent ${
              open
                ? "animate-[misc-select-stream_820ms_cubic-bezier(0.22,1,0.36,1)_both]"
                : "animate-[misc-select-stream-out_160ms_cubic-bezier(0.4,0,1,1)_both]"
            }`}
          />
          <div className="max-h-[min(16rem,calc(100vh-12rem))] overflow-auto pr-1">
            {allOptions.map((option, index) => {
              const active = option.value === value;
              return (
                <button
                  key={`${field.name}-${option.value || "__empty"}`}
                  type="button"
                  role="option"
                  aria-selected={active}
                  onClick={(event) => {
                    event.preventDefault();
                    onChange(option.value);
                    closeDropdown();
                  }}
                  style={{ animationDelay: open ? `${Math.min(index * 24, 144)}ms` : "0ms" }}
                  className={`group relative flex w-full items-center justify-between gap-3 rounded-xl px-3 py-2.5 text-left text-sm transition-colors ${
                    open
                      ? "animate-[misc-select-option-in_220ms_cubic-bezier(0.22,1,0.36,1)_both]"
                      : "animate-[misc-select-option-out_120ms_cubic-bezier(0.4,0,1,1)_both]"
                  } ${
                    active
                      ? "bg-gradient-to-r from-cyan-50 to-sky-50 font-semibold text-cyan-800"
                      : "text-slate-700 hover:bg-slate-50 hover:text-cyan-700"
                  }`}
                >
                  <span className="min-w-0 truncate">{option.label || option.value || placeholder}</span>
                  {active ? <Check className="h-4 w-4 shrink-0 text-cyan-500" /> : null}
                </button>
              );
            })}
          </div>
        </div>
      ) : null}
    </div>
  );
}

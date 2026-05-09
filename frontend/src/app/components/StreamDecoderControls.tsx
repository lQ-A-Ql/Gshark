import { type ReactNode } from "react";
import { Cog, LoaderCircle, type LucideIcon } from "lucide-react";
import { EMPTY_SELECT_VALUE } from "./StreamDecoderWorkbenchUtils";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "./ui/select";

export function DecoderButton({
  icon: Icon,
  label,
  active,
  disabled,
  onClick,
}: {
  icon: LucideIcon;
  label: string;
  active: boolean;
  disabled: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      disabled={disabled || active}
      className="inline-flex items-center gap-2 rounded-lg border border-border bg-background px-3 py-2 text-xs font-medium text-foreground shadow-sm transition-colors hover:bg-accent disabled:cursor-not-allowed disabled:opacity-60"
    >
      {active ? <LoaderCircle className="h-3.5 w-3.5 animate-spin" /> : <Icon className="h-3.5 w-3.5" />}
      {label}
    </button>
  );
}

export function ApplyModeButton({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`rounded-md border px-2.5 py-1 text-[11px] font-medium transition-colors ${
        active
          ? "border-blue-300 bg-blue-50 text-blue-700"
          : "border-border bg-background text-muted-foreground hover:bg-accent hover:text-foreground"
      }`}
    >
      {label}
    </button>
  );
}

export function SettingsButton({ onClick }: { onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="inline-flex items-center rounded-lg border border-border bg-background p-2 text-muted-foreground shadow-sm transition-colors hover:bg-accent hover:text-foreground"
      title="解码设置"
    >
      <Cog className="h-3.5 w-3.5" />
    </button>
  );
}

export function DecoderSettingsSection({
  title,
  onClose,
  children,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
}) {
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="text-sm font-semibold text-foreground">{title}</div>
        <button
          onClick={onClose}
          className="rounded border border-border px-2 py-1 text-xs text-muted-foreground hover:bg-accent hover:text-foreground"
        >
          收起
        </button>
      </div>
      {children}
    </div>
  );
}

export function LabeledInput({
  label,
  value,
  onChange,
  placeholder,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
}) {
  return (
    <label className="flex flex-col gap-1 text-xs text-muted-foreground">
      <span>{label}</span>
      <input
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        className="rounded-md border border-border bg-background px-3 py-2 font-mono text-foreground outline-none focus:border-blue-500"
      />
    </label>
  );
}

export function LabeledSelect({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string;
  options: Array<[string, string]>;
  onChange: (value: string) => void;
}) {
  const selectedValue = value === "" ? EMPTY_SELECT_VALUE : value;
  return (
    <div className="flex flex-col gap-1 text-xs text-muted-foreground">
      <span>{label}</span>
      <Select value={selectedValue} onValueChange={(next) => onChange(next === EMPTY_SELECT_VALUE ? "" : next)}>
        <SelectTrigger className="h-9 rounded-md border-border bg-background text-xs text-foreground focus:border-blue-500 focus:ring-blue-100">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {options.map(([optionValue, optionLabel]) => (
            <SelectItem key={optionValue || EMPTY_SELECT_VALUE} value={optionValue || EMPTY_SELECT_VALUE}>
              {optionLabel}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  );
}

export function LabeledToggle({
  label,
  checked,
  onChange,
}: {
  label: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
}) {
  return (
    <label className="flex items-center gap-2 rounded-md border border-border bg-background px-3 py-2 text-xs text-foreground">
      <input
        type="checkbox"
        checked={checked}
        onChange={(event) => onChange(event.target.checked)}
        className="accent-blue-600"
      />
      <span>{label}</span>
    </label>
  );
}

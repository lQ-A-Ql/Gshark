import { SelectField, type SelectOption } from "../../components/ui/select";
import type { MiscModuleFormField } from "../../core/types";

export const miscFieldSurfaceClass =
  "gshark-field text-slate-900 transition-all placeholder:text-slate-400 disabled:cursor-not-allowed disabled:opacity-60";

interface GenericMiscSelectFieldProps {
  field: MiscModuleFormField;
  value: string;
  onChange: (next: string) => void;
  disabled: boolean;
}

export function GenericMiscSelectField({ field, value, onChange, disabled }: GenericMiscSelectFieldProps) {
  const options = field.options ?? [];
  const placeholder = field.placeholder ?? "请选择";
  const selectOptions: SelectOption[] = [
    { label: placeholder, value: "" },
    ...options.map((option) => ({ label: option.label || option.value || placeholder, value: option.value })),
  ];

  return (
    <SelectField
      label={field.label}
      value={value}
      onValueChange={onChange}
      options={selectOptions}
      disabled={disabled}
      placeholder={placeholder}
      size="md"
      tone="cyan"
      fieldClassName="gap-2"
      labelClassName="sr-only"
      triggerClassName={`h-11 px-3.5 text-sm ${miscFieldSurfaceClass}`}
      contentClassName="border-cyan-200/14 shadow-[0_18px_48px_rgba(8,145,178,0.06),0_0_34px_rgba(255,255,255,0.22)] ring-cyan-50/30"
    />
  );
}

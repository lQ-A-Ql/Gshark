import { SelectField, type SelectOption } from "../../components/ui/select";
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
      triggerClassName={`h-11 rounded-xl px-3.5 text-sm ${miscFieldSurfaceClass}`}
      contentClassName="border-cyan-100 shadow-[0_22px_55px_rgba(8,145,178,0.18)] ring-cyan-50"
    />
  );
}

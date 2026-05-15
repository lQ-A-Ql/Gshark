import * as React from "react";
import * as SelectPrimitive from "@radix-ui/react-select";
import { Check, ChevronDown, ChevronUp } from "lucide-react";

import { cn } from "./utils";

const EMPTY_SELECT_VALUE = "__gshark_empty_select_value__";

export type SelectOption = {
  value: string;
  label: string;
  disabled?: boolean;
  description?: string;
};

type SelectSize = "sm" | "md";
type SelectTone = "blue" | "cyan" | "rose" | "slate";

const selectSizeClasses: Record<SelectSize, string> = {
  sm: "h-8 rounded-lg px-2.5 text-[11px]",
  md: "h-9 rounded-xl px-3 text-xs",
};

const selectToneClasses: Record<SelectTone, string> = {
  blue: "hover:border-blue-200 hover:bg-blue-50/30 focus:border-blue-400 focus:ring-blue-100 data-[state=open]:border-blue-400 data-[state=open]:ring-blue-100",
  cyan: "hover:border-cyan-200 hover:bg-cyan-50/40 focus:border-cyan-400 focus:ring-cyan-100 data-[state=open]:border-cyan-400 data-[state=open]:ring-cyan-100",
  rose: "hover:border-rose-200 hover:bg-rose-50/30 focus:border-rose-300 focus:ring-rose-100 data-[state=open]:border-rose-300 data-[state=open]:ring-rose-100",
  slate:
    "hover:border-slate-300 hover:bg-slate-50 focus:border-slate-400 focus:ring-slate-100 data-[state=open]:border-slate-400 data-[state=open]:ring-slate-100",
};

const itemToneClasses: Record<SelectTone, string> = {
  blue: "focus:bg-blue-50 focus:text-blue-700 data-[highlighted]:bg-blue-50 data-[highlighted]:text-blue-700 data-[state=checked]:bg-blue-50 data-[state=checked]:text-blue-700",
  cyan: "focus:bg-cyan-50 focus:text-cyan-700 data-[highlighted]:bg-cyan-50 data-[highlighted]:text-cyan-700 data-[state=checked]:bg-cyan-50 data-[state=checked]:text-cyan-700",
  rose: "focus:bg-rose-50 focus:text-rose-700 data-[highlighted]:bg-rose-50 data-[highlighted]:text-rose-700 data-[state=checked]:bg-rose-50 data-[state=checked]:text-rose-700",
  slate:
    "focus:bg-slate-100 focus:text-slate-800 data-[highlighted]:bg-slate-100 data-[highlighted]:text-slate-800 data-[state=checked]:bg-slate-100 data-[state=checked]:text-slate-800",
};

function toRadixSelectValue(value: string) {
  return value === "" ? EMPTY_SELECT_VALUE : value;
}

function fromRadixSelectValue(value: string) {
  return value === EMPTY_SELECT_VALUE ? "" : value;
}

const Select = SelectPrimitive.Root;

const SelectGroup = SelectPrimitive.Group;

const SelectValue = SelectPrimitive.Value;

const SelectTrigger = React.forwardRef<
  React.ElementRef<typeof SelectPrimitive.Trigger>,
  React.ComponentPropsWithoutRef<typeof SelectPrimitive.Trigger>
>(({ className, children, ...props }, ref) => (
  <SelectPrimitive.Trigger
    ref={ref}
    className={cn(
      "flex h-9 w-full items-center justify-between gap-2 rounded-xl border border-slate-200 bg-white px-3 text-left text-[11px] text-slate-700 shadow-sm outline-none transition-all",
      "hover:border-blue-200 hover:bg-blue-50/30",
      "focus:border-blue-400 focus:ring-4 focus:ring-blue-100",
      "disabled:cursor-not-allowed disabled:opacity-50",
      "[&>span]:min-w-0 [&>span]:truncate",
      className,
    )}
    {...props}
  >
    {children}
    <SelectPrimitive.Icon asChild>
      <ChevronDown className="h-3.5 w-3.5 shrink-0 text-slate-400" />
    </SelectPrimitive.Icon>
  </SelectPrimitive.Trigger>
));
SelectTrigger.displayName = SelectPrimitive.Trigger.displayName;

const SelectScrollUpButton = React.forwardRef<
  React.ElementRef<typeof SelectPrimitive.ScrollUpButton>,
  React.ComponentPropsWithoutRef<typeof SelectPrimitive.ScrollUpButton>
>(({ className, ...props }, ref) => (
  <SelectPrimitive.ScrollUpButton
    ref={ref}
    className={cn("flex cursor-default items-center justify-center py-1 text-slate-500", className)}
    {...props}
  >
    <ChevronUp className="h-3.5 w-3.5" />
  </SelectPrimitive.ScrollUpButton>
));
SelectScrollUpButton.displayName = SelectPrimitive.ScrollUpButton.displayName;

const SelectScrollDownButton = React.forwardRef<
  React.ElementRef<typeof SelectPrimitive.ScrollDownButton>,
  React.ComponentPropsWithoutRef<typeof SelectPrimitive.ScrollDownButton>
>(({ className, ...props }, ref) => (
  <SelectPrimitive.ScrollDownButton
    ref={ref}
    className={cn("flex cursor-default items-center justify-center py-1 text-slate-500", className)}
    {...props}
  >
    <ChevronDown className="h-3.5 w-3.5" />
  </SelectPrimitive.ScrollDownButton>
));
SelectScrollDownButton.displayName = SelectPrimitive.ScrollDownButton.displayName;

const SelectContent = React.forwardRef<
  React.ElementRef<typeof SelectPrimitive.Content>,
  React.ComponentPropsWithoutRef<typeof SelectPrimitive.Content>
>(({ className, children, position = "popper", ...props }, ref) => (
  <SelectPrimitive.Portal>
    <SelectPrimitive.Content
      ref={ref}
      position={position}
      className={cn(
        "relative z-[1000] max-h-72 min-w-[var(--radix-select-trigger-width)] overflow-hidden rounded-xl border border-slate-200 bg-white text-xs text-slate-700 shadow-[0_22px_60px_rgba(15,23,42,0.16)] ring-1 ring-slate-100/80",
        "data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0",
        "data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95",
        position === "popper" && "data-[side=bottom]:translate-y-1 data-[side=top]:-translate-y-1",
        className,
      )}
      {...props}
    >
      <SelectScrollUpButton />
      <SelectPrimitive.Viewport className={cn("p-1", position === "popper" && "w-full")}>
        {children}
      </SelectPrimitive.Viewport>
      <SelectScrollDownButton />
    </SelectPrimitive.Content>
  </SelectPrimitive.Portal>
));
SelectContent.displayName = SelectPrimitive.Content.displayName;

const SelectItem = React.forwardRef<
  React.ElementRef<typeof SelectPrimitive.Item>,
  React.ComponentPropsWithoutRef<typeof SelectPrimitive.Item>
>(({ className, children, ...props }, ref) => (
  <SelectPrimitive.Item
    ref={ref}
    className={cn(
      "relative flex min-h-8 cursor-default select-none items-center rounded-lg py-2 pl-8 pr-3 text-[11px] outline-none transition-colors",
      "focus:bg-blue-50 focus:text-blue-700 data-[highlighted]:bg-blue-50 data-[highlighted]:text-blue-700",
      "data-[state=checked]:bg-blue-50 data-[state=checked]:font-semibold data-[state=checked]:text-blue-700",
      "data-[disabled]:pointer-events-none data-[disabled]:opacity-50",
      className,
    )}
    {...props}
  >
    <span className="absolute left-2 flex h-3.5 w-3.5 items-center justify-center">
      <SelectPrimitive.ItemIndicator>
        <Check className="h-3.5 w-3.5" />
      </SelectPrimitive.ItemIndicator>
    </span>
    <SelectPrimitive.ItemText>{children}</SelectPrimitive.ItemText>
  </SelectPrimitive.Item>
));
SelectItem.displayName = SelectPrimitive.Item.displayName;

interface SelectControlProps {
  value: string;
  options: SelectOption[];
  onValueChange: (value: string) => void;
  placeholder?: string;
  disabled?: boolean;
  "aria-label"?: string;
  size?: SelectSize;
  tone?: SelectTone;
  className?: string;
  triggerClassName?: string;
  contentClassName?: string;
}

function SelectControl({
  value,
  options,
  onValueChange,
  placeholder = "请选择",
  disabled = false,
  "aria-label": ariaLabel,
  size = "md",
  tone = "blue",
  className,
  triggerClassName,
  contentClassName,
}: SelectControlProps) {
  return (
    <Select value={toRadixSelectValue(value)} onValueChange={(next) => onValueChange(fromRadixSelectValue(next))}>
      <SelectTrigger
        aria-label={ariaLabel}
        disabled={disabled}
        className={cn(selectSizeClasses[size], selectToneClasses[tone], className, triggerClassName)}
      >
        <SelectValue placeholder={placeholder} />
      </SelectTrigger>
      <SelectContent className={contentClassName}>
        {options.map((option) => (
          <SelectItem
            key={toRadixSelectValue(option.value)}
            value={toRadixSelectValue(option.value)}
            disabled={option.disabled}
            className={cn(itemToneClasses[tone], option.description && "items-start py-2.5")}
          >
            <span className="flex min-w-0 flex-col">
              <span className="truncate">{option.label}</span>
              {option.description ? (
                <span className="mt-0.5 truncate text-[10px] font-normal text-slate-400">{option.description}</span>
              ) : null}
            </span>
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

interface SelectFieldProps extends Omit<SelectControlProps, "aria-label"> {
  label: string;
  help?: string;
  error?: string;
  fieldClassName?: string;
  labelClassName?: string;
}

function SelectField({
  label,
  help,
  error,
  fieldClassName,
  labelClassName,
  ...controlProps
}: SelectFieldProps) {
  return (
    <div className={cn("flex flex-col gap-1.5 text-xs text-muted-foreground", fieldClassName)}>
      <div className={cn("font-semibold text-slate-600", labelClassName)}>{label}</div>
      <SelectControl aria-label={label} {...controlProps} />
      {error ? <div className="text-[11px] font-medium text-rose-600">{error}</div> : null}
      {help && !error ? <div className="text-[11px] leading-5 text-slate-400">{help}</div> : null}
    </div>
  );
}

export {
  Select,
  SelectContent,
  SelectControl,
  SelectField,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
};

import type { CSSProperties, HTMLAttributes, ReactNode, Ref } from "react";
import { createPortal } from "react-dom";
import { cn } from "./utils";

type FloatingSurfaceProps = HTMLAttributes<HTMLDivElement> & {
  x: number;
  y: number;
  children: ReactNode;
  floatingRef?: Ref<HTMLDivElement>;
};

export function FloatingSurface({
  x,
  y,
  children,
  className,
  floatingRef,
  style,
  ...props
}: FloatingSurfaceProps) {
  if (typeof document === "undefined") return null;

  const surfaceStyle: CSSProperties = {
    left: x,
    top: y,
    ...style,
  };

  return createPortal(
    <div
      ref={floatingRef}
      className={cn(
        "fixed z-[1000] overflow-hidden rounded-xl border border-slate-200 bg-white/95 text-xs shadow-[0_24px_64px_rgba(15,23,42,0.16)] backdrop-blur",
        className,
      )}
      style={surfaceStyle}
      {...props}
    >
      {children}
    </div>,
    document.body,
  );
}

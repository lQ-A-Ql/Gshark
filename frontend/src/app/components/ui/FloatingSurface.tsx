import type { CSSProperties, HTMLAttributes, ReactNode, Ref } from "react";
import { createPortal } from "react-dom";
import { cn } from "./utils";

type FloatingSurfaceProps = HTMLAttributes<HTMLDivElement> & {
  x: number;
  y: number;
  children: ReactNode;
  floatingRef?: Ref<HTMLDivElement>;
};

export function FloatingSurface({ x, y, children, className, floatingRef, style, ...props }: FloatingSurfaceProps) {
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
        "fixed z-[1000] overflow-hidden rounded-sm border border-slate-200/30 bg-white/86 text-xs shadow-[0_20px_58px_rgba(15,23,42,0.1),0_0_38px_rgba(255,255,255,0.28)] backdrop-blur-xl",
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

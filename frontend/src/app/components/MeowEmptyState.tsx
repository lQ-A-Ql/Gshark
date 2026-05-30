import type { ReactNode } from "react";
import { cn } from "./ui/utils";

export type MeowCatVariant = "box" | "window" | "keyboard" | "headphones";

const variantClass: Record<MeowCatVariant, string> = {
  box: "meow-empty-cat-box",
  window: "meow-empty-cat-window",
  keyboard: "meow-empty-cat-keyboard",
  headphones: "meow-empty-cat-headphones",
};

const variantLabel: Record<MeowCatVariant, string> = {
  box: "猫咪在纸箱里打盹",
  window: "猫咪在窗台上看风景",
  keyboard: "猫咪趴在键盘上睡着了",
  headphones: "猫咪戴着没插线的耳机",
};

export function MeowEmptyState({
  variant = "box",
  children,
  className,
}: {
  variant?: MeowCatVariant;
  children?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("meow-empty-cat", className)}>
      <div
        className={cn("meow-empty-cat-figure text-slate-400", variantClass[variant])}
        role="img"
        aria-label={variantLabel[variant]}
      />
      {children && <div className="text-center text-xs leading-5 text-slate-500">{children}</div>}
    </div>
  );
}

import { lazy, Suspense, type ReactNode } from "react";

interface LazyMarkdownProps {
  children: string;
  components?: Record<string, (props: Record<string, any>) => ReactNode>;
  [key: string]: unknown;
}

const LazyReactMarkdown = lazy(() =>
  import("react-markdown").then(async (mod) => {
    const remarkGfm = (await import("remark-gfm")).default;
    const MarkdownComponent = mod.default;
    return {
      default: function MarkdownWithGfm(props: LazyMarkdownProps) {
        return <MarkdownComponent {...props} remarkPlugins={[remarkGfm]} />;
      },
    };
  }),
);

export function LazyMarkdown(props: LazyMarkdownProps) {
  return (
    <Suspense fallback={<div className="animate-pulse text-sm text-slate-400">加载中...</div>}>
      <LazyReactMarkdown {...props} />
    </Suspense>
  );
}

import type { HTMLAttributes, ReactNode } from "react";
import { normalizeReleaseMarkdownHref } from "./updateReleaseLinks";

function ReleaseMarkdownLink({ href, children }: { href?: string; children?: ReactNode }) {
  const safeHref = normalizeReleaseMarkdownHref(href);
  if (!safeHref) {
    return <span className="font-medium text-slate-500">{children}</span>;
  }

  return (
    <a
      href={safeHref}
      target="_blank"
      rel="noreferrer"
      className="font-medium text-blue-600 underline decoration-blue-200 underline-offset-4 hover:text-blue-700"
    >
      {children}
    </a>
  );
}

export const releaseMarkdownComponents = {
  h1: ({ children }: { children?: ReactNode }) => (
    <h1 className="mt-1 text-2xl font-semibold text-slate-900 first:mt-0">{children}</h1>
  ),
  h2: ({ children }: { children?: ReactNode }) => (
    <h2 className="mt-6 text-xl font-semibold text-slate-900 first:mt-0">{children}</h2>
  ),
  h3: ({ children }: { children?: ReactNode }) => (
    <h3 className="mt-5 text-lg font-semibold text-slate-900 first:mt-0">{children}</h3>
  ),
  p: ({ children }: { children?: ReactNode }) => (
    <p className="mt-3 text-sm leading-7 text-slate-700 first:mt-0">{children}</p>
  ),
  ul: ({ children }: { children?: ReactNode }) => (
    <ul className="mt-3 list-disc space-y-2 pl-5 text-sm leading-7 text-slate-700">{children}</ul>
  ),
  ol: ({ children }: { children?: ReactNode }) => (
    <ol className="mt-3 list-decimal space-y-2 pl-5 text-sm leading-7 text-slate-700">{children}</ol>
  ),
  li: ({ children }: { children?: ReactNode }) => <li className="pl-1">{children}</li>,
  blockquote: ({ children }: { children?: ReactNode }) => (
    <blockquote className="gshark-soft-fill mt-0 border-l-4 border-blue-200 px-4 py-3 text-sm leading-7 text-slate-700">
      {children}
    </blockquote>
  ),
  hr: () => <hr className="my-6 border-slate-200" />,
  a: ReleaseMarkdownLink,
  code: ({ children, ...props }: HTMLAttributes<HTMLElement>) => {
    const isInline = !String(children).includes("\n");
    return isInline ? (
      <code className="rounded bg-slate-200 px-1.5 py-0.5 font-mono text-[13px] text-slate-800" {...props}>
        {children}
      </code>
    ) : (
      <code className="font-mono text-[13px] text-slate-100" {...props}>
        {children}
      </code>
    );
  },
  pre: ({ children }: { children?: ReactNode }) => (
    <pre className="mt-4 overflow-x-auto border border-slate-800 bg-slate-900 p-4 text-[13px] leading-6 text-slate-100">
      {children}
    </pre>
  ),
  table: ({ children }: { children?: ReactNode }) => (
    <div className="gshark-tile-table mt-0 overflow-x-auto border-slate-200">
      <table className="min-w-full border-collapse text-left text-sm text-slate-700">{children}</table>
    </div>
  ),
  thead: ({ children }: { children?: ReactNode }) => <thead className="bg-slate-100 text-slate-800">{children}</thead>,
  th: ({ children }: { children?: ReactNode }) => (
    <th className="border-b border-slate-200 px-3 py-2 font-semibold">{children}</th>
  ),
  td: ({ children }: { children?: ReactNode }) => (
    <td className="border-b border-slate-100 px-3 py-2 align-top">{children}</td>
  ),
  strong: ({ children }: { children?: ReactNode }) => (
    <strong className="font-semibold text-slate-900">{children}</strong>
  ),
};

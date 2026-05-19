export function KeyboardEditedText({ deleted, text }: { deleted: string; text: string }) {
  return (
    <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
      <KeyboardTextBlock title="编辑后文本" value={text || "(未复原出编辑后文本)"} />
      <KeyboardTextBlock title="删除字符" value={deleted || "(未检测到删除字符)"} />
    </div>
  );
}

function KeyboardTextBlock({ title, value }: { title: string; value: string }) {
  return (
    <section className="rounded-2xl border border-border bg-card p-4 shadow-sm">
      <h3 className="text-sm font-semibold text-foreground">{title}</h3>
      <pre className="mt-3 max-h-[180px] overflow-auto whitespace-pre-wrap break-all rounded-md border border-border bg-background px-3 py-3 font-mono text-xs leading-5">
        {value}
      </pre>
    </section>
  );
}

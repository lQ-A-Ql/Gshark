export function KeyboardEditedText({ deleted, text }: { deleted: string; text: string }) {
  return (
    <div className="grid grid-cols-1 gap-0 xl:grid-cols-2">
      <KeyboardTextBlock title="编辑后文本" value={text || "(未复原出编辑后文本)"} />
      <KeyboardTextBlock title="删除字符" value={deleted || "(未检测到删除字符)"} />
    </div>
  );
}

function KeyboardTextBlock({ title, value }: { title: string; value: string }) {
  return (
    <section className="gshark-tile p-3.5">
      <h3 className="text-sm font-semibold text-foreground">{title}</h3>
      <pre className="gshark-soft-fill mt-3 max-h-[180px] overflow-auto whitespace-pre-wrap break-all px-3 py-3 font-mono text-xs leading-5">
        {value}
      </pre>
    </section>
  );
}

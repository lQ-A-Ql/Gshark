import { useRef, type ChangeEvent } from "react";
import { Upload } from "lucide-react";
import { Button } from "../components/ui/button";

interface MiscImportButtonsProps {
  importing: boolean;
  onImportModule: (file: File) => void | Promise<void>;
  onImportModuleFromNativeDialog?: () => void | Promise<void>;
}

export function MiscImportButtons({
  importing,
  onImportModule,
  onImportModuleFromNativeDialog,
}: MiscImportButtonsProps) {
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  function handleImportModule(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (file) void onImportModule(file);
  }

  return (
    <>
      <input ref={fileInputRef} type="file" accept=".zip" className="hidden" onChange={handleImportModule} />
      <div className="flex flex-wrap justify-start gap-2 lg:justify-end">
        {onImportModuleFromNativeDialog && (
          <Button
            type="button"
            onClick={() => void onImportModuleFromNativeDialog()}
            disabled={importing}
            className="h-9 rounded-sm bg-slate-900 px-4 text-xs font-semibold text-white hover:bg-slate-800"
          >
            <Upload className="mr-2 h-4 w-4" />
            {importing ? "导入中..." : "桌面原生导入"}
          </Button>
        )}
        <Button
          type="button"
          onClick={() => fileInputRef.current?.click()}
          disabled={importing}
          className="h-9 rounded-sm bg-cyan-600 px-4 text-xs font-semibold text-white hover:bg-cyan-700"
        >
          <Upload className="mr-2 h-4 w-4" />
          {importing ? "导入中..." : "导入模块 ZIP"}
        </Button>
      </div>
    </>
  );
}

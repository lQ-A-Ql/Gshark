import { Loader2, Trash2 } from "lucide-react";
import { Button } from "../../components/ui/button";

interface GenericMiscDeleteActionProps {
  canDelete: boolean;
  deleting: boolean;
  running: boolean;
  onDelete: () => void;
  variant: "embedded" | "card";
}

export function GenericMiscDeleteAction({
  canDelete,
  deleting,
  running,
  onDelete,
  variant,
}: GenericMiscDeleteActionProps) {
  if (!canDelete) return null;

  const className =
    variant === "embedded"
      ? "border-rose-200 bg-white text-rose-700 shadow-sm hover:bg-rose-50"
      : "border-rose-200 bg-white/80 text-rose-600 shadow-sm backdrop-blur hover:border-rose-300 hover:bg-rose-50 hover:text-rose-700";

  return (
    <Button
      type="button"
      variant="outline"
      size="sm"
      className={className}
      onClick={onDelete}
      disabled={deleting || running}
    >
      {deleting ? <Loader2 className="h-4 w-4 animate-spin" /> : <Trash2 className="h-4 w-4" />}
      {deleting ? "删除中..." : "删除模块"}
    </Button>
  );
}

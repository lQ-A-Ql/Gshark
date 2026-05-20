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
      ? "gshark-diffuse-chip border-rose-200/28 bg-rose-50/18 text-rose-700 hover:bg-rose-50/24"
      : "gshark-diffuse-chip border-rose-200/24 bg-rose-50/14 text-rose-600 hover:border-rose-300/35 hover:bg-rose-50/22 hover:text-rose-700";

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

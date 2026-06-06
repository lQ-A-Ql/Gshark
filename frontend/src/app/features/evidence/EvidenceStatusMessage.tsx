export function EvidenceStatusMessage({ error, loading, onRetry }: { error: string | null; loading: boolean; onRetry?: () => void }) {
  if (loading) {
    return (
      <div className="meow-tile mb-3 border-indigo-100 bg-indigo-50/60 px-3 py-2.5 text-xs font-medium text-slate-500">
        正在聚合跨模块证据...
      </div>
    );
  }

  if (!error) return null;

  return (
    <div className="meow-tile mb-3 flex items-center gap-2 border-amber-200 bg-amber-50/80 px-3 py-2.5 text-xs text-amber-700">
      <span>{error}</span>
      {onRetry && (
        <button
          type="button"
          onClick={onRetry}
          className="ml-auto shrink-0 rounded border border-amber-300 px-2 py-0.5 text-xs font-medium text-amber-700 hover:bg-amber-100"
        >
          重试
        </button>
      )}
    </div>
  );
}

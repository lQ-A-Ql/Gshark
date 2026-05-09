export type BrowserDragEventLike = {
  preventDefault: () => void;
  stopPropagation: () => void;
  target?: EventTarget | null;
};

function isExplicitDropZone(target: EventTarget | null | undefined) {
  return target instanceof Element && Boolean(target.closest("[data-gshark-drop-zone='true']"));
}

export function preventBrowserPageDrag(event: BrowserDragEventLike) {
  if (isExplicitDropZone(event.target)) {
    return;
  }
  event.preventDefault();
  event.stopPropagation();
}

export function installBrowserPageDragGuard() {
  window.addEventListener("dragstart", preventBrowserPageDrag, { capture: true });
  window.addEventListener("dragover", preventBrowserPageDrag, { capture: true });
  window.addEventListener("drop", preventBrowserPageDrag, { capture: true });
  document.addEventListener("dragstart", preventBrowserPageDrag, { capture: true });
  document.addEventListener("dragover", preventBrowserPageDrag, { capture: true });
  document.addEventListener("drop", preventBrowserPageDrag, { capture: true });
  return () => {
    window.removeEventListener("dragstart", preventBrowserPageDrag, { capture: true });
    window.removeEventListener("dragover", preventBrowserPageDrag, { capture: true });
    window.removeEventListener("drop", preventBrowserPageDrag, { capture: true });
    document.removeEventListener("dragstart", preventBrowserPageDrag, { capture: true });
    document.removeEventListener("dragover", preventBrowserPageDrag, { capture: true });
    document.removeEventListener("drop", preventBrowserPageDrag, { capture: true });
  };
}

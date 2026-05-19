import type { USBKeyboardEvent } from "../../core/types";

export function buildKeyboardEditedText(events: USBKeyboardEvent[]) {
  const text: string[] = [];
  const deleted: string[] = [];
  let capsLock = false;

  for (const event of events) {
    if (event.pressedKeys.includes("CapsLock")) {
      capsLock = !capsLock;
      continue;
    }
    if (event.pressedKeys.includes("Backspace")) {
      const removed = text.pop();
      if (removed) deleted.push(removed);
      continue;
    }
    const token = event.text ?? "";
    if (!token) continue;
    text.push(capsLock ? applyCapsLock(token) : token);
  }

  return { text: text.join(""), deleted: deleted.join("") };
}

function applyCapsLock(token: string) {
  return token.replace(/[a-zA-Z]/g, (char) => {
    const lower = char.toLowerCase();
    return char === lower ? char.toUpperCase() : lower;
  });
}

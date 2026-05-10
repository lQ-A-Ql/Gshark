import { useEffect, useMemo, useState } from "react";
import type { USBAnalysis } from "../../core/types";
import { keyboardReplayToken } from "./UsbHidPanels";

export type HidSubTab = "keyboard" | "mouse";

export function useUsbHidState(analysis: USBAnalysis) {
  const [activeSubTab, setActiveSubTab] = useState<HidSubTab>("keyboard");
  const [activeKeyboardDevice, setActiveKeyboardDevice] = useState("");
  const [keyboardCursor, setKeyboardCursor] = useState(0);
  const [isKeyboardPlaying, setIsKeyboardPlaying] = useState(false);
  const [activeMouseDevice, setActiveMouseDevice] = useState("");

  const keyboardEvents = useMemo(
    () => (analysis.hid.keyboardEvents.length > 0 ? analysis.hid.keyboardEvents : analysis.keyboardEvents),
    [analysis.hid.keyboardEvents, analysis.keyboardEvents],
  );
  const mouseEvents = useMemo(
    () => (analysis.hid.mouseEvents.length > 0 ? analysis.hid.mouseEvents : analysis.mouseEvents),
    [analysis.hid.mouseEvents, analysis.mouseEvents],
  );
  const notes = analysis.hid.notes.length > 0 ? analysis.hid.notes : analysis.notes;

  useEffect(() => {
    setActiveSubTab((prev) => {
      if (prev === "keyboard" && keyboardEvents.length > 0) return prev;
      if (prev === "mouse" && mouseEvents.length > 0) return prev;
      return keyboardEvents.length > 0 ? "keyboard" : "mouse";
    });
  }, [keyboardEvents.length, mouseEvents.length]);

  const keyboardDevices = useMemo(
    () => uniqueStrings(keyboardEvents.map((item) => item.device || item.endpoint).filter(Boolean)),
    [keyboardEvents],
  );
  const mouseDevices = useMemo(
    () => uniqueStrings(mouseEvents.map((item) => item.device || item.endpoint).filter(Boolean)),
    [mouseEvents],
  );

  useEffect(() => {
    if (keyboardDevices.length === 0) {
      setActiveKeyboardDevice("");
      return;
    }
    setActiveKeyboardDevice((prev) => (prev && keyboardDevices.includes(prev) ? prev : keyboardDevices[0]));
  }, [keyboardDevices]);

  useEffect(() => {
    if (mouseDevices.length === 0) {
      setActiveMouseDevice("");
      return;
    }
    setActiveMouseDevice((prev) => (prev && mouseDevices.includes(prev) ? prev : mouseDevices[0]));
  }, [mouseDevices]);

  const filteredKeyboardEvents = useMemo(() => {
    if (!activeKeyboardDevice) return keyboardEvents;
    return keyboardEvents.filter((item) => (item.device || item.endpoint) === activeKeyboardDevice);
  }, [activeKeyboardDevice, keyboardEvents]);

  const filteredMouseEvents = useMemo(() => {
    if (!activeMouseDevice) return mouseEvents;
    return mouseEvents.filter((item) => (item.device || item.endpoint) === activeMouseDevice);
  }, [activeMouseDevice, mouseEvents]);

  useEffect(() => {
    setKeyboardCursor((prev) => Math.min(prev, Math.max(filteredKeyboardEvents.length - 1, 0)));
    setIsKeyboardPlaying(false);
  }, [filteredKeyboardEvents]);

  useEffect(() => {
    if (!isKeyboardPlaying || filteredKeyboardEvents.length <= 1) return;
    if (keyboardCursor >= filteredKeyboardEvents.length - 1) {
      setIsKeyboardPlaying(false);
      return;
    }
    const timer = window.setTimeout(() => {
      setKeyboardCursor((prev) => {
        if (prev >= filteredKeyboardEvents.length - 1) {
          setIsKeyboardPlaying(false);
          return prev;
        }
        return prev + 1;
      });
    }, 480);
    return () => window.clearTimeout(timer);
  }, [filteredKeyboardEvents.length, isKeyboardPlaying, keyboardCursor]);

  const keyboardStats = useMemo(() => {
    const uniqueKeys = new Set(
      filteredKeyboardEvents.flatMap((item) => [...item.keys, ...item.pressedKeys, ...item.releasedKeys]),
    );
    return {
      printableCount: filteredKeyboardEvents.filter((item) => Boolean(item.text && item.text.length > 0)).length,
      comboCount: filteredKeyboardEvents.filter((item) => item.modifiers.length > 0).length,
      uniqueKeyCount: uniqueKeys.size,
    };
  }, [filteredKeyboardEvents]);

  const mouseStats = useMemo(() => {
    let distance = 0;
    let buttonActions = 0;
    let wheelCount = 0;
    for (const event of filteredMouseEvents) {
      distance += Math.hypot(event.xDelta, event.yDelta);
      buttonActions += event.pressedButtons.length + event.releasedButtons.length;
      if (event.wheelVertical !== 0 || event.wheelHorizontal !== 0) {
        wheelCount += 1;
      }
    }
    return {
      distance: Math.round(distance),
      buttonActions,
      wheelCount,
    };
  }, [filteredMouseEvents]);

  const keyboardTextPreview = useMemo(() => {
    const text = filteredKeyboardEvents
      .map((item) => item.text ?? "")
      .join("")
      .replace(/\n/g, "↵\n")
      .replace(/\t/g, "⇥");
    return text || "(未解析到可打印字符，仍可查看下方按键行为表)";
  }, [filteredKeyboardEvents]);

  const keyboardReplayText = useMemo(() => {
    if (filteredKeyboardEvents.length === 0) {
      return "(未解析到键盘行为)";
    }
    const text = filteredKeyboardEvents
      .slice(0, keyboardCursor + 1)
      .map((item) => keyboardReplayToken(item))
      .join("")
      .replace(/\n/g, "↵\n")
      .replace(/\t/g, "⇥");
    return text || "(当前事件未产生可打印字符)";
  }, [filteredKeyboardEvents, keyboardCursor]);

  return {
    activeSubTab,
    activeKeyboardDevice,
    activeMouseDevice,
    currentKeyboardEvent: filteredKeyboardEvents[keyboardCursor] ?? null,
    filteredKeyboardEvents,
    filteredMouseEvents,
    isKeyboardPlaying,
    keyboardCursor,
    keyboardDevices,
    keyboardReplayText,
    keyboardStats,
    keyboardTextPreview,
    mouseDevices,
    mouseStats,
    notes,
    setActiveKeyboardDevice,
    setActiveMouseDevice,
    setActiveSubTab,
    setKeyboardCursor,
    toggleKeyboardPlay() {
      if (filteredKeyboardEvents.length <= 1) return;
      setIsKeyboardPlaying((prev) => {
        if (keyboardCursor >= filteredKeyboardEvents.length - 1 && !prev) {
          setKeyboardCursor(0);
        }
        return !prev;
      });
    },
  };
}

function uniqueStrings(values: string[]) {
  return Array.from(new Set(values));
}

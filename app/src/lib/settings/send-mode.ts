import { useSyncExternalStore } from "react";

/**
 * How the composer handles a message submitted while a Bot is already working.
 *
 * - `"queue"`: Park the message behind the active turn (or disable sending where no queue exists)
 *   until the Bot finishes.
 * - `"instant"`: Interrupt any active or stuck turn and send the message immediately.
 */
export type SendMode = "queue" | "instant";

export const SEND_MODES = [
  "queue",
  "instant",
] as const satisfies readonly SendMode[];

export const DEFAULT_SEND_MODE: SendMode = "queue";

export const SEND_MODE_STORAGE_KEY = "openbot-send-mode";

export function parseSendMode(value: unknown): SendMode {
  return value === "instant" ? "instant" : DEFAULT_SEND_MODE;
}

const listeners = new Set<() => void>();
let storageBound = false;

function readStoredSendMode(): SendMode {
  if (typeof window === "undefined") return DEFAULT_SEND_MODE;
  try {
    return parseSendMode(window.localStorage.getItem(SEND_MODE_STORAGE_KEY));
  } catch {
    return DEFAULT_SEND_MODE;
  }
}

function bindStorageListener(): void {
  if (storageBound || typeof window === "undefined") return;
  storageBound = true;
  window.addEventListener("storage", (event) => {
    if (event.key !== null && event.key !== SEND_MODE_STORAGE_KEY) return;
    notifyListeners();
  });
}

function notifyListeners(): void {
  for (const listener of [...listeners]) {
    listener();
  }
}

/** Read the persisted send mode preference (`"queue"` by default). */
export function getSendMode(): SendMode {
  return readStoredSendMode();
}

/** Persist the send mode preference in browser storage and notify subscribers. */
export function setSendMode(mode: SendMode): void {
  const normalized = parseSendMode(mode);
  if (typeof window !== "undefined") {
    try {
      window.localStorage.setItem(SEND_MODE_STORAGE_KEY, normalized);
    } catch {
      // Storage may be unavailable in restricted contexts; listeners still see the change if read.
    }
  }
  notifyListeners();
}

/** Subscribe to send mode changes in this tab and across tabs. */
export function subscribeSendMode(listener: () => void): () => void {
  bindStorageListener();
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/** React hook returning the current send mode and a setter that persists it. */
export function useSendMode(): [SendMode, (mode: SendMode) => void] {
  const mode = useSyncExternalStore(
    subscribeSendMode,
    getSendMode,
    () => DEFAULT_SEND_MODE,
  );
  return [mode, setSendMode];
}

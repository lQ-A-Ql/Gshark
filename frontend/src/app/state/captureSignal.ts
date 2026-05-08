export function wakeCaptureWaiters(waiters: Set<() => void>) {
  if (waiters.size === 0) return;
  const pending = Array.from(waiters);
  waiters.clear();
  for (const waiter of pending) {
    waiter();
  }
}

export function waitForCaptureSignal(waiters: Set<() => void>, delayMs: number) {
  return new Promise<void>((resolve) => {
    let settled = false;
    let timer = 0;
    const finish = () => {
      if (settled) return;
      settled = true;
      if (timer) {
        window.clearTimeout(timer);
      }
      waiters.delete(finish);
      resolve();
    };
    timer = window.setTimeout(finish, delayMs);
    waiters.add(finish);
  });
}

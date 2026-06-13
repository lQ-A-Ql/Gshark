export function packageScriptRunsFromCi(manifest, scriptName) {
  const scripts = manifest?.scripts ?? {};
  const wanted = `pnpm run ${scriptName}`;
  const visited = new Set();
  const queue = ["ci"];

  while (queue.length > 0) {
    const current = queue.shift();
    if (!current || visited.has(current)) {
      continue;
    }
    visited.add(current);
    const command = String(scripts[current] ?? "");
    if (command.includes(wanted)) {
      return true;
    }
    for (const match of command.matchAll(/\bpnpm\s+run\s+([A-Za-z0-9:._-]+)/g)) {
      const next = match[1];
      if (next && !visited.has(next)) {
        queue.push(next);
      }
    }
  }
  return false;
}

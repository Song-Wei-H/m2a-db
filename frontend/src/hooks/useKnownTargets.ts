import { useMemo, useState } from "react";

const KEY = "m2a.knownTargetIds";

function readIds() {
  try {
    const value = JSON.parse(localStorage.getItem(KEY) || "[]") as unknown;
    if (Array.isArray(value)) {
      return value.filter((item): item is number => Number.isInteger(item) && item > 0);
    }
  } catch {
    return [];
  }
  return [];
}

export function useKnownTargets() {
  const [ids, setIds] = useState<number[]>(readIds);

  const api = useMemo(
    () => ({
      ids,
      add(id: number) {
        const current = readIds();
        if (current.includes(id)) return;
        const next = [id, ...current].slice(0, 50);
        localStorage.setItem(KEY, JSON.stringify(next));
        setIds(next);
      },
      remove(id: number) {
        const current = readIds();
        if (!current.includes(id)) return;
        const next = current.filter((knownId) => knownId !== id);
        localStorage.setItem(KEY, JSON.stringify(next));
        setIds(next);
      }
    }),
    [ids]
  );

  return api;
}

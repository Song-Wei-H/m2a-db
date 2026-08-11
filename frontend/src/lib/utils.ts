import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDate(value?: string | null) {
  if (!value) return "n/a";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export function formatPercent(value?: number | null) {
  if (value === null || value === undefined) return "n/a";
  return `${Math.round(value * 100)}%`;
}

export function asNumber(value: unknown, fallback = 0) {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

export function compactText(value: unknown) {
  if (value === null || value === undefined || value === "") return "n/a";
  if (typeof value === "string") return value;
  return JSON.stringify(value, null, 2);
}

import { writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { customDetectorLabels } from "../../guard/custom-rules.js";
import type { ExposureAccount } from "../../lib/account.js";
import { localDetectorLabel, type FindingRow } from "../../lib/findings.js";
import type { CliContext, EngineHandle } from "../context.js";
import { CliError, type Styles } from "../output.js";

export type Severity = FindingRow["severity"];
export const SEVERITIES: readonly Severity[] = ["critical", "high", "medium", "low"];

/** critical/high red, medium yellow, low dim: the contract's severity colours. */
export function paintSeverity(style: Styles, severity: Severity): string {
  if (severity === "critical" || severity === "high") return style.error(severity);
  if (severity === "medium") return style.warn(severity);
  return style.dim(severity);
}

/** "critical 1 · high 2 · medium 0 · low 3", as the status line prints it. */
export function severityLine(counts: Record<Severity, number>): string {
  return SEVERITIES.map((s) => `${s} ${counts[s]}`).join(" · ");
}

/** Labels for the live policy's custom rules, for `custom:<id>` rows. */
export function ruleLabels(ctx: CliContext): Record<string, string> {
  return customDetectorLabels(ctx.policy().custom_rules ?? []);
}

/** The rule's name as the row recorded it, else as the app names it today. */
export function ruleLabel(row: Pick<FindingRow, "detector" | "detector_label">, labels: Record<string, string>): string {
  return row.detector_label ?? localDetectorLabel(row.detector, labels);
}

/** A Radar card's headline: the exposure's account title, else the rule's
 * name. The account quotes fields in backticks (mono on screen); a terminal
 * reads them without. */
export function cardTitle(row: FindingRow & { account?: ExposureAccount }, labels: Record<string, string>): string {
  return plain(row.account?.title || ruleLabel(row, labels));
}

/** Account sentences quote fields in backticks; a terminal reads them as is. */
export function plain(text: string): string {
  return text.replace(/`/g, "");
}

/** Whitespace folded to single spaces, cut to `max` characters when given.
 * Table cells pass none: the table cuts to the terminal and never when piped. */
export function oneLine(text: string, max = Number.POSITIVE_INFINITY): string {
  const flat = text.replace(/\s+/g, " ").trim();
  return flat.length > max ? `${flat.slice(0, max - 3)}...` : flat;
}

/** The item whose id is `id`, or the only one it starts. Ids are long; the
 * lists print them whole, but a unique prefix is enough to type. `list` is
 * the command that lists them, offered when nothing matches. */
export function byIdOrPrefix<T>(items: readonly T[], given: string, idOf: (item: T) => string | undefined, what: string, list?: string): T {
  // An id copied from a cut table cell ends in an ellipsis: the rest is a prefix.
  const id = given.replace(/(?:…|\.\.\.)$/, "");
  const exact = items.find((item) => idOf(item) === id);
  if (exact) return exact;
  const matches = items.filter((item) => idOf(item)?.startsWith(id));
  if (matches.length === 1) return matches[0]!;
  if (matches.length === 0) throw new CliError(`No ${what} "${id}".`, 1, list ? `\`${list}\` lists them with their ids.` : undefined);
  throw new CliError(`"${id}" matches ${matches.length} ${what}s; give more of the id.`);
}

/** A whole-number option, inside [min, max]. */
export function intOption(value: unknown, name: string, fallback: number, min = 0, max = Number.MAX_SAFE_INTEGER): number {
  if (value === undefined) return fallback;
  const n = typeof value === "string" && /^\d+$/.test(value) ? Number(value) : Number.NaN;
  if (!Number.isInteger(n) || n < min || n > max) {
    throw new CliError(`--${name} takes a whole number ${max === Number.MAX_SAFE_INTEGER ? `of ${min} or more` : `from ${min} to ${max}`}.`, 2);
  }
  return n;
}

/** `--days` limited to the windows the screen offers. */
export function daysOption<T extends number>(value: unknown, allowed: readonly T[], fallback: T): T {
  if (value === undefined) return fallback;
  const n = Number(value);
  const hit = allowed.find((d) => d === n);
  if (hit === undefined) throw new CliError(`--days takes ${allowed.slice(0, -1).join(", ")} or ${allowed[allowed.length - 1]}.`, 2);
  return hit;
}

/** Open the engine, run `fn`, and always put the engine (and any snapshot copy) away. */
export async function withEngine<T>(ctx: CliContext, scan: boolean, fn: (handle: EngineHandle) => Promise<T> | T): Promise<T> {
  const handle = await ctx.openEngine({ scan });
  try {
    return await fn(handle);
  } finally {
    handle.close();
  }
}

/** Write a file the person named (relative to where they ran the command). */
export function writeOut(path: string, content: string): string {
  const target = resolve(path);
  try {
    writeFileSync(target, content);
  } catch (err) {
    const code = err instanceof Error && "code" in err ? err.code : undefined;
    const why = code === "ENOENT" ? "no such folder" : code === "EACCES" || code === "EPERM" ? "permission denied" : err instanceof Error ? err.message : String(err);
    throw new CliError(`Couldn't write ${target}: ${why}.`);
  }
  return target;
}

/** 5400 → "1h 30m"; 90 → "2m"; 0 → "0m". */
export function duration(seconds: number): string {
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m`;
  const h = Math.floor(minutes / 60);
  const m = minutes % 60;
  return m === 0 ? `${h}h` : `${h}h ${m}m`;
}

/** "+12% vs prior 7d", or "" when there is nothing before to compare with. */
export function delta(current: number, previous: number, suffix: string): string {
  if (!(previous > 0)) return "";
  const pct = Math.round(((current - previous) / previous) * 100);
  return `${pct >= 0 ? "+" : ""}${pct}% ${suffix}`;
}

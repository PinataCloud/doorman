import { existsSync, statSync } from "node:fs";
import { join } from "node:path";
import type { CaptureEngine } from "./capture.js";
import { installedGuardHostIds } from "./enforcement.js";
import { HOSTS } from "./guard/hosts/index.js";
import { scanShadowAi, type ShadowAiState } from "./lib/shadow-ai.js";

/** The shadow-AI catalog against this machine's filesystem. Home-relative
 * paths are joined here; absolute ones (app bundles) pass through. Shared by
 * the app's coverage card and the CLI's report. */
export function shadowAiNow(home: string, engine: Pick<CaptureEngine, "presentSources" | "capturedAppIds"> | undefined, nowMs = Date.now()): ShadowAiState {
  const resolve = (rel: string): string => (rel.startsWith("/") ? rel : join(home, rel));
  const exists = (rel: string): boolean => {
    try {
      return existsSync(resolve(rel));
    } catch {
      return false;
    }
  };
  const newestMtimeMs = (rels: string[]): number | undefined => {
    let newest = 0;
    for (const rel of rels) {
      try {
        const ms = statSync(resolve(rel)).mtimeMs;
        if (ms > newest) newest = ms;
      } catch {
        // absent — skip
      }
    }
    return newest > 0 ? newest : undefined;
  };
  return scanShadowAi(
    exists,
    newestMtimeMs,
    nowMs,
    // `covered` is computed, not declared: a catalog entry counts as covered
    // only while the guard is installed into its host.
    installedGuardHostIds(),
    // ...and `guardable` is every host the registry has an adapter for, so an
    // uncovered row can say "one switch away" instead of "unreachable".
    HOSTS.map((h) => h.id),
    // `captured` is computed the same way: the transcript sources registered on
    // this build whose host is on this machine (capture.ts), so a row reads
    // "Captured" exactly when a parser for it exists and can see something —
    // plus any app whose sessions one of the RAILS carried instead (ChatGPT
    // Desktop, over the Codex rollouts its desktop mode writes, which no
    // descriptor of its own will ever discover).
    engine ? [...engine.presentSources().map((s) => s.id), ...engine.capturedAppIds()] : [],
  );
}

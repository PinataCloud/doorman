import { readFileSync } from "node:fs";
import { join } from "node:path";

/**
 * Which commit this build was made from (scripts/stamp-build.mjs writes
 * `build/main/build-info.json` at compile time): the app and the CLI compare
 * revisions — commit times — to tell which of their guard bundles is newer.
 * A build without the file (a bare `tsc`, the tests) is revision 0.
 */
export interface BuildInfo {
  /** The commit's time, seconds since the epoch; 0 when unknown. */
  revision: number;
  commit?: string;
}

let cached: BuildInfo | undefined;

export function buildInfo(): BuildInfo {
  if (cached) return cached;
  try {
    const raw: unknown = JSON.parse(readFileSync(join(__dirname, "..", "build-info.json"), "utf8"));
    const r = raw && typeof raw === "object" ? (raw as Partial<BuildInfo>) : {};
    cached = { revision: typeof r.revision === "number" && Number.isFinite(r.revision) ? r.revision : 0, ...(typeof r.commit === "string" ? { commit: r.commit } : {}) };
  } catch {
    cached = { revision: 0 };
  }
  return cached;
}

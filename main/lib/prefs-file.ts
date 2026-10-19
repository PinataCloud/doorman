import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Prefs } from "../state.js";

/** `<userData>/prefs.json` — read by the app at boot and by the CLI per command. */
export function prefsPath(userDataDir: string): string {
  return join(userDataDir, "prefs.json");
}

/** The raw file, unvalidated: Store's sanitizer re-checks every field, and an
 * unreadable or non-object file is "no prefs yet", never an error. A leading
 * BOM is dropped first: Windows PowerShell 5.1 (`Set-Content -Encoding UTF8`)
 * and Notepad write one, JSON.parse throws on it, and "no prefs yet" would
 * reset the person's settings and then overwrite the file with the defaults. */
export function readPrefsFile(userDataDir: string): Partial<Prefs> {
  try {
    const raw: unknown = JSON.parse(readFileSync(prefsPath(userDataDir), "utf8").replace(/^\uFEFF/, ""));
    if (!raw || typeof raw !== "object") return {};
    return raw;
  } catch {
    return {};
  }
}

/** Written whole through a temp file and a rename, so a reader in the other
 * process (app or CLI) never sees half a file. */
export function writePrefsFile(userDataDir: string, prefs: Prefs): void {
  mkdirSync(userDataDir, { recursive: true });
  const path = prefsPath(userDataDir);
  const temp = `${path}.${process.pid}.tmp`;
  writeFileSync(temp, `${JSON.stringify(prefs, null, 2)}\n`);
  renameSync(temp, path);
}

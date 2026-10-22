/**
 * Reading and writing a config file a PERSON owns (an agent's MCP config),
 * under the rules a foreign document deserves:
 *
 *  · A file that exists but can't be read is an error, never "absent" — the
 *    merge would otherwise start from `{}` and replace the person's servers.
 *  · A symlinked config (dotfiles repos) is written THROUGH the link, so the
 *    link and its target stay one file.
 *  · A read-only file is refused, not replaced: the read-only bit is the
 *    person saying "don't change this", and an atomic rename would ignore it.
 *  · The replacement keeps the original's mode, and a failed write leaves no
 *    `.doorman.tmp` behind.
 *  · `<path>.doorman.bak` holds the text from BEFORE Doorman's first edit. It
 *    is written only when absent (so a second edit can't overwrite the
 *    original with Doorman's own text) and with the original's mode (an MCP
 *    config can carry tokens; the backup is no more readable than it was).
 */

import { accessSync, chmodSync, constants, lstatSync, readFileSync, readlinkSync, realpathSync, renameSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

export type ConfigRead = { exists: false } | { exists: true; text: string; mode: number };

function code(err: unknown): string | undefined {
  return err && typeof err === "object" && "code" in err ? String(err.code) : undefined;
}

/** A person-readable reason for a filesystem error. */
function why(err: unknown): string {
  switch (code(err)) {
    case "EACCES":
    case "EPERM":
      return "permission denied";
    case "EISDIR":
      return "it is a folder, not a file";
    case "EROFS":
      return "it is on a read-only volume";
    case "ENOSPC":
      return "the disk is full";
    default:
      return err instanceof Error ? err.message : String(err);
  }
}

/** The file's text, or `{ exists: false }` when there is no file. Throws a
 * user-facing Error (naming `label`) for a file that is there but unreadable. */
export function readConfigFile(path: string, label: string): ConfigRead {
  let text: string;
  let mode: number;
  try {
    mode = statSync(path).mode & 0o777;
    text = readFileSync(path, "utf8");
  } catch (err) {
    const c = code(err);
    if (c === "ENOENT" || c === "ENOTDIR") return { exists: false };
    throw new Error(`${label} (${path}) can't be read: ${why(err)}; not touching it`);
  }
  return { exists: true, text, mode };
}

/** Where a write to `path` lands: the end of its symlink chain, so the link
 * survives. A dangling link resolves to where it points. */
export function writeTarget(path: string): string {
  try {
    return realpathSync(path);
  } catch {
    try {
      if (lstatSync(path).isSymbolicLink()) return resolve(dirname(path), readlinkSync(path));
    } catch {
      // not there at all — a fresh file at `path`
    }
    return path;
  }
}

/** Atomically replace (or create) the file at `path` with `text`, through a
 * symlink, keeping the original's mode. Throws a user-facing Error. */
export function writeConfigFile(path: string, text: string, label: string): void {
  const target = writeTarget(path);
  let mode: number | undefined;
  try {
    mode = statSync(target).mode & 0o777;
  } catch {
    mode = undefined;
  }
  if (mode !== undefined) {
    try {
      accessSync(target, constants.W_OK);
    } catch {
      throw new Error(`${label} (${path}) is read-only; not touching it. Make it writable and try again.`);
    }
  }
  const temp = `${target}.doorman.tmp`;
  try {
    writeFileSync(temp, text, mode === undefined ? undefined : { mode });
    if (mode !== undefined) chmodSync(temp, mode); // the umask narrowed it
    renameSync(temp, target);
  } catch (err) {
    try {
      unlinkSync(temp);
    } catch {
      // never created
    }
    throw new Error(`${label} (${path}) couldn't be written: ${why(err)}`);
  }
}

export function backupPath(path: string): string {
  return `${path}.doorman.bak`;
}

/** Keep the pre-Doorman original beside the config — only if no backup is
 * there yet, and with the original's mode. Best effort: the edit itself is
 * byte-preserving, so a missing backup loses nothing. */
export function backupOnce(path: string, before: string, mode: number): void {
  try {
    writeFileSync(backupPath(path), before, { flag: "wx", mode });
    chmodSync(backupPath(path), mode);
  } catch {
    // already there (keep the first), or unwritable
  }
}

/** The pre-Doorman original, when one was kept. */
export function readBackup(path: string): string | undefined {
  try {
    return readFileSync(backupPath(path), "utf8");
  } catch {
    return undefined;
  }
}

/** Remove a file Doorman created (no backup: there was no file before). */
export function removeConfigFile(path: string, label: string): void {
  try {
    unlinkSync(path);
  } catch (err) {
    if (code(err) === "ENOENT") return;
    throw new Error(`${label} (${path}) couldn't be removed: ${why(err)}`);
  }
}

export function removeBackup(path: string): void {
  try {
    unlinkSync(backupPath(path));
  } catch {
    // none
  }
}

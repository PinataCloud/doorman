import { homedir } from "node:os";

/**
 * The home directory the app resolves every agent config from — MCP configs it
 * registers into, routes and watches, hook documents, transcripts — the same
 * one the guard, the CLI and the sandbox check use.
 *
 * Not Electron's `app.getPath("home")`: on macOS that asks NSHomeDirectory,
 * the account's home whatever `$HOME` says, while `os.homedir()` (what the
 * guard install, the MCP config watcher and lib/sandbox.ts go by) follows
 * `$HOME`. A run with a redirected `HOME` (scripts/dev-sandbox.mjs) once
 * showed the inventory one home and wrote MCP registrations into the other —
 * the real one (2026-10-21). One function, `$HOME` first as `os.homedir()`
 * does on POSIX, so there is one answer.
 *
 * `electronHome` is only the last resort, for an account `os.homedir()` can't
 * resolve (no `$HOME`, no passwd entry).
 */
export function appHome(electronHome: () => string, env: NodeJS.ProcessEnv = process.env, platform: NodeJS.Platform = process.platform): string {
  if (platform !== "win32" && env.HOME) return env.HOME;
  try {
    const home = homedir();
    if (home) return home;
  } catch {
    // no passwd entry: Electron's answer below
  }
  return electronHome();
}

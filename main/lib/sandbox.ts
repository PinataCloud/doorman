import { userInfo } from "node:os";

/**
 * A sandboxed run — `DOORMAN_APPDATA_DIR` set, the dev/test way to boot the
 * app against a scratch profile (see index.ts) — must never write into files
 * this app does not own: `~/.claude/settings.json`, `~/.codex/hooks.json`, the
 * Cursor / Gemini / Copilot hook documents, MCP configs. Those live under the REAL home, not under the sandbox, and
 * every merge into them bakes the sandbox's own paths in.
 *
 * Learned the hard way on 2026-09-06: a sandboxed screenshot run found the
 * real guard installed (the person had switched it on in the real app), the
 * boot re-merge did its job faithfully — and rewrote all five hook documents
 * to point at a guard bundle inside /private/tmp that would vanish with the
 * session. The real app healed it on its next launch, but nothing should have
 * needed healing. So: one predicate, checked at every write into a foreign
 * document; a sandbox reads everything and writes only inside itself.
 *
 * WITH ONE EXCEPTION, and it is the same rule rather than a hole in it: a
 * sandbox that ALSO redirects `HOME` has no foreign document to damage. Every
 * hook path is resolved from `homedir()`, so under a redirected home they all
 * land inside the fixture — the scratch `settings.json` the guard merges into
 * included. The incident above was a sandboxed run against the REAL home,
 * which is still refused.
 *
 * This is what makes the guard testable at all. Without it a sandboxed run can
 * never turn protection on, so no rule can ever hold a call, so custom rules
 * and enforcement modes cannot be exercised anywhere but the real machine.
 * `scripts/dev-sandbox.mjs` is the supported way in.
 */
export function hookWritesAllowed(env: NodeJS.ProcessEnv = process.env): boolean {
  if (!env.DOORMAN_APPDATA_DIR) return true;
  // …unless HOME is redirected too, in which case there is no foreign document
  // to damage: every hook path resolves under the fixture's own home, and the
  // rule above is about the REAL account's files. This is what makes the guard
  // testable — a sandbox that can install it into its own home can actually
  // hold a tool call, which is the only way to exercise a rule.
  return homeIsRedirected(env);
}

/**
 * Is `HOME` pointed somewhere other than this account's real home?
 *
 * `userInfo().homedir` reads the password database (getpwuid), NOT `$HOME` —
 * which is exactly why it can answer this at all. `homedir()` follows the
 * override, so comparing it against itself would always say "no".
 *
 * Unresolvable (`userInfo` can throw for a user with no passwd entry) counts
 * as NOT redirected: the safe end of the guess is the one that writes nothing.
 */
export function homeIsRedirected(env: NodeJS.ProcessEnv = process.env): boolean {
  const home = env.HOME;
  if (!home) return false;
  let real: string;
  try {
    real = userInfo().homedir;
  } catch {
    return false;
  }
  if (!real) return false;
  const trim = (p: string) => (p.length > 1 && p.endsWith("/") ? p.slice(0, -1) : p);
  return trim(home) !== trim(real);
}

export const SANDBOX_READ_ONLY =
  "Sandboxed run (DOORMAN_APPDATA_DIR is set): files outside the sandbox — hook documents, MCP configs, beacons — are read-only.";

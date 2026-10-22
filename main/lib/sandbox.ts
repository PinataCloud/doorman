import { existsSync, realpathSync } from "node:fs";
import { userInfo } from "node:os";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

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
 *
 * A redirected `HOME` only says where paths SHOULD resolve, not where a given
 * write actually lands: the app once resolved MCP configs from Electron's
 * `app.getPath("home")`, which on macOS is the account's home whatever `$HOME`
 * says, and wrote Doorman's entry into the real `~/.copilot/mcp-config.json`
 * while this predicate, looking at `$HOME` alone, said yes (2026-10-21). So a
 * caller passes the `target` it is about to write — a file, or the home it
 * resolved its documents from — and a sandbox allows it only when its real
 * path (symlinks followed: `dev-sandbox --real-transcripts` links real
 * directories into the fixture) lies inside the redirected home.
 */
export function hookWritesAllowed(env: NodeJS.ProcessEnv = process.env, target?: string): boolean {
  if (!env.DOORMAN_APPDATA_DIR) return true;
  // …unless HOME is redirected too, in which case there is no foreign document
  // to damage: every hook path resolves under the fixture's own home, and the
  // rule above is about the REAL account's files. This is what makes the guard
  // testable — a sandbox that can install it into its own home can actually
  // hold a tool call, which is the only way to exercise a rule.
  if (!homeIsRedirected(env)) return false;
  return target === undefined || insideHome(target, env.HOME!);
}

/** Does `target`, symlinks resolved, lie inside `home` (or is it `home`)? */
function insideHome(target: string, home: string): boolean {
  const from = realPath(home);
  const to = realPath(target);
  const rel = relative(from, to);
  return rel === "" || (rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
}

/** The real path of `path`, or of its nearest existing ancestor with the rest
 * appended — a file about to be created has no real path yet, but the
 * directory it lands in does. */
function realPath(path: string): string {
  let existing = resolve(path);
  const rest: string[] = [];
  while (!existsSync(existing)) {
    const parent = dirname(existing);
    if (parent === existing) break;
    rest.unshift(basename(existing));
    existing = parent;
  }
  try {
    existing = realpathSync(existing);
  } catch {
    // unreadable: compare it as written
  }
  return rest.length > 0 ? join(existing, ...rest) : existing;
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

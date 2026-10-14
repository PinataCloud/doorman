#!/usr/bin/env node
/**
 * Boot the app against a throwaway home + profile, with the guard INSTALLABLE.
 *
 * Why this exists: a sandboxed run (`DOORMAN_APPDATA_DIR`) refuses to write
 * hook documents, because one once rewrote the real ones to point at a bundle
 * in /private/tmp (lib/sandbox.ts tells that story). But that makes the guard
 * impossible to exercise — protection can never come on, so no rule can hold a
 * call, so custom rules and enforcement modes can only be tested on the real
 * machine, against the real ~/.claude.
 *
 * Redirecting HOME as well settles it: every hook path resolves under the
 * fixture, so the guard installs into a scratch `settings.json` that this
 * script owns and deletes. `hookWritesAllowed` allows exactly this shape and
 * still refuses a sandbox pointed at the real home.
 *
 *   node scripts/dev-sandbox.mjs [--screen rules] [--real-transcripts] [--keep] [--reset]
 *
 * `--real-transcripts` symlinks your REAL transcript directories into the
 * fixture so the app reads your actual sessions — the only way to see what a
 * screen looks like with real data. It links transcript roots ONLY, never a
 * config file: the guard still writes to the fixture's own settings.json, and
 * capture only ever reads the linked directories.
 *
 * Nothing under your real home is read or written. The fixture lives in
 * `.dev-sandbox/` (git-ignored) and persists between runs so a level or a rule
 * you set survives a restart; `--reset` starts clean.
 */
import { spawn } from "node:child_process";
import { mkdirSync, rmSync, writeFileSync, existsSync, symlinkSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { userInfo } from "node:os";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const box = join(root, ".dev-sandbox");
const home = join(box, "home");
const appdata = join(box, "appdata");

const args = process.argv.slice(2);
const flag = (name) => args.includes(name);
const value = (name, fallback) => {
  const i = args.indexOf(name);
  return i >= 0 && args[i + 1] ? args[i + 1] : fallback;
};

if (flag("--reset")) rmSync(box, { recursive: true, force: true });
mkdirSync(join(home, ".claude"), { recursive: true });
mkdirSync(appdata, { recursive: true });

// Refuse to run if HOME would not actually be redirected — the whole safety
// argument rests on it, and a fixture that silently pointed at the real home
// is the exact incident this design exists to prevent.
if (userInfo().homedir === home) {
  console.error("[dev-sandbox] refusing: the fixture home IS the real home");
  process.exit(1);
}

/* Your real transcripts, read-only in practice, linked in on request.
 *
 * Only the directories agents WRITE TRANSCRIPTS into — never `.claude` itself,
 * because the guard merges into `.claude/settings.json` and a link there would
 * put the fixture's hook entries in your real file, which is the exact
 * incident lib/sandbox.ts exists to prevent. Each link is the leaf directory,
 * so the parent stays the fixture's own. */
const TRANSCRIPT_ROOTS = [
  ".claude/projects",
  ".codex/sessions",
  ".copilot/session-state",
  ".gemini",
  ".qwen",
  ".aider",
  ".cursor",
  ".hermes",
  ".kiro",
  ".local/share/opencode",
  ".local/share/crush",
  "Library/Application Support/Claude",
  "Library/Application Support/Cursor",
  "Library/Application Support/com.openai.chat",
];

if (flag("--real-transcripts")) {
  const realHome = userInfo().homedir;
  let linked = 0;
  for (const rel of TRANSCRIPT_ROOTS) {
    const from = join(realHome, rel);
    if (!existsSync(from)) continue;
    const to = join(home, rel);
    mkdirSync(dirname(to), { recursive: true });
    rmSync(to, { recursive: true, force: true });
    symlinkSync(from, to);
    linked += 1;
    console.log(`[dev-sandbox] reading your real ${rel}`);
  }
  if (linked === 0) console.log("[dev-sandbox] no real transcript directories found to link");
}

// Skip first-run setup and start with protection WANTED, so the app installs
// the guard into the fixture on boot and there is something to test.
const prefs = join(appdata, "Doorman", "prefs.json");
if (!existsSync(prefs)) {
  mkdirSync(dirname(prefs), { recursive: true });
  writeFileSync(prefs, JSON.stringify({ onboarding_open: false, guard_wanted: true }, null, 2));
}

const env = {
  ...process.env,
  HOME: home,
  DOORMAN_APPDATA_DIR: appdata,
  ...(flag("--screen") ? { DOORMAN_SHOT_SCREEN: value("--screen", "rules") } : {}),
};

console.log(`[dev-sandbox] home    ${home}`);
console.log(`[dev-sandbox] profile ${appdata}`);
console.log(`[dev-sandbox] the guard installs into ${join(home, ".claude", "settings.json")}`);

const electron = join(root, "node_modules", ".bin", "electron");
const child = spawn(electron, ["."], { cwd: root, env, stdio: "inherit" });
child.on("exit", (code) => {
  if (!flag("--keep")) console.log("[dev-sandbox] fixture kept at .dev-sandbox (--reset to clear)");
  process.exit(code ?? 0);
});

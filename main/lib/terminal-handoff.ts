/**
 * Terminal hand-off — "Open" for a live session, "Continue" for an ended one.
 *
 * A session belongs to a terminal window; nothing can attach a second
 * keyboard to it. So the app does the two things that are honest:
 *
 *   · a LIVE session's window is brought forward — Terminal and iTerm2 expose
 *     each tab's tty over Apple Events, so the exact tab is selected; any
 *     other terminal app is activated as a whole;
 *   · an ENDED session is resumed in a NEW window with the host's own resume
 *     command (`claude --resume <id>`, `codex resume <id>`, …), in the
 *     session's own working directory.
 *
 * Pure builders here (AppleScript and shell text, fully quoted); the runner
 * in main spawns `osascript`/`open`. Only the hosts whose resume command is
 * documented get one — a guess would start the wrong thing in a shell.
 */

import type { TurnSource } from "./turns.js";

/** Session ids are file names on every host we resume; refuse anything
 * else rather than quoting it into a shell. */
const SAFE_ID = /^[A-Za-z0-9._:-]{1,160}$/;

/** The host's documented "continue this session" command, or undefined when
 * the host has none we know of. */
export function resumeCommand(source: TurnSource, sessionId: string): string | undefined {
  if (!SAFE_ID.test(sessionId)) return undefined;
  switch (source) {
    case "claude-code":
      return `claude --resume ${sessionId}`;
    case "codex":
      return `codex resume ${sessionId}`;
    case "copilot-cli":
      return `copilot --resume ${sessionId}`;
    default:
      return undefined;
  }
}

/** POSIX single-quote: the only escaping a shell cannot be talked out of. */
export function shellQuote(text: string): string {
  return `'${text.replace(/'/g, `'\\''`)}'`;
}

/** `cd '<cwd>' && <command>` — the line typed into the new window. */
export function shellLine(cwd: string | undefined, command: string): string {
  return cwd ? `cd ${shellQuote(cwd)} && ${command}` : command;
}

/** AppleScript string literal: backslash and double quote are the only
 * escapes it knows. */
export function appleScriptString(text: string): string {
  return `"${text.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

/** Which apps the builders can address by tab. Everything else falls back
 * to Terminal for a new window and to `open -a` for focusing. */
export type ScriptableTerminal = "Terminal" | "iTerm2";

/** Normalise an app name from the process table (`iTerm2`, `Terminal`) or
 * a `$TERM_PROGRAM` value (`Apple_Terminal`, `iTerm.app`) to a scriptable
 * target, or undefined. */
export function scriptableTerminal(name: string | undefined): ScriptableTerminal | undefined {
  if (!name) return undefined;
  const n = name.toLowerCase();
  if (n === "terminal" || n === "apple_terminal") return "Terminal";
  if (n === "iterm2" || n === "iterm.app" || n === "iterm") return "iTerm2";
  return undefined;
}

/** Bring the tab owning `tty` (a device name like `ttys003`) to the front. */
export function focusScript(app: ScriptableTerminal, tty: string): string {
  const dev = appleScriptString(tty.startsWith("/dev/") ? tty : `/dev/${tty}`);
  if (app === "Terminal") {
    return [
      'tell application "Terminal"',
      "  activate",
      "  repeat with w in windows",
      "    repeat with t in tabs of w",
      `      if tty of t is ${dev} then`,
      "        set selected of t to true",
      "        set index of w to 1",
      "        return true",
      "      end if",
      "    end repeat",
      "  end repeat",
      "end tell",
      "return false",
    ].join("\n");
  }
  return [
    'tell application "iTerm2"',
    "  activate",
    "  repeat with w in windows",
    "    repeat with t in tabs of w",
    "      repeat with s in sessions of t",
    `        if tty of s is ${dev} then`,
    "          select s",
    "          select t",
    "          select w",
    "          return true",
    "        end if",
    "      end repeat",
    "    end repeat",
    "  end repeat",
    "end tell",
    "return false",
  ].join("\n");
}

/** Open a new window running `line`. */
export function newWindowScript(app: ScriptableTerminal, line: string): string {
  const text = appleScriptString(line);
  if (app === "Terminal") {
    return ['tell application "Terminal"', "  activate", `  do script ${text}`, "end tell"].join("\n");
  }
  return [
    'tell application "iTerm2"',
    "  activate",
    "  set w to (create window with default profile)",
    `  tell current session of w to write text ${text}`,
    "end tell",
  ].join("\n");
}

export interface HandoffPlan {
  kind: "focus" | "activate" | "open";
  /** AppleScript to run through osascript (focus / open). */
  script?: string;
  /** App to `open -a` (activate fallback). */
  app?: string;
  /** The shell line a person could paste, shown beside the outcome. */
  line?: string;
}

/** What to do for a live row: select its tab when the app is scriptable and
 * the tty is known, otherwise just bring the app forward. Nothing for a
 * headless run or one behind tmux (the tty is tmux's, not a window's). */
export function planFocus(row: {
  tty?: string;
  terminal_app?: string;
  term_program?: string;
  tmux?: boolean;
  headless?: boolean;
}): HandoffPlan | undefined {
  if (row.headless) return undefined;
  const app = row.terminal_app ?? termProgramApp(row.term_program);
  const scriptable = scriptableTerminal(row.terminal_app) ?? scriptableTerminal(row.term_program);
  if (scriptable && row.tty && !row.tmux) return { kind: "focus", script: focusScript(scriptable, row.tty) };
  if (app) return { kind: "activate", app };
  return undefined;
}

/** `$TERM_PROGRAM` → an app name `open -a` accepts. */
export function termProgramApp(program: string | undefined): string | undefined {
  if (!program) return undefined;
  const p = program.toLowerCase();
  if (p === "apple_terminal") return "Terminal";
  if (p === "iterm.app") return "iTerm";
  if (p === "ghostty") return "Ghostty";
  if (p === "warpterminal") return "Warp";
  if (p === "vscode") return "Visual Studio Code";
  if (p === "wezterm") return "WezTerm";
  if (p === "kitty") return "kitty";
  if (p === "alacritty") return "Alacritty";
  if (p === "hyper") return "Hyper";
  if (p === "tmux") return undefined;
  return undefined;
}

/** What to do for an ended session: a new window in the preferred app (the
 * one the person's live agents run in, else Terminal) running the host's
 * resume command in the session's cwd. */
export function planResume(
  source: TurnSource,
  sessionId: string,
  cwd: string | undefined,
  preferredApp: string | undefined,
): HandoffPlan | undefined {
  const command = resumeCommand(source, sessionId);
  if (!command) return undefined;
  const line = shellLine(cwd, command);
  const app = scriptableTerminal(preferredApp) ?? "Terminal";
  return { kind: "open", script: newWindowScript(app, line), line };
}

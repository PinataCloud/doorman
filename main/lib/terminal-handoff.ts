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
 *     session's own working directory — Terminal/iTerm2 over Apple Events on
 *     macOS, a `cmd` console on Windows, a terminal emulator on Linux.
 *
 * Pure builders here (AppleScript, shell text and argv, fully quoted); the
 * runner in main spawns `osascript`/`open` or the window's program. Only the
 * hosts whose resume command is documented get one — a guess would start the
 * wrong thing in a shell. Focusing a live tab is macOS-only.
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
  /** Off macOS: programs to spawn in the session's cwd, tried in order until
   * one starts (open). */
  launches?: WindowLaunch[];
  /** The shell line a person could paste, shown beside the outcome. */
  line?: string;
}

/** A new terminal window off macOS: the program, its arguments, and whether
 * they reach Windows' command line exactly as written (`start`'s quoted
 * empty title would otherwise be re-quoted). */
export interface WindowLaunch {
  file: string;
  args: string[];
  verbatim?: boolean;
}

/** `cd /d "<cwd>" && <command>` — cmd's syntax, the shell the Windows window
 * runs. A Windows path cannot contain a double quote. */
export function cmdLine(cwd: string | undefined, command: string): string {
  return cwd ? `cd /d "${cwd}" && ${command}` : command;
}

/** Windows: `start` gives the command its own console window (or the
 * person's default terminal app); `cmd /k` keeps it open once the agent
 * exits, as the macOS window does. The command is resumeCommand's: fixed
 * words and a SAFE_ID, nothing for cmd to interpret. */
export function windowsLaunch(command: string): WindowLaunch {
  return { file: "cmd.exe", args: ["/d", "/c", "start", '""', "cmd.exe", "/k", command], verbatim: true };
}

/** Linux: there is no one terminal, so the standard launcher first, then the
 * emulators desktops ship, each told to run a command its own way. The
 * command runs in the person's interactive shell (their PATH — where npm or
 * a version manager put the agent), which stays once the agent exits. */
export function linuxLaunches(command: string, shell: string): WindowLaunch[] {
  const run = [shell, "-ic", `${command}; exec ${shellQuote(shell)} -i`];
  return [
    { file: "xdg-terminal-exec", args: run },
    { file: "ptyxis", args: ["--new-window", "--", ...run] },
    { file: "gnome-terminal", args: ["--", ...run] },
    { file: "konsole", args: ["-e", ...run] },
    { file: "xfce4-terminal", args: ["-x", ...run] },
    { file: "kitty", args: run },
    { file: "alacritty", args: ["-e", ...run] },
    { file: "wezterm", args: ["start", "--", ...run] },
    { file: "foot", args: run },
    { file: "x-terminal-emulator", args: ["-e", ...run] },
    { file: "xterm", args: ["-e", ...run] },
  ];
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

/** What to do for an ended session: a new window running the host's resume
 * command in the session's cwd. On macOS, in the preferred app (the one the
 * person's live agents run in, else Terminal) over Apple Events; elsewhere a
 * spawned console or terminal emulator. */
export function planResume(
  source: TurnSource,
  sessionId: string,
  cwd: string | undefined,
  preferredApp: string | undefined,
  platform: NodeJS.Platform = process.platform,
  shell = "/bin/sh",
): HandoffPlan | undefined {
  const command = resumeCommand(source, sessionId);
  if (!command) return undefined;
  if (platform === "win32") return { kind: "open", launches: [windowsLaunch(command)], line: cmdLine(cwd, command) };
  const line = shellLine(cwd, command);
  if (platform !== "darwin") return { kind: "open", launches: linuxLaunches(command, shell), line };
  const app = scriptableTerminal(preferredApp) ?? "Terminal";
  return { kind: "open", script: newWindowScript(app, line), line };
}

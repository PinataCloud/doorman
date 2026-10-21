import { homeBanner } from "./art.js";
import type { CliCommand } from "./command.js";
import { visibleLength } from "./output.js";
import type { Ui } from "./ui.js";

/**
 * `doorman`, `doorman help` and `doorman <command> --help`.
 *
 * Commands are listed by family (the first word: `guard` covers `guard
 * install` and the rest) in groups. Every family must be in a group; the
 * help test checks it.
 */

export const TAGLINE = "watch what your AI coding agents read and run";

export interface HelpGroup {
  title: string;
  about: string;
  /** Each family (a command's first word) and its one line in the overview,
   * short enough to fit 80 columns beside the name. */
  families: readonly (readonly [family: string, blurb: string])[];
  examples: readonly (readonly [command: string, what: string])[];
}

export const HELP_GROUPS: readonly HelpGroup[] = [
  {
    title: "Overview",
    about: "where things stand",
    families: [
      ["status", "Guard, agents, model, what needs review, what to do next"],
      ["scan", "Read new transcripts now and say what was new"],
      ["doctor", "Check the guard, MCP and editor wiring, and repair it"],
    ],
    examples: [
      ["doorman status", "the dashboard"],
      ["doorman scan", "read new transcripts now"],
    ],
  },
  {
    title: "Guard",
    about: "hold risky tool calls until a person answers",
    families: [
      ["guard", "Where the guard is installed and who answers held calls"],
      ["watch", "Answer held tool calls in this terminal"],
      ["policy", "The level, rule modes and hold settings the guard enforces"],
      ["rules", "Each rule and what it does now: observe, warn, ask, block"],
      ["packs", "Shipped rule packs, and which are on"],
      ["exceptions", "Findings that match one of these are not raised"],
      ["custom-rules", "Your own rules, and the ones packs add"],
    ],
    examples: [
      ["doorman guard install", "turn the guard on in every agent"],
      ["doorman watch", "answer held calls in this terminal"],
      ["doorman rules set secret_egress block", "deny instead of asking"],
    ],
  },
  {
    title: "Findings",
    about: "secrets and risky actions your agents exposed",
    families: [
      ["findings", "Open exposures, grouped by what was exposed"],
      ["trace", "Where one secret went, across every transcript"],
    ],
    examples: [
      ["doorman findings --severity high", "high and critical exposures"],
      ["doorman findings resolve <id>", "mark one resolved"],
    ],
  },
  {
    title: "Data",
    about: "sessions, usage and reports",
    families: [
      ["sessions", "Recent agent sessions, newest first"],
      ["session", "One session's turns (masked), with its findings"],
      ["search", "Search every captured turn (masked)"],
      ["usage", "Tokens and time spent with AI"],
      ["analytics", "What each rule found, and how often"],
      ["report", "The security report the app exports (Markdown)"],
      ["export", "Sightings or sessions as schema-valid JSON bundles"],
    ],
    examples: [
      ["doorman search deploy", "every captured turn that mentions it"],
      ["doorman report --out report.md", "the security report as Markdown"],
    ],
  },
  {
    title: "Integrations",
    about: "MCP servers, the gateway, editors, Docker Sandboxes",
    families: [
      ["mcp", "MCP servers here: config, use, findings, recognition"],
      ["gateway", "Route local MCP servers through Doorman's gateway"],
      ["editor", "The Doorman VS Code companion in each editor"],
      ["sbx", "Docker Sandboxes: list, answer held calls, pull findings"],
    ],
    examples: [
      ["doorman mcp", "every MCP server on this machine"],
      ["doorman sbx watch", "answer every sandbox's held calls here"],
    ],
  },
  {
    title: "Setup",
    about: "the classifier, settings, updates",
    families: [
      ["model", "The injection classifier: which model runs, downloads"],
      ["config", "Settings shared with the app"],
      ["update", "Check for a newer Doorman CLI and install it"],
      ["changelog", "What changed in each release of the CLI"],
      ["completion", "Tab completion for zsh, bash and fish"],
    ],
    examples: [
      ["doorman config set retention_days 30", "keep 30 days of history"],
      ["doorman update", "install the newest CLI"],
    ],
  },
];

/** What the first run is told to do, in order. */
const FIRST_STEPS: readonly (readonly [string, string])[] = [
  ["doorman guard install", "hold risky tool calls until you answer"],
  ["doorman scan", "look for secrets your agents have already seen"],
  ["doorman watch", "answer held calls here while the app is closed"],
];

/** Flags every command takes (index.ts strips them before parsing). */
export const GLOBAL_FLAGS: readonly (readonly [string, string])[] = [
  ["--json", "machine-readable output on stdout"],
  ["--verbose", "log what happens to stderr"],
  ["--quiet, -q", "no progress lines or update notice"],
  ["--no-color", "plain text, as NO_COLOR=1 does"],
  ["--help, -h", "usage, options and examples for a command"],
  ["--version", "print the version"],
];

const familyOf = (name: string) => name.split(" ")[0]!;

/** The family's line: its blurb in the overview, else its bare command's summary. */
function familySummary(family: string, commands: readonly CliCommand[]): string {
  const blurb = HELP_GROUPS.flatMap((g) => g.families).find(([f]) => f === family)?.[1];
  return blurb ?? commands.find((c) => c.name === family)?.summary ?? "";
}

/** `$ doorman x  # what`, the comments aligned. When one doesn't fit the
 * terminal, each comment goes above its command instead, wrapped. */
function exampleLines(ui: Ui, examples: readonly (readonly [string, string])[], indent = 2): string[] {
  const s = ui.style;
  const pad = " ".repeat(indent);
  const width = Math.max(...examples.map(([c]) => c.length));
  const cmd = (command: string) => `${pad}${s.dim("$")} ${ui.decorate ? s.accent(command) : command}`;
  const aligned = ui.width === undefined || examples.every(([, what]) => indent + 2 + width + 4 + what.length <= ui.width!);
  if (aligned) return examples.map(([command, what]) => `${cmd(command)}${" ".repeat(width - command.length)}  ${s.dim(`# ${what}`)}`);
  const room = Math.max(20, ui.width! - indent - 2);
  return examples.flatMap(([command, what]) => [...ui.wrap(what, room).map((l) => `${pad}${s.dim(`# ${l}`)}`), cmd(command)]);
}

/** Prose wrapped to the terminal (as written when piped). Commands are
 * coloured before wrapping, so one broken across lines keeps its colour. */
function paragraph(ui: Ui, text: string, indent = 0): string[] {
  const pad = " ".repeat(indent);
  const prose = ui.prose(text);
  const lines = ui.width === undefined ? [prose] : ui.wrap(prose, Math.max(20, ui.width - indent));
  return lines.map((l) => `${pad}${l}`);
}

/** Options and other two-column blocks: names bold on a terminal. */
function pairs(ui: Ui, rows: readonly (readonly [string, string])[], keyWidth?: number): string[] {
  return ui.kv(
    rows.map(([k, v]) => [ui.style.bold(k), ui.prose(v)]),
    { plainKeys: true, ...(keyWidth !== undefined ? { keyWidth } : {}) },
  );
}

/** `doorman` and `doorman help`: the banner, the first steps on a first run,
 * then every command by group with examples. */
export function homeHelp(ui: Ui, commands: readonly CliCommand[], version: string, firstRun: boolean): string[] {
  const s = ui.style;
  const out = [...homeBanner(ui, version, TAGLINE), ""];
  if (firstRun) {
    const width = Math.max(...FIRST_STEPS.map(([c]) => c.length));
    out.push(ui.section("Start here"));
    out.push(
      ...ui.kv(
        FIRST_STEPS.map(([command, what], i) => [`${s.bold(`${i + 1}`)}  ${ui.decorate ? s.accent(command) : command}`, what]),
        { plainKeys: true, keyWidth: 3 + width },
      ),
    );
    out.push("");
  }
  out.push(`${ui.decorate ? s.dim("Usage") : "Usage:"} doorman <command> [options]`, "");
  const families = new Set(commands.map((c) => familyOf(c.name)));
  const keyWidth = Math.max(...[...families].map((f) => f.length));
  // The overview keeps each family to its summary (wrapped on a narrow
  // terminal); `doorman help <family>` has the rest.
  for (const group of HELP_GROUPS) {
    // The group's aside goes under its title when the line won't hold both.
    if (ui.width !== undefined && group.title.length + 2 + group.about.length > ui.width) out.push(ui.section(group.title), ...paragraph(ui, group.about).map(s.dim));
    else out.push(ui.section(group.title, group.about));
    for (const [family, summary] of group.families) {
      if (!families.has(family)) continue;
      const subs = commands.filter((c) => familyOf(c.name) === family && c.name !== family).map((c) => c.name.slice(family.length + 1));
      out.push(...ui.kv([[s.bold(family), summary]], { plainKeys: true, keyWidth }));
      if (subs.length > 0) {
        // Packed whole into lines: a name like `server install` never breaks.
        const pad = " ".repeat(keyWidth + 4);
        const room = ui.width === undefined ? Infinity : Math.max(20, ui.width - pad.length);
        const lines: string[][] = [];
        for (const sub of subs) {
          const last = lines.at(-1);
          if (last && visibleLength(ui.list([...last, sub])) <= room) last.push(sub);
          else lines.push([sub]);
        }
        out.push(...lines.map((l) => `${pad}${ui.list(l.map(s.dim))}`));
      }
    }
    out.push(...exampleLines(ui, group.examples), "");
  }
  out.push(ui.section("Global options"), ...pairs(ui, GLOBAL_FLAGS), "");
  out.push(...paragraph(ui, "Run `doorman help <command>` for its options and examples."));
  out.push(...paragraph(ui, "Data: the desktop app's own directory (DOORMAN_APPDATA_DIR overrides), so the CLI and the app share one store."));
  out.push(...paragraph(ui, "Display: NO_COLOR=1 for plain text, DOORMAN_ASCII=1 for ASCII glyphs."));
  return out;
}

/** `doorman <name> <usage>`; `[options]` when it takes options but names none. */
export function usageLine(command: CliCommand): string {
  return `doorman ${command.name}${command.usage ? ` ${command.usage}` : command.flags?.length ? " [options]" : ""}`;
}

/**
 * `doorman <command> --help` (also `doorman help <command>`): what it does,
 * usage, notes, options, examples, and the family's other commands. `name`
 * may be a family with no bare command (`export`).
 */
export function commandHelp(ui: Ui, name: string, commands: readonly CliCommand[]): string[] {
  const s = ui.style;
  const command = commands.find((c) => c.name === name);
  const family = familyOf(name);
  const subs = commands.filter((c) => c.name !== name && c.name.startsWith(`${name} `) && (command === undefined || familyOf(c.name) === family));
  const siblings = command && name !== family ? [] : subs;
  const out: string[] = [];
  out.push(ui.section(`doorman ${name}`), ...paragraph(ui, command?.summary ?? familySummary(family, commands)), "");
  if (command?.notes && command.notes.length > 0) {
    for (const note of command.notes) out.push(...(/^\s/.test(note) ? noteLines(ui, note) : paragraph(ui, note)));
    out.push("");
  }
  if (command) {
    out.push(ui.section("Usage"), ...usageLines(ui, command), "");
    if (command.flags && command.flags.length > 0) out.push(ui.section("Options"), ...pairs(ui, command.flags), "");
    if (command.examples && command.examples.length > 0) out.push(ui.section("Examples"), ...exampleLines(ui, command.examples), "");
  }
  if (siblings.length > 0) {
    // Each with its arguments: in two columns when they're short, else each
    // usage (broken between arguments) with its summary under it.
    const usages = siblings.map((c) => usageLine(c));
    out.push(ui.section("Commands"));
    if (usages.every((u) => u.length <= 40)) out.push(...pairs(ui, siblings.map((c, i) => [usages[i]!, c.summary])));
    else for (const c of siblings) out.push(...usageLines(ui, c), ...paragraph(ui, c.summary, 6));
    out.push("");
    out.push(...paragraph(ui, `Run \`doorman help ${name} <command>\` for one of them.`));
  }
  out.push(...paragraph(ui, "Every command also takes --json (machine-readable output), --verbose, --quiet, --no-color and --help."));
  return out;
}

/** An indented note line, like `  a  allow once` or `  key   what it takes`:
 * as written, or on a narrow terminal wrapped under the text after its
 * first word (below that word when it leaves too little room). */
function noteLines(ui: Ui, note: string): string[] {
  const lead = /^\s+\S+\s+/.exec(note)?.[0] ?? "";
  if (ui.width === undefined || note.length <= ui.width || lead === "") return [ui.prose(note)];
  const rest = ui.prose(note.slice(lead.length));
  if (ui.width - lead.length < 20) return [lead.trimEnd(), ...ui.wrap(rest, Math.max(20, ui.width - 6)).map((l) => `      ${l}`)];
  const pad = " ".repeat(lead.length);
  return ui.wrap(rest, ui.width - lead.length).map((l, i) => `${i === 0 ? lead : pad}${l}`);
}

/** The usage line; on a narrow terminal it breaks between arguments (never
 * inside `[--days <n>]`) and hangs under the first one, or, when the
 * command's name leaves too little room, under the name. */
function usageLines(ui: Ui, command: CliCommand): string[] {
  const s = ui.style;
  const line = usageLine(command);
  const head = `doorman ${command.name}`;
  if (ui.width === undefined || line.length + 2 <= ui.width) return [`  ${ui.decorate ? s.accent(line) : line}`];
  const args = command.usage?.match(/\[[^\]]*\]|<[^>]*>|\([^)]*\)|\S+/g) ?? [];
  const besideRoom = ui.width - (head.length + 3);
  const beside = besideRoom >= 20 && args.every((a) => a.length <= besideRoom);
  const hang = beside ? head.length + 3 : 6;
  const room = ui.width - hang;
  const lines: string[] = [];
  for (const arg of args) {
    const last = lines.length - 1;
    if (last >= 0 && lines[last]!.length + 1 + arg.length <= room) lines[last] += ` ${arg}`;
    else lines.push(arg);
  }
  const name = `  ${ui.decorate ? s.accent(head) : head}`;
  if (!beside) return [name, ...lines.map((l) => `${" ".repeat(hang)}${l}`)];
  return [`${name} ${lines[0] ?? ""}`, ...lines.slice(1).map((l) => `${" ".repeat(hang)}${l}`)];
}

/** The families and commands the person may have meant, for an unknown name. */
export function suggest(input: string, commands: readonly CliCommand[]): string | undefined {
  const names = [...new Set(commands.flatMap((c) => [c.name, familyOf(c.name)]))];
  let best: { name: string; d: number } | undefined;
  for (const name of names) {
    const d = distance(input, name);
    if (d <= Math.max(1, Math.floor(name.length / 3)) && (!best || d < best.d)) best = { name, d };
  }
  return best?.name;
}

/** Edits from `a` to `b`: insert, delete, replace, or swap two neighbours
 * (optimal string alignment, so `gaurd` is one edit from `guard`). */
function distance(a: string, b: string): number {
  const d = Array.from({ length: a.length + 1 }, (_, i) => Array.from({ length: b.length + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0)));
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i]![j] = Math.min(d[i - 1]![j]! + 1, d[i]![j - 1]! + 1, d[i - 1]![j - 1]! + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i]![j] = Math.min(d[i]![j]!, d[i - 2]![j - 2]! + 1);
    }
  }
  return d[a.length]![b.length]!;
}

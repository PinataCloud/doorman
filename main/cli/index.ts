#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parseArgs } from "node:util";
import type { CliCommand } from "./command.js";
import { COMMANDS } from "./commands/index.js";
import { CliContext, defaultEnvironment, type CliEnvironment } from "./context.js";
import { CliError, table } from "./output.js";

/** The CLI's own version: `cli/package.json` in the repo, the root
 * `package.json` in the published package (both three levels above build/main/cli). */
function packageVersion(): string {
  const root = join(__dirname, "..", "..", "..");
  for (const path of [join(root, "cli", "package.json"), join(root, "package.json")]) {
    try {
      const raw: unknown = JSON.parse(readFileSync(path, "utf8"));
      if (raw && typeof raw === "object" && "version" in raw && typeof raw.version === "string") return raw.version;
    } catch {
      // the other location
    }
  }
  return "0.0.0";
}

/** The longest command name the arguments start with (`guard install` before `guard`). */
export function matchCommand(argv: readonly string[], commands: readonly CliCommand[]): { command: CliCommand; rest: string[] } | undefined {
  let best: { command: CliCommand; rest: string[] } | undefined;
  for (const command of commands) {
    const words = command.name.split(" ");
    if (words.every((w, i) => argv[i] === w) && (!best || words.length > best.command.name.split(" ").length)) {
      best = { command, rest: argv.slice(words.length) };
    }
  }
  return best;
}

function helpText(commands: readonly CliCommand[], version: string): string[] {
  return [
    `doorman ${version}: watch what your AI coding agents read and run, from the terminal.`,
    "",
    "Usage: doorman <command> [options]",
    "",
    ...table(
      ["Command", "What it does"],
      commands.map((c) => [c.name, c.summary]),
    ).map((l) => `  ${l}`),
    "",
    "Run `doorman <command> --help` for its arguments and options.",
    "Global options: --json (machine-readable output), --verbose (log to stderr), --help, --version",
    "Data: the desktop app's own directory (DOORMAN_APPDATA_DIR overrides), so the CLI and the app share one store.",
  ];
}

function commandHelp(command: CliCommand): string[] {
  return [`Usage: doorman ${command.name}${command.usage ? ` ${command.usage}` : ""}`, "", command.summary, ...(command.details ? ["", ...command.details] : [])];
}

/** Runs one invocation and returns the exit code; never throws. */
export async function main(argv: readonly string[], io?: CliEnvironment): Promise<number> {
  const version = io?.version ?? packageVersion();
  const json = argv.includes("--json");
  const verbose = argv.includes("--verbose");
  const help = argv.includes("--help") || argv.includes("-h");
  const args = argv.filter((a) => a !== "--json" && a !== "--verbose" && a !== "--help" && a !== "-h");
  const env = io ?? defaultEnvironment(version, verbose);
  const write = (lines: readonly string[]) => env.stdout.write(lines.length > 0 ? `${lines.join("\n")}\n` : "");

  if (args[0] === "--version" || args[0] === "-v") {
    write([version]);
    return 0;
  }
  if (args.length === 0 || args[0] === "help") {
    const target = args[0] === "help" ? matchCommand(args.slice(1), COMMANDS) : undefined;
    write(target ? commandHelp(target.command) : helpText(COMMANDS, version));
    return 0;
  }
  const match = matchCommand(args, COMMANDS);
  if (!match) {
    env.stderr.write(`doorman: unknown command "${args.join(" ")}". Run \`doorman help\`.\n`);
    return 2;
  }
  if (help) {
    write(commandHelp(match.command));
    return 0;
  }
  const { command, rest } = match;
  let parsed;
  try {
    parsed = parseArgs({ args: [...rest], options: command.options ?? {}, allowPositionals: true, strict: true });
  } catch (err) {
    env.stderr.write(`doorman ${command.name}: ${err instanceof Error ? err.message : String(err)}\n`);
    return 2;
  }
  const range = command.positionals ?? { min: 0, max: 0 };
  if (parsed.positionals.length < range.min || parsed.positionals.length > range.max) {
    env.stderr.write(`doorman ${command.name}: expected ${commandHelp(command)[0]!.replace("Usage: ", "")}\n`);
    return 2;
  }
  try {
    const result = await command.run(new CliContext(env), { values: parsed.values, positionals: parsed.positionals });
    if (json) env.stdout.write(`${JSON.stringify(result.data, null, 2)}\n`);
    else write(result.text);
    return result.exitCode ?? 0;
  } catch (err) {
    if (err instanceof CliError) {
      env.stderr.write(`doorman: ${err.message}\n`);
      return err.exitCode;
    }
    env.stderr.write(`doorman: ${err instanceof Error ? (verbose ? (err.stack ?? err.message) : err.message) : String(err)}\n`);
    return 1;
  }
}

if (require.main === module) {
  void main(process.argv.slice(2)).then((code) => {
    process.exitCode = code;
  });
}

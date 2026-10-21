#!/usr/bin/env node
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { doormanDataDir } from "../lib/data-dir.js";
import { maybeStartModelDownload } from "./auto-download.js";
import type { CliCommand } from "./command.js";
import { modelDownloadFailureNotice } from "./commands/model.js";
import { COMMANDS } from "./commands/index.js";
import { CliContext, defaultEnvironment, type CliEnvironment } from "./context.js";
import { commandHelp, homeHelp, suggest, usageLine } from "./help.js";
import { CliError } from "./output.js";
import { termInfo, toAscii, Ui } from "./ui.js";
import { startUpdateCheck } from "./update-check.js";

const DEFAULT_PACKAGE = "@pinata/doorman";

/** The CLI's own package: `cli/package.json` in the repo, the root
 * `package.json` in the published package (both three levels above build/main/cli). */
function packageInfo(): { name: string; version: string } {
  const root = join(__dirname, "..", "..", "..");
  for (const path of [join(root, "cli", "package.json"), join(root, "package.json")]) {
    try {
      const raw: unknown = JSON.parse(readFileSync(path, "utf8"));
      if (raw && typeof raw === "object" && "version" in raw && typeof raw.version === "string") {
        return { name: "name" in raw && typeof raw.name === "string" ? raw.name : DEFAULT_PACKAGE, version: raw.version };
      }
    } catch {
      // the other location
    }
  }
  return { name: DEFAULT_PACKAGE, version: "0.0.0" };
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

/**
 * A failure on stderr. Plain: `doorman: <message> <hint>` on one line
 * (scripts match on it). On a terminal: a red mark, the message with its
 * commands coloured, and the hint under it, dim.
 */
function errorText(ui: Ui, message: string, hint: string | undefined): string {
  if (!ui.decorate) return `doorman: ${message}${hint ? ` ${hint}` : ""}\n`;
  const [first = "", ...rest] = message.split("\n");
  const lines = [ui.mark("error", ui.style.bold(ui.prose(first))), ...rest.map((l) => `  ${ui.prose(l)}`)];
  if (hint) lines.push(`  ${ui.style.dim(ui.prose(hint))}`);
  return `${lines.join("\n")}\n`;
}

/** The command an unknown invocation most likely meant, word by word:
 * `gaurd install` → `guard install`, not just `guard`. */
function guessCommand(words: readonly string[]): string | undefined {
  const first = words[0] ?? "";
  const head = COMMANDS.some((c) => c.name.split(" ")[0] === first) ? first : suggest(first, COMMANDS)?.split(" ")[0];
  if (!head) return suggest(words.join(" "), COMMANDS);
  const subs = COMMANDS.filter((c) => c.name.startsWith(`${head} `));
  const second = words[1];
  if (second !== undefined && !second.startsWith("-") && subs.length > 0) {
    const exact = subs.find((c) => c.name === `${head} ${second}`);
    const sub = exact?.name ?? suggest(`${head} ${second}`, subs);
    if (sub && sub !== head) return sub;
  }
  return head;
}

/** `doorman help <words>` for a family or command, or why there is none. */
function helpFor(words: readonly string[]): string | undefined {
  const match = matchCommand(words, COMMANDS);
  if (match && match.rest.length === 0) return match.command.name;
  const family = words[0];
  if (words.length === 1 && family && COMMANDS.some((c) => c.name.startsWith(`${family} `))) return family;
  return match?.command.name;
}

/** The stream, with each string written to it in its ASCII form (`toAscii`). */
function asciiStream<T extends NodeJS.WritableStream>(stream: T): T {
  // write's overloads (chunk, encoding?, callback?) pass through as given.
  const write = stream.write.bind(stream) as (...args: unknown[]) => boolean;
  return new Proxy(stream, {
    get(target, property) {
      if (property === "write") return (chunk: unknown, ...rest: unknown[]) => write(typeof chunk === "string" ? toAscii(chunk) : chunk, ...rest);
      const value: unknown = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

/** Runs one invocation and returns the exit code; never throws. */
export async function main(argv: readonly string[], io?: CliEnvironment): Promise<number> {
  const pkg = io ? { name: io.packageName ?? DEFAULT_PACKAGE, version: io.version } : packageInfo();
  const version = pkg.version;
  const json = argv.includes("--json");
  const verbose = argv.includes("--verbose");
  const help = argv.includes("--help") || argv.includes("-h");
  const quiet = argv.includes("--quiet") || argv.includes("-q");
  const noColor = argv.includes("--no-color");
  const globals = new Set(["--json", "--verbose", "--help", "-h", "--quiet", "-q", "--no-color"]);
  const args = argv.filter((a) => !globals.has(a));
  const base = io ?? { ...defaultEnvironment(version, verbose), packageName: pkg.name };
  // --no-color: as NO_COLOR, for this run and anything it starts.
  const given: CliEnvironment = noColor ? { ...base, env: { ...base.env, NO_COLOR: "1" } } : base;
  // In ASCII mode every character Doorman writes is ASCII (ui.ts), except
  // --json on stdout, which is machine output and stays as it is.
  const asciiOut = !json && termInfo(given.stdout, given.env, given.platform).ascii;
  const asciiErr = termInfo(given.stderr, given.env, given.platform).ascii;
  const env: CliEnvironment = {
    ...given,
    stdout: asciiOut ? asciiStream(given.stdout) : given.stdout,
    stderr: asciiErr ? asciiStream(given.stderr) : given.stderr,
  };
  const write = (lines: readonly string[]) => env.stdout.write(lines.length > 0 ? `${lines.join("\n")}\n` : "");
  const outUi = Ui.for(env.stdout, env.env, env.platform);
  const errUi = Ui.for(env.stderr, env.env, env.platform);
  const fail = (message: string, hint: string | undefined, code: number) => {
    env.stderr.write(errorText(errUi, message, hint));
    return code;
  };

  if (args[0] === "--version" || args[0] === "-v") {
    write([version]);
    return 0;
  }
  if (args.length === 0 || (args[0] === "help" && args.length === 1)) {
    // A first run: nothing written yet, not even by the app.
    const firstRun = !existsSync(join(doormanDataDir(env.env, env.platform, env.home), "store"));
    write(homeHelp(outUi, COMMANDS, version, firstRun));
    return 0;
  }
  if (args[0] === "help") {
    const name = helpFor(args.slice(1));
    if (!name) {
      const guess = suggest(args.slice(1).join(" "), COMMANDS);
      return fail(`No command "${args.slice(1).join(" ")}".`, guess ? `Did you mean \`doorman help ${guess}\`? \`doorman help\` lists every command.` : "`doorman help` lists every command.", 2);
    }
    write(commandHelp(outUi, name, COMMANDS));
    return 0;
  }
  const match = matchCommand(args, COMMANDS);
  const family = !match && COMMANDS.some((c) => c.name.startsWith(`${args[0]} `)) ? args[0] : undefined;
  if (!match && family && (help || args.length === 1)) {
    // `doorman export`: a family with no bare command lists its commands;
    // asked for, on stdout; as a usage error, on stderr.
    if (help) {
      write(commandHelp(outUi, family, COMMANDS));
      return 0;
    }
    env.stderr.write(`${commandHelp(errUi, family, COMMANDS).join("\n")}\n`);
    return 2;
  }
  if (!match) {
    const guess = guessCommand(args);
    return fail(`Unknown command "${args.join(" ")}".`, guess ? `Did you mean \`doorman ${guess}\`? \`doorman help\` lists every command.` : "`doorman help` lists every command.", 2);
  }
  if (help) {
    write(commandHelp(outUi, match.command.name, COMMANDS));
    return 0;
  }
  const { command, rest } = match;
  let parsed;
  try {
    parsed = parseArgs({ args: [...rest], options: command.options ?? {}, allowPositionals: true, strict: true });
  } catch (err) {
    // node's own message, without its advice on positionals that start with "-".
    const why = err instanceof Error ? err.message.replace(/\. To specify a positional argument[\s\S]*$/, ".") : String(err);
    return fail(why, `Usage: ${usageLine(command)}. \`doorman ${command.name} --help\` lists its options.`, 2);
  }
  const range = command.positionals ?? { min: 0, max: 0 };
  const subs = COMMANDS.filter((c) => c.name.startsWith(`${command.name} `));
  const word = parsed.positionals[0];
  if (parsed.positionals.length > range.max && subs.length > 0 && word !== undefined) {
    // `doorman guard instal`: a mistyped subcommand, not an argument.
    const guess = suggest(`${command.name} ${word}`, subs);
    return fail(
      `Unknown ${command.name} command "${word}".`,
      guess && guess !== command.name ? `Did you mean \`doorman ${guess}\`?` : `\`doorman help ${command.name}\` lists its commands.`,
      2,
    );
  }
  if (parsed.positionals.length < range.min || parsed.positionals.length > range.max) {
    const what = parsed.positionals.length < range.min ? "Missing an argument." : "Too many arguments.";
    return fail(what, `Usage: ${usageLine(command)}. \`doorman ${command.name} --help\` has examples.`, 2);
  }
  const ctx = new CliContext(env);
  ctx.commandName = command.name;
  ctx.json = json;
  ctx.quiet = quiet;
  // `completion` runs on every Tab press, its stderr discarded: nothing in the
  // background, and no notice someone would never see.
  const background = command.name !== "completion";
  // Whether a newer CLI is out: asked at most once a day, while the command
  // runs, and said on stderr after its output (update-check.ts).
  const updateNotice = command.name === "update" || !background ? undefined : startUpdateCheck(ctx, env.packageName ?? DEFAULT_PACKAGE, env.version);
  let code: number;
  try {
    // The classifier's model, if it is on and not here yet: fetched by a
    // detached child while this command runs (auto-download.ts).
    if (background) maybeStartModelDownload(ctx, command.name);
    const result = await command.run(ctx, { values: parsed.values, positionals: parsed.positionals });
    if (json) given.stdout.write(`${JSON.stringify(result.data, null, 2)}\n`);
    else if (result.raw) given.stdout.write(result.text.length > 0 ? `${result.text.join("\n")}\n` : "");
    else write(result.text);
    code = result.exitCode ?? 0;
  } catch (err) {
    if (err instanceof CliError) {
      code = fail(err.message, err.hint, err.exitCode);
    } else if (!verbose && err instanceof Error && "code" in err && err.code === "ENOENT" && "path" in err && typeof err.path === "string") {
      code = fail(`No such file: ${err.path}`, undefined, 1);
    } else {
      code = fail(err instanceof Error ? (verbose ? (err.stack ?? err.message) : err.message) : String(err), undefined, 1);
    }
  } finally {
    // An app waiting to start goes ahead the moment this command is done.
    ctx.releaseWrite();
  }
  // A background model download that failed and nobody was told (model.ts).
  let failed: string | undefined;
  try {
    failed = background ? modelDownloadFailureNotice(ctx, command.name) : undefined;
  } catch {
    failed = undefined; // a notice never fails a command
  }
  if (failed) env.stderr.write(`\n${errUi.decorate ? errUi.mark("warn", errUi.prose(failed)) : failed}\n`);
  // --quiet: only the command's own output, warnings and errors.
  const notice = quiet ? undefined : await updateNotice?.();
  if (notice) env.stderr.write(`\n${errUi.decorate ? errUi.mark("info", errUi.prose(notice)) : notice}\n`);
  return code;
}

if (require.main === module) {
  void main(process.argv.slice(2)).then((code) => {
    process.exitCode = code;
  });
}

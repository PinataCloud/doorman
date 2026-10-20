import type { ParseArgsConfig } from "node:util";
import type { CliContext } from "./context.js";
import type { CommandResult } from "./output.js";

export type OptionSpec = NonNullable<ParseArgsConfig["options"]>;

export interface ParsedArgs {
  values: Record<string, string | boolean | (string | boolean)[] | undefined>;
  positionals: string[];
}

/**
 * One `doorman <name>` command. `name` may hold a space (`guard install`): the
 * dispatcher matches the longest name the argv starts with. `--json`,
 * `--verbose` and `--help` are global and never reach `options`.
 */
export interface CliCommand {
  name: string;
  /** One line for `doorman help`. */
  summary: string;
  /** What follows the name, e.g. `<finding-id> [--status reviewed]`. */
  usage?: string;
  /** `doorman <name> --help`'s Options: the flag as typed (`--days <n>`) and
   * what it does, one short line each. */
  flags?: readonly (readonly [flag: string, what: string])[];
  /** Examples: the command line, and what it does. */
  examples?: readonly (readonly [command: string, what: string])[];
  /** Paragraphs after the options. Wrapped to the terminal; a line starting
   * with spaces is kept as written (lists, tables). */
  notes?: readonly string[];
  options?: OptionSpec;
  /** How many positionals it takes; default none. */
  positionals?: { min: number; max: number };
  run(ctx: CliContext, args: ParsedArgs): Promise<CommandResult>;
}

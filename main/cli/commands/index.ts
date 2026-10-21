import type { CliCommand } from "../command.js";
import { changelogCommand } from "./changelog.js";
import { completionCommand } from "./completion.js";
import { dataCommands } from "./data.js";
import { guardCommands } from "./guard.js";
import { integrationCommands } from "./integrations.js";
import { sbxCommands } from "./sbx.js";
import { statusCommand } from "./status.js";
import { updateCommand } from "./update.js";

/** Every command. `doorman help` lists them by family in groups (help.ts);
 * `doorman completion` reads them all for its scripts. */
export const COMMANDS: readonly CliCommand[] = [statusCommand, ...dataCommands, ...guardCommands, ...integrationCommands, ...sbxCommands, updateCommand, changelogCommand, completionCommand(() => COMMANDS)];

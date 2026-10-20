import type { CliCommand } from "../command.js";
import { dataCommands } from "./data.js";
import { guardCommands } from "./guard.js";
import { integrationCommands } from "./integrations.js";
import { statusCommand } from "./status.js";
import { updateCommand } from "./update.js";

/** Every command. `doorman help` lists them by family in groups (help.ts). */
export const COMMANDS: readonly CliCommand[] = [statusCommand, ...dataCommands, ...guardCommands, ...integrationCommands, updateCommand];

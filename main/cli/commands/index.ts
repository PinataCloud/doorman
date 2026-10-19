import type { CliCommand } from "../command.js";
import { dataCommands } from "./data.js";
import { guardCommands } from "./guard.js";
import { integrationCommands } from "./integrations.js";
import { statusCommand } from "./status.js";
import { updateCommand } from "./update.js";

/** Every command, in the order `doorman help` lists them. */
export const COMMANDS: readonly CliCommand[] = [statusCommand, ...dataCommands, ...guardCommands, ...integrationCommands, updateCommand];

import type { CliCommand } from "../command.js";
import { configCommands } from "./config.js";
import { doctorCommand } from "./doctor.js";
import { editorCommands } from "./editor.js";
import { gatewayCommands } from "./gateway.js";
import { mcpCommands } from "./mcp.js";
import { modelCommands } from "./model.js";

/** The Integrations screen and the headless half of Settings. */
export const integrationCommands: CliCommand[] = [...mcpCommands, ...gatewayCommands, ...editorCommands, doctorCommand, ...modelCommands, ...configCommands];

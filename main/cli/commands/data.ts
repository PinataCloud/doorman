import type { CliCommand } from "../command.js";
import { findingsCommand, findingsShowCommand, findingsStatusCommands } from "./findings.js";
import { exportBundleCommand, exportDetectionsCommand, exportLedgerCommand, reportCommand } from "./report.js";
import { scanCommand } from "./scan.js";
import { searchCommand, sessionCommand, sessionsCommand } from "./sessions.js";
import { traceCommand } from "./trace.js";
import { analyticsCommand, usageCommand } from "./usage.js";

/** The Radar, Ledger, Usage and Analytics screens, from the terminal. */
export const dataCommands: CliCommand[] = [
  scanCommand,
  findingsCommand,
  findingsShowCommand,
  ...findingsStatusCommands,
  sessionsCommand,
  sessionCommand,
  searchCommand,
  usageCommand,
  analyticsCommand,
  reportCommand,
  exportDetectionsCommand,
  exportLedgerCommand,
  exportBundleCommand,
  traceCommand,
];

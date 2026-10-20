/**
 * Stored findings re-read under the current severity bands.
 *
 * The bands say what happened to a secret, and an older build said too much:
 * a credential pasted into a prompt was critical while the same value shown
 * to the model in a tool's output was high; a `.env` read was high whether it
 * printed the file or piped it into `curl`; a secret sent to a host in the
 * same command was high and "leaked" though it never touched the model. The
 * detectors now band by reach (guard/security-detect.ts): the value in the
 * model's context is high; a read printed back to the agent, or a value sent
 * to a host without passing through the model, is medium; a read that kept
 * its output on this computer is low.
 *
 * The ledger keeps rows for months and only a new sighting rewrites one, so a
 * session looked at today would still read by yesterday's bands. This moves a
 * row off an OLD band and nothing else — a row a current detector minted
 * already carries the new one — and re-renders the card's words from the
 * account's fields, so the sentence matches the band. An old read cannot say
 * where its output went (the command is not kept), so it lands on medium,
 * and its card says "if it printed …".
 */

import type { SecuritySeverity } from "../guard/security-detect.js";
import { refreshAccountText } from "./account.js";
import type { FindingRow } from "./findings.js";

/** detector → the band an older build wrote → the band it reads at now. */
const REBANDS: Readonly<Record<string, readonly [SecuritySeverity, SecuritySeverity]>> = {
  credential_in_prompt: ["critical", "high"],
  secret_egress: ["high", "medium"],
  dotenv_read: ["high", "medium"],
  env_dump: ["high", "medium"],
  secret_manager_read: ["high", "medium"],
};

export function rebandFindingRow(row: FindingRow): FindingRow {
  const reband = Object.hasOwn(REBANDS, row.detector) ? REBANDS[row.detector] : undefined;
  const severity = reband !== undefined && row.severity === reband[0] ? reband[1] : row.severity;
  // The extractor's words are a function of its fields, so rendering them
  // again is safe and settles: an up-to-date row comes back unchanged. A
  // local reader's account is its own text and is left as it is.
  const account = row.account?.by === "extractor" ? refreshAccountText(row.detector, row.account) : row.account;
  if (severity === row.severity && JSON.stringify(account) === JSON.stringify(row.account)) return row;
  return { ...row, severity, ...(account === undefined ? {} : { account }) };
}

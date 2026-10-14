/**
 * Per-detector remediation guidance folded into the "How to fix this?" prompt
 * with a finding — what the rule means, what to do first — kept short and
 * deterministic so the model starts
 * from the product's own position rather than inventing one. Pure data.
 *
 * Narrowed through guard/rule-scope.ts: the snapshot hands this map
 * to the renderer whole, so a hidden rule's guidance must not be in it.
 */

import { shownRecord } from "../guard/rule-scope.js";

export interface DetectorGuidance {
  blurb: string;
  fix: string;
}

export const DETECTOR_GUIDANCE: Record<string, DetectorGuidance> = shownRecord<string, DetectorGuidance>({
  credential_in_prompt: {
    blurb: "A live credential was pasted into a prompt, so it already reached the model provider.",
    fix: "Rotate the credential now; then find how it got into the prompt (a pasted .env, a config block) and keep it out next time.",
  },
  credential_in_tool_arg: {
    blurb: "The agent put a recognized credential into a tool call it authored — the value was already in its context.",
    fix: "Find the upstream exposure (a prompt paste or a file read) and rotate if the value is real; if it was handed over deliberately, consider a scoped exception.",
  },
  secret_egress: {
    blurb: "One command both read a credential source and reached the network.",
    fix: "Confirm where the bytes went; if it was not a deploy you intended, rotate what the file held and deny similar calls (the rule ships on ask).",
  },
  env_dump: { blurb: "The whole environment was printed, API keys included.", fix: "Usually diagnostic; prefer printing named variables. Nothing to rotate unless the output was sent somewhere." },
  dotenv_read: { blurb: "A file that is a credential by name was read.", fix: "Routine in development; the finding matters when it precedes a network call. Consider an exception scoped to the project if it is your own .env." },
  hardcoded_credential: { blurb: "A high-entropy literal was written into a file under a secret-shaped name.", fix: "Move the value to an environment variable or secret manager before it is committed; rotate if the file was pushed." },
  unsafe_fetch_exec: { blurb: "A download was piped straight into an interpreter.", fix: "Download first, read the script, then run it — or pin to a checksum. Deny the held call unless the source is one you trust." },
  destructive_command: { blurb: "An irreversible local or SQL operation.", fix: "Check the target path or table; if intended, allow once. Never allow-for-project a rm -rf against a root-ish path." },
  infra_mutation: { blurb: "Cloud, cluster or datastore state was changed.", fix: "Confirm the environment (dev vs prod) and the change plan; a destroy against production is the case to deny." },
  unrecognized_secret: { blurb: "A high-entropy token no named pattern claimed — a guess.", fix: "Decide whether it is a real secret; if not, mark it a false positive. This rule never holds a call." },
  invisible_unicode: { blurb: "Invisible characters that can smuggle instructions.", fix: "Inspect the source text (View raw) — a tag-block payload or bidi override is an attack; a stray zero-width in copied text is noise." },
  exfil_render_link: { blurb: "A markdown/HTML link whose URL carries a payload — it exfiltrates on render.", fix: "Treat the tool result as hostile; do not render or click it; check what the agent did after reading it." },
  secret_manager_read: { blurb: "A credential fetched from a secret manager.", fix: "Expected in ops work; the finding matters when a later call sends it out. Nothing to rotate on its own." },
  agent_config_tamper: { blurb: "A write to the agent's own governance: hooks, permissions, MCP servers, shell startup, launch agents, ssh keys, sudoers.", fix: "Read the diff. If you did not ask for the change, treat the session as compromised and restore the file from version control or a backup." },
  injected_instruction: { blurb: "Text a tool RETURNED tried to steer the agent.", fix: "Distrust the whole tool result and check the following calls for credential reads, config writes and network sends; consider the source (a web page, an issue) hostile." },
  insecure_code_written: { blurb: "A known-dangerous construct in code on its way to disk.", fix: "Review the diff; fix or justify it before commit. Test fixtures are the usual false positive." },
  pii_exposure: { blurb: "A checksum-valid payment card, IBAN or SSN appeared.", fix: "Find where it came from; if it is real customer data, remove it from the transcript's source and report per your data-handling policy." },
  license_contamination: { blurb: "Copyleft or proprietary license text arrived in a written file.", fix: "Check the provenance of the pasted code before it is committed; replace it if the license is incompatible." },
  security_control_disabled: { blurb: "A command whose only purpose is to turn a protection off (Gatekeeper, SIP, firewall, setuid…).", fix: "Confirm you asked for it. If not, treat the session as steered: check what the agent read just before, and re-enable the control." },
  flow_secret_egress: { blurb: "A credential read in one call, a network send in a later call of the same session.", fix: "Follow the two calls in the Event Ledger; if the send carried the credential, rotate it." },
  flow_injection_followed: { blurb: "An injected instruction arrived, and a later call did what it asked — the critical escalation.", fix: "Assume compromise of that session: rotate anything it read, review anything it wrote or sent, and consider blocking the source." },
  flow_fetch_then_exec: { blurb: "Content downloaded, then executed by a later call.", fix: "Read the downloaded file before it runs again; prefer pinned, checksummed installs." },
  flow_read_then_send: { blurb: "Private data read from mail/chat/docs, then an outbound send.", fix: "Check the recipient of the send; if it is outside your organization, treat it as exfiltration." },
  flow_sql_second_order: { blurb: "A database result interpolated into a later query.", fix: "Parameterize the second query; never build SQL from result text." },
  flow_fetch_then_install: { blurb: "Fetched content named a package, and a later call installed it — an untrusted page chose a dependency.", fix: "Check the package's provenance (registry page, publisher, download counts) before it stays; remove it if the page that named it was not one you trust." },
  flow_insecure_code_executed: { blurb: "A file this session wrote with a known-dangerous construct was then executed.", fix: "Read the written file before it runs again; fix the construct (eval of a variable, pickle.loads, shell=True…) or justify it in review." },
  agent_loop: { blurb: "The same tool call repeated with identical arguments — the agent was stuck, and it burned tokens for nothing.", fix: "Nothing to secure; consider a tighter prompt or a step limit for that task." },
  unknown_mcp_server: { blurb: "A session used an MCP server nobody approved.", fix: "Review the server on Integrations; recognize it if you know it, remove it from the config if you don't." },
  mcp_tool_poisoning: { blurb: "Injection patterns inside an MCP server's config or tool output.", fix: "Stop using the server until you have read the flagged text; if it is a hidden instruction block, remove the server and rotate anything it could read." },
  mcp_tool_changed: { blurb: "A routed server changed a tool description after you first saw it — the rug pull.", fix: "Read the change note; if the new text steers the agent, remove the server. Re-recognize it only after reading the new description." },
  egress_new_destination: { blurb: "First send to an exfiltration-shaped destination (paste site, webhook, file share).", fix: "Confirm the destination is yours; if not, find the call in the Ledger and what it carried." },
  guard_tampered: { blurb: "The guard's hook entry or bundle changed outside the app — a silent fail-open.", fix: "Reinstall the guard from Settings, then find what changed the file (an agent writing settings.json is itself a finding)." },
}) as Record<string, DetectorGuidance>;

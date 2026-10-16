import { maskTurnText } from "../../lib/masking.js";
import { literalForms, normalizeTraceInput, type TraceReport } from "../../lib/secret-trace.js";
import type { CliCommand } from "../command.js";
import type { CliEnvironment } from "../context.js";
import { CliError } from "../output.js";
import { withEngine } from "./data-shared.js";

type RawModeStream = NodeJS.ReadableStream & { isTTY?: boolean; setRawMode?: (on: boolean) => unknown };

/**
 * The value to trace, from stdin and nowhere else: never argv (shell history,
 * `ps`), never echoed. On a terminal it is typed or pasted in raw mode, so
 * nothing appears, and ends at Enter; piped, it is the whole input.
 */
async function readSecret(io: CliEnvironment): Promise<string> {
  const stdin = io.stdin as RawModeStream;
  if (stdin.isTTY === true && typeof stdin.setRawMode === "function") {
    io.stderr.write("Paste the value to trace, then press Enter (it won't be shown): ");
    stdin.setRawMode(true);
    stdin.resume();
    try {
      return await new Promise<string>((resolve, reject) => {
        let value = "";
        const onData = (chunk: Buffer | string) => {
          for (const ch of chunk.toString()) {
            if (ch === "\r" || ch === "\n" || ch === "\u0004") {
              stdin.off("data", onData);
              resolve(value);
              return;
            }
            if (ch === "\u0003") {
              stdin.off("data", onData);
              reject(new CliError("Cancelled."));
              return;
            }
            if (ch === "\u007f" || ch === "\b") value = value.slice(0, -1);
            else value += ch;
          }
        };
        stdin.on("data", onData);
      });
    } finally {
      stdin.setRawMode(false);
      stdin.pause();
      io.stderr.write("\n");
    }
  }
  const chunks: Buffer[] = [];
  for await (const chunk of stdin) chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
  return Buffer.concat(chunks).toString("utf8");
}

export const traceCommand: CliCommand = {
  name: "trace",
  summary: "Trace a secret: where a value went across every transcript (read from stdin)",
  usage: "(the value on stdin)",
  details: [
    "Searches every agent transcript and the turn store on this machine for one value and reports",
    "where it went: which agents and providers saw it, files written with it, commands that carried",
    "it, and what the guard did. The value is read from stdin only (never an argument), is not shown,",
    "and is kept for the length of the search; the report carries its shape (length, last characters,",
    "family), not the value.",
    "  doorman trace            prompts for the value",
    "  pbpaste | doorman trace  reads it from a pipe",
  ],
  async run(ctx) {
    const normalized = normalizeTraceInput(await readSecret(ctx.io));
    if (!normalized.ok) throw new CliError(normalized.error);
    return withEngine(ctx, false, async ({ engine }) => {
      const report = await engine.traceSecret(normalized.value);
      // A sighting's target is a raw tool argument and could hold the value
      // itself (`KEY=... node`); nothing this prints may, so every literal
      // form of it is cut out of the whole report, Markdown included.
      const forms = literalForms(normalized.value).sort((a, b) => b.length - a.length);
      const scrubbed = forms.reduce((json, form) => json.split(JSON.stringify(form).slice(1, -1)).join("[redacted]"), JSON.stringify(report));
      const safe = JSON.parse(scrubbed) as TraceReport;
      for (const place of safe.places) for (const s of place.sightings) if (s.target !== undefined) s.target = maskTurnText(s.target);
      return { data: safe, text: safe.markdown.replace(/\n$/, "").split("\n") };
    });
  },
};

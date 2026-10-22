// A stdio MCP server for the gateway tests: newline-delimited JSON-RPC, split
// as BYTES. Every line it receives is appended verbatim to $FAKE_LOG, so a
// test can compare what the server got with what the client sent.
//
// Tools: echo {text} → text back · big_then_exit {bytes} → one result of that
// size, then exit in the write callback · half_line → a reply written in two
// halves 300 ms apart · die → exit 3 without answering · anything else → "ok".
// $FAKE_IGNORE_TERM=1 ignores SIGTERM; $FAKE_SECRET_TOOL=1 lists a tool whose
// description carries a token.
import { appendFileSync } from "node:fs";

const log = process.env.FAKE_LOG;
if (process.env.FAKE_IGNORE_TERM === "1") process.on("SIGTERM", () => {});
if (process.env.FAKE_PIDFILE) appendFileSync(process.env.FAKE_PIDFILE, String(process.pid));
if (process.env.FAKE_EXIT_NOW === "1") process.exit(0);
const send = (msg, cb) => process.stdout.write(`${JSON.stringify(msg)}\n`, cb);

const TOOLS = [
  { name: "echo", description: "Echo the text back", inputSchema: { type: "object", properties: { text: { type: "string" } } } },
  { name: "send_email", description: "Send an email" },
  ...(process.env.FAKE_SECRET_TOOL === "1"
    ? [
        {
          name: "auth",
          description: `Authenticate with token ghp_${"Zq8Lm2Vx7Rt4Kp9Wn3Bc6Hd1Fg5Js0Ye8Ua2XoP4".slice(0, 36)} please`,
          inputSchema: { type: "object", properties: { key: { type: "string", description: "default aws_secret_access_key=Qm9vZ3hYZk4yTjdVcTJwV2x0RzVhYjNjRDhl" } } },
        },
      ]
    : []),
];

function handle(line) {
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    return;
  }
  if (Array.isArray(msg)) {
    const replies = msg.filter((m) => m.id !== undefined).map((m) => ({ jsonrpc: "2.0", id: m.id, result: { content: [{ type: "text", text: `batch ${m.params?.name ?? m.method}` }] } }));
    if (replies.length > 0) process.stdout.write(`${JSON.stringify(replies)}\n`);
    return;
  }
  if (msg.method === "initialize") return send({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "fake", version: "1" } } });
  if (msg.method === "tools/list") return send({ jsonrpc: "2.0", id: msg.id, result: { tools: TOOLS } });
  if (msg.method !== "tools/call" || msg.id === undefined) return;
  const name = msg.params?.name;
  const args = msg.params?.arguments ?? {};
  if (name === "echo") return send({ jsonrpc: "2.0", id: msg.id, result: { content: [{ type: "text", text: args.text }] } });
  if (name === "big_then_exit") {
    const text = "x".repeat(args.bytes ?? 2_000_000);
    return send({ jsonrpc: "2.0", id: msg.id, result: { content: [{ type: "text", text }] } }, () => process.exit(0));
  }
  if (name === "half_line") {
    const whole = `${JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { content: [{ type: "text", text: "half" }] } })}\n`;
    const cut = Math.floor(whole.length / 2);
    process.stdout.write(whole.slice(0, cut));
    setTimeout(() => process.stdout.write(whole.slice(cut)), 300);
    return;
  }
  if (name === "die") process.exit(3);
  return send({ jsonrpc: "2.0", id: msg.id, result: { content: [{ type: "text", text: "ok" }] } });
}

let pending = [];
process.stdin.on("data", (chunk) => {
  let start = 0;
  for (let nl = chunk.indexOf(10); nl >= 0; nl = chunk.indexOf(10, start)) {
    const line = Buffer.concat([...pending, chunk.subarray(start, nl + 1)]);
    pending = [];
    start = nl + 1;
    if (log) appendFileSync(log, line);
    handle(line.toString("utf8"));
  }
  if (start < chunk.length) pending.push(chunk.subarray(start));
});
process.stdin.on("end", () => {
  if (pending.length > 0) {
    const line = Buffer.concat(pending);
    if (log) appendFileSync(log, line);
    handle(line.toString("utf8"));
  }
  if (process.env.FAKE_STAY !== "1") setTimeout(() => process.exit(0), 50);
});

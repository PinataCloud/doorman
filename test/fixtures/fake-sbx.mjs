#!/usr/bin/env node
/**
 * A stand-in for Docker Sandboxes' `sbx` (0.46), for tests: point
 * DOORMAN_SBX_BIN at this file (executable) and FAKE_SBX_ROOT at a directory
 * holding `sandboxes.json`:
 *
 *   [{ "name": "a", "status": "running", "agent": "claude", "doorman": "installed" }]
 *
 * `doorman` is "installed" (the default), "missing" (exec fails the way
 * `docker exec` does) or "old" (a CLI without `watch --stdio`).
 *
 *   sbx ls --json                    {"sandboxes":[…]} as sbx prints it
 *   sbx exec [-i] [-t] <name> <cmd…> runs <cmd> "inside": `doorman` is the
 *                                    compiled CLI (build/main/cli/index.js)
 *                                    with the sandbox's HOME,
 *                                    DOORMAN_APPDATA_DIR, SANDBOX_NAME and
 *                                    SANDBOX_ID; stdin only with -i
 *   sbx rm [--force] <name>          forgets it and deletes its files
 *
 * Each sandbox's files are <root>/<name>/home and <root>/<name>/appdata.
 * Like the real one, exec starts a stopped sandbox.
 */

import { spawn } from "node:child_process";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = process.env.FAKE_SBX_ROOT;
if (!root) {
  process.stderr.write("fake sbx: FAKE_SBX_ROOT is not set\n");
  process.exit(1);
}
const statePath = join(root, "sandboxes.json");
const cli = process.env.FAKE_SBX_CLI ?? join(dirname(fileURLToPath(import.meta.url)), "..", "..", "build", "main", "cli", "index.js");
const read = () => JSON.parse(readFileSync(statePath, "utf8"));
const save = (list) => writeFileSync(statePath, JSON.stringify(list, null, 2));

function sandboxEnv(rootDir, name) {
  const home = join(rootDir, name, "home");
  const appData = join(rootDir, name, "appdata");
  return { HOME: home, DOORMAN_APPDATA_DIR: appData, SANDBOX_NAME: name, SANDBOX_ID: `sbx-${name}`, DOORMAN_NO_UPDATE_CHECK: "1" };
}

const [verb, ...rest] = process.argv.slice(2);

if (verb === "ls") {
  const sandboxes = read().map((s) => ({
    name: s.name,
    id: `id-${s.name}`,
    agent: s.agent ?? "claude",
    status: s.status ?? "running",
    last_used_at: new Date().toISOString(),
    workspaces: [join(root, s.name, "work")],
  }));
  process.stdout.write(`${JSON.stringify({ sandboxes }, null, 2)}\n`);
  process.exit(0);
}

if (verb === "rm") {
  const name = rest.filter((a) => !a.startsWith("-"))[0];
  const list = read();
  if (!list.some((s) => s.name === name)) {
    process.stderr.write(`sandbox ${name} not found\n`);
    process.exit(1);
  }
  save(list.filter((s) => s.name !== name));
  rmSync(join(root, name), { recursive: true, force: true });
  process.exit(0);
}

if (verb === "exec") {
  let interactive = false;
  let i = 0;
  for (; i < rest.length && rest[i].startsWith("-"); i++) {
    const flag = rest[i];
    if (/^-[it]+$/.test(flag)) interactive ||= flag.includes("i");
    else if (flag === "--interactive") interactive = true;
    else if (["-e", "--env", "-u", "--user", "-w", "--workdir"].includes(flag)) i++;
  }
  const [name, command, ...args] = rest.slice(i);
  const list = read();
  const sandbox = list.find((s) => s.name === name);
  if (!sandbox) {
    process.stderr.write(`ERROR: sandbox ${name} not found\n`);
    process.exit(1);
  }
  if (sandbox.status !== "running") {
    sandbox.status = "running";
    save(list);
  }
  const doorman = sandbox.doorman ?? "installed";
  if (command === "doorman" && doorman === "missing") {
    process.stderr.write('OCI runtime exec failed: exec failed: unable to start container process: exec: "doorman": executable file not found in $PATH: unknown\n');
    process.exit(127);
  }
  if (command === "doorman" && doorman === "old" && args.includes("--stdio")) {
    process.stderr.write("doorman: Unknown option '--stdio'. Usage: doorman watch [--auto deny] [--replace]. `doorman watch --help` lists its options.\n");
    process.exit(2);
  }
  const env = { ...process.env, ...sandboxEnv(root, name) };
  delete env.DOORMAN_SBX_BIN;
  mkdirSync(join(env.HOME, ".claude"), { recursive: true });
  mkdirSync(env.DOORMAN_APPDATA_DIR, { recursive: true });
  const [file, argv] = command === "doorman" ? [process.execPath, [cli, ...args]] : [command, args];
  const child = spawn(file, argv, { env, stdio: [interactive ? "inherit" : "ignore", "inherit", "inherit"] });
  for (const signal of ["SIGTERM", "SIGINT", "SIGHUP"]) process.on(signal, () => child.kill(signal));
  child.on("error", (err) => {
    process.stderr.write(`exec: ${err.message}\n`);
    process.exit(127);
  });
  child.on("exit", (code, signal) => process.exit(code ?? (signal ? 137 : 1)));
} else if (verb !== "ls" && verb !== "rm") {
  process.stderr.write(`fake sbx: no verb ${verb}\n`);
  process.exit(1);
}

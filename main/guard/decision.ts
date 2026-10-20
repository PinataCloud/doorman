/**
 * The guard's pure core: one tool call in, findings + an enforcement decision
 * out. Redact-first, exactly like every other caller of the detectors — and
 * `raw_text` (pre-redaction) rides along so hardcoded_credential can see what
 * a Write/Edit is about to put on disk.
 *
 * Two things layer on the shared detectors here, both this app's own:
 *  · SCOPED ignore rules (policy.ts applicableIgnoreRules) — the call's working
 *    directory decides which of the person's "not in this project" rules apply
 *    before the detector ever sees them;
 *  · CUSTOM rules (custom-rules.ts) — the person's own `when` clauses, each
 *    carrying its own posture, folded into the same decision as the detectors.
 *
 * Self-containment rule: this directory is compiled and copied verbatim into
 * the user's data dir, where Claude Code or Codex spawns it with plain `node`. Nothing
 * here may import from outside main/guard/.
 */

import { redact } from "./redact.js";
import { detectSecurityFindings, globToRegExp, invocationHeads, isWriteTool, shellUnescaped } from "./security-detect.js";
import { commandSegments } from "./segments.js";
import { Buffer } from "node:buffer";
import { posix, win32 } from "node:path";
import { homedir } from "node:os";
import { matchCustomRules } from "./custom-rules.js";
import {
  applicableIgnoreRules,
  decideEnforcement,
  parsePolicy,
  type EnforcementDecision,
  type GuardFinding,
  type GuardPolicy,
  type ScopedIgnoreRule,
} from "./policy.js";

export interface GuardHookInput {
  session_id?: string;
  tool_name?: string;
  tool_input?: unknown;
  /** The agent's working directory, from the hook payload. Scopes ignore and
   * custom rules; absent means unscoped rules only. */
  cwd?: string;
}

/** A finding a scoped ignore rule waved through, with that rule — recorded,
 * never enforced. */
export type ExceptedFinding = GuardFinding & { exception: ScopedIgnoreRule };

/** A prompt about to be sent, from a host that fires on prompts (hosts/types.ts
 * normalizePrompt). The text is RAW here; evaluatePrompt redacts it. */
export interface GuardPromptInput {
  session_id?: string;
  cwd?: string;
  prompt: string;
}

export interface GuardPromptResult {
  findings: GuardFinding[];
  excepted: ExceptedFinding[];
  decision: EnforcementDecision;
  /** The redacted prompt — what an approval card is allowed to show. */
  redacted: string;
}

/**
 * Evaluate a PROMPT before the model sees it — the one place "prevent" is
 * true for text the person typed: a seed phrase pasted into Claude Code is
 * stopped here, with the prompt erased, rather than recorded after the fact.
 * Same pipeline as a tool call (redact → detect → fold), `kind: "prompt"`, no
 * custom rules (a `when` clause describes a call). Whether a finding holds is
 * the detector's mode as for any call: `wallet_key_material` ships ask, and
 * `credential_in_prompt` — observe by default because it could never be acted
 * on — becomes enforceable the moment someone raises it.
 */
export function evaluatePrompt(input: GuardPromptInput, policy: GuardPolicy, nowMs: number = Date.now()): GuardPromptResult {
  const redacted = redact(input.prompt);
  const cwd = typeof input.cwd === "string" && input.cwd !== "" ? input.cwd : undefined;
  const ignore = applicableIgnoreRules(policy.ignore, cwd, nowMs);
  const excepted: ExceptedFinding[] = [];
  const findings: GuardFinding[] = detectSecurityFindings(
    { kind: "prompt", text: redacted },
    {
      disabled: policy.disabled,
      ignore,
      ...(policy.wallets === undefined ? {} : { wallets: policy.wallets }),
      onIgnored: (finding, rule) => excepted.push({ ...finding, exception: rule as ScopedIgnoreRule }),
    },
  );
  return { findings, excepted, decision: decideEnforcement(findings, policy), redacted };
}

export interface GuardResult {
  findings: GuardFinding[];
  /** What a detector raised and an applicable exception dropped: the person's
   * own decision, kept visible on the Radar rather than folded
   * into silence. Custom rules are never excepted (they are the person's own). */
  excepted: ExceptedFinding[];
  decision: EnforcementDecision;
  /** What the call is pointed at (Bash program name, or the file path). */
  target?: string;
  /** The redacted tool input — what an approval card is allowed to show. */
  redacted: string;
  /** The shell command, when this is a shell call — the custom rules and the
   * armed escalation both read it. */
  command?: string;
}

/** The Bash program name, or a file-tool path — duplicated from lib/ (10 lines)
 * rather than imported, to keep this directory copyable. */
export function toolTarget(toolName: string | undefined, input: unknown): string | undefined {
  if (!input || typeof input !== "object") return undefined;
  const obj = input as Record<string, unknown>;
  if (toolName === "Bash" || toolName === "shell") {
    const command = obj.command;
    if (typeof command !== "string" || command.trim() === "") return undefined;
    return command.trim().split(/\s+/, 1)[0];
  }
  for (const key of ["file_path", "path", "notebook_path"]) {
    const value = obj[key];
    if (typeof value === "string" && value !== "") return value;
  }
  return undefined;
}

/** The command string out of a tool input — the same keys the detector's own
 * readCommand walks, on the parsed object the guard already holds. */
export function commandOfInput(toolName: string | undefined, input: unknown): string | undefined {
  if (!input || typeof input !== "object") return undefined;
  const record = input as Record<string, unknown>;
  for (const key of ["command", "cmd", "script", "commandLine"]) {
    const value = record[key];
    if (typeof value === "string" && value !== "") return value;
  }
  if (toolName && /shell|bash/i.test(toolName)) {
    const first = Object.values(record).find((v) => typeof v === "string" && v !== "");
    return typeof first === "string" ? first : undefined;
  }
  return undefined;
}

export function evaluateToolCall(
  input: GuardHookInput,
  policy: GuardPolicy,
  nowMs: number = Date.now(),
): GuardResult {
  const raw = JSON.stringify(input.tool_input ?? {});
  const redacted = redact(raw);
  const target = toolTarget(input.tool_name, input.tool_input);
  const cwd = typeof input.cwd === "string" && input.cwd !== "" ? input.cwd : undefined;
  const ignore = applicableIgnoreRules(policy.ignore, cwd, nowMs);
  const excepted: ExceptedFinding[] = [];
  const findings: GuardFinding[] = detectSecurityFindings(
    {
      kind: "tool_call",
      text: redacted,
      raw_text: raw,
      tool_name: input.tool_name,
      target,
    },
    {
      disabled: policy.disabled,
      ignore,
      // The person's wallets: which chains to watch, and the hashed addresses
      // that are theirs (policy.ts `wallets`).
      ...(policy.wallets === undefined ? {} : { wallets: policy.wallets }),
      // The matcher hands back the very ScopedIgnoreRule object from `ignore`,
      // scope fields and all — that is what the spool line names.
      onIgnored: (finding, rule) => excepted.push({ ...finding, exception: rule as ScopedIgnoreRule }),
    },
  );
  const command = commandOfInput(input.tool_name, input.tool_input);
  if (policy.custom_rules && policy.custom_rules.length > 0) {
    // Custom rules read the REDACTED command: a rule can never be used to
    // probe for a secret's value, because the value is gone before it matches.
    const redactedCommand = command === undefined ? undefined : redact(command);
    findings.push(
      ...matchCustomRules(policy.custom_rules, {
        tool_name: input.tool_name,
        tool_input: input.tool_input,
        command: redactedCommand,
        target,
        cwd,
        redacted,
      }),
    );
  }
  return { findings, excepted, decision: decideEnforcement(findings, policy), target, redacted, command };
}

export { parsePolicy };

// ── Self-protection ──────────────────────────────────────────────────────────
//
// The guard's directory holds the handshake (`pending/<id>.reply.json` IS an
// approval), the policy it enforces and the armed-session state. An agent that
// can write there can approve its own hold, set every mode to observe, or
// replace the guard itself — and hides `agent_config_tamper`, the rule
// that used to notice. So this is NOT a rule: it cannot be hidden, silenced,
// excepted or observed down, and it holds whatever the policy says. Reading the
// directory is fine (the spool is the person's own record); changing it is not.
//
// Lexical, like every command check here: a path assembled at runtime
// (`$(printf …)`, a variable) escapes it. The hold is the common-case fix; the
// handshake cannot tell the app's reply from the agent's (both are this user),
// which is why the write itself has to be stopped.
//
// On Windows the same checks run with Windows path rules (PathRules): either
// separator, a drive letter or none (`\Users\…`, Git Bash `/c/…`, WSL
// `/mnt/c/…`, `\\?\C:\…` and `\\localhost\c$\…` all reach the same file, so a
// directory is matched wherever its drive-less path appears), `%APPDATA%` /
// `$env:APPDATA` expansion, trailing dots and alternate data streams folded,
// and every command read three ways — as bash (backslash escapes), as
// PowerShell (backslash literal, backtick escapes) and as cmd (caret escapes,
// `'` not a quote). 8.3 short names (`DOORMA~1`) are not resolved.

/** Programs that only READ their path arguments. Anything else naming a path
 * inside the guard directory is treated as changing it. */
const READ_ONLY_PROGRAMS: ReadonlySet<string> = new Set([
  "cat", "less", "more", "head", "tail", "grep", "egrep", "fgrep", "rg", "ag", "ls", "stat", "wc", "file",
  "jq", "diff", "cmp", "md5", "md5sum", "shasum", "sha256sum", "du", "find", "tree", "realpath", "readlink",
  "basename", "dirname", "echo", "printf", "test", "[", "open", "code", "bat", "xxd", "hexdump", "od", "strings",
]);

/** Windows programs and cmdlets that only read their path arguments — on
 * Windows only: some of these names mean something else elsewhere. Looked up
 * with Object.hasOwn: the key is the agent's program word. */
const WINDOWS_READ_ONLY_PROGRAMS: Readonly<Record<string, true>> = {
  "get-content": true, gc: true, type: true, "get-childitem": true, gci: true, dir: true, "get-item": true,
  gi: true, "get-itemproperty": true, gp: true, "test-path": true, "select-string": true, sls: true,
  findstr: true, "resolve-path": true, rvpa: true, "get-filehash": true, "join-path": true, "split-path": true,
  "get-acl": true, "format-hex": true, fhx: true, "write-output": true, "write-host": true,
  "measure-object": true, "convertfrom-json": true, "select-object": true, "sort-object": true,
  "format-list": true, "format-table": true, "out-string": true, "out-host": true,
};

/** A program word's name: its last path component, lowercased — on Windows
 * after either separator and without the `.exe`/`.cmd`/`.bat`/`.com`/`.ps1`
 * that `cmd.exe` and `powershell.exe` are usually spelled with. */
function programName(word: string, win: boolean): string {
  const base = (word.split(win ? /[\\/]/ : "/").pop() ?? word).toLowerCase();
  return win ? base.replace(/\.(?:exe|com|cmd|bat|ps1)$/, "") : base;
}

/**
 * Does this invocation of a READ_ONLY_PROGRAMS entry write after all? Each of
 * these has a spelling that puts bytes on disk: find's actions (`-delete`, the
 * `-exec` family, the `-fprint`/`-fls` output files), `xxd -r` or `xxd in out`,
 * `tree -o file`, `less --log-file`. When it does, every path it names is
 * treated as changed — the same as any unknown program.
 */
function writesDespiteReadOnly(program: string, words: readonly string[]): boolean {
  const args = words.slice(1);
  switch (program) {
    case "find":
      return args.some((w) => /^-(?:delete|exec|execdir|ok|okdir|fprint0?|fprintf|fls)$/.test(w));
    case "tree":
      return args.some((w) => w.startsWith("-o") || w.startsWith("--output"));
    case "less":
      return args.some((w) => /^-[A-Za-z]*[oO]/.test(w) || /^--log-file/i.test(w));
    case "rg":
      // `--pre CMD` runs CMD on every file it searches.
      return args.some((w) => /^--pre(?:=|$)/.test(w));
    case "diff":
      return args.some((w) => /^--output(?:=|$)/.test(w));
    case "xxd": {
      if (args.some((w) => /^-r/.test(w))) return true;
      // `xxd [options] [infile [outfile]]` — a second operand is written.
      let operands = 0;
      for (let i = 0; i < args.length; i += 1) {
        const w = args[i]!;
        if (w === ">" || w === ">>") {
          i += 1;
          continue;
        }
        if (w === "-") operands += 1;
        else if (/^-(?:c|cols|g|groupsize|l|len|n|name|o|s|seek)$/.test(w)) i += 1;
        else if (!w.startsWith("-")) operands += 1;
      }
      return operands >= 2;
    }
    default:
      return false;
  }
}

/**
 * Does some segment EXECUTE what an earlier one prints? `find $G | xargs rm`,
 * `… | parallel rm`, `… | while read f; do rm "$f"; done` and `echo "rm $G/x"
 * | sh` turn printed paths into operands of a command nobody wrote out, so a
 * guard path any head names — even `echo`'s or `find`'s — is a write. An
 * xargs/parallel that runs a read-only program is not one.
 */
function feedsAWriter(command: string, win: boolean): boolean {
  for (const raw of commandSegments(command)) {
    const segment = raw
      .trim()
      .replace(/^(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+)*(?:(?:\S*\/)?(?:sudo|doas|nice|nohup|time|command)\s+(?:-\S+\s+)*)*/, "");
    if (/^(?:while|until)\s+(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+)*read\b/.test(segment)) return true;
    if (/^(?:\S*\/)?(?:ba|z|da|k|fi)?sh(?:\s+-[a-zA-Z]+)*\s*$/.test(segment) && !/\s-[a-zA-Z]*c/.test(segment)) return true;
    if (/^(?:\S*\/)?(?:source|\.)\s+\/dev\/(?:stdin|fd\/0)\b/.test(segment)) return true;
    const runner = /^(?:\S*\/)?(xargs|parallel)(?:\s|$)/.exec(segment);
    if (!runner) continue;
    // What it runs: invocationHeads strips `xargs` and its flags; `parallel`
    // and its flags are stripped here. No program at all is xargs' `echo`.
    const inner =
      runner[1] === "xargs"
        ? (invocationHeads(segment)[0] ?? "")
        : segment.replace(/^(?:\S*\/)?parallel\s*(?:(?:-[jN]\s*\S+|--jobs[=\s]\S+|-\S+)\s+)*/, "");
    const words = shellWords(inner);
    const program = programName(words[0] ?? "", win);
    if (program === "" || program === "xargs" || program === "parallel") continue;
    const readOnly = READ_ONLY_PROGRAMS.has(program) || (win && Object.hasOwn(WINDOWS_READ_ONLY_PROGRAMS, program));
    if (readOnly && !writesDespiteReadOnly(program, words)) continue;
    return true;
  }
  // PowerShell binds piped objects to a cmdlet's -Path (`Get-ChildItem $G |
  // Remove-Item`) and runs a piped script block on each (`| % { … }`).
  return (
    win &&
    pipedSegments(command).some((segment) => {
      const program = programName(shellWords(invocationHeads(segment)[0] ?? "")[0] ?? "", true);
      return PIPE_WRITER_RE.test(program) || segment.replace(/'[^']*'|"[^"]*"/g, "").includes("{");
    })
  );
}

/** Cmdlets (and their aliases) that act on what is piped into them. */
const PIPE_WRITER_RE =
  /^(?:(?:remove|set|add|clear|copy|move|rename|new)-(?:item|content|itemproperty)|(?:invoke|start)-\w+|set-acl|tee-object|foreach-object|where-object|ri|rm|rmdir|rd|del|erase|sc|ac|clc|cpi|copy|cp|mi|move|mv|rni|ren|ni|si|cli|sp|rp|clp|cpp|mp|rnp|tee|foreach|where|%|\?|ii|saps|start|iex|icm)$/;

/** Every segment that a lone `|` feeds — quote-aware, `||` and `>|` excluded. */
function pipedSegments(command: string): string[] {
  const out: string[] = [];
  let quote: string | undefined;
  let current: string | undefined;
  const end = (next: string | undefined): void => {
    if (current !== undefined) out.push(current);
    current = next;
  };
  for (let i = 0; i < command.length; i += 1) {
    const ch = command[i]!;
    if (quote) {
      if (ch === quote) quote = undefined;
    } else if (ch === "'" || ch === '"') {
      quote = ch;
    } else if (ch === "|" && command[i - 1] !== ">") {
      if (command[i + 1] === "|") {
        i += 1;
        end(undefined);
      } else end("");
      continue;
    } else if (ch === "\n" || ch === ";" || (ch === "&" && command[i - 1] !== ">" && command[i + 1] !== ">")) {
      end(undefined);
      continue;
    }
    if (current !== undefined) current += ch;
  }
  end(undefined);
  return out;
}

/**
 * Programs that run a program TEXT — an inline `-c`/`-e` string, a script on
 * stdin, an awk/sed program, an AppleScript — rather than only operating on
 * their path operands. The guard path such a text names is not an operand
 * anyone can tell read from written (`python3 -c "open('$G/policy.json','w')"`,
 * `echo "rm $G/x" | sh`), so any guard path anywhere in a command that runs
 * one is a write. Fail-closed: a read-only one-liner holds too.
 */
const INTERPRETER_RE =
  /^(?:python[\d.]*|pypy[\d.]*|node|nodejs|deno|bun|perl[\d.]*|ruby|irb|php[\d.]*|lua[\d.]*|luajit|tclsh[\d.]*|wish|expect|r|rscript|julia|pwsh|powershell|swift|osascript|jxa|(?:ba|z|da|k|fi|c|tc|a)?sh|eval|source|\.|exec|[gmn]?awk|busybox|sed|gsed|ex|vim?|nvim|emacs|xargs|parallel|watch|script)$/;

/** Windows programs that run a command TEXT: cmd, WSL, the script hosts,
 * PowerShell's script-block and process-starting cmdlets. */
const WINDOWS_INTERPRETER_RE =
  /^(?:cmd|wsl|wscript|cscript|mshta|forfiles|runas|schtasks|wmic|start|start-process|saps|start-job|sajb|start-threadjob|invoke-expression|iex|invoke-command|icm|foreach-object|foreach|where-object|where|%|\?)$/;

/** Does some invocation in this command run an interpreter? A program word
 * the guard cannot read statically (a glob, a variable) counts — on Windows
 * also a command whose program word is not a plain name: `(Get-Item
 * …).Delete()`, `[IO.File]::WriteAllText(…)`. Not a bracket group's
 * (windowsHeads): there that is mostly data, `'{a: .x}'` read by cmd. */
function runsInterpreter(command: string, heads: readonly string[], win: boolean): boolean {
  const top = win ? new Set(invocationHeads(command)) : undefined;
  return heads.some((head) => {
    if (!win) {
      const word = shellUnescaped(head.trim().split(/\s+/, 1)[0] ?? "");
      const program = (word.split("/").pop() ?? word).toLowerCase();
      return INTERPRETER_RE.test(program) || /[?*[$`]/.test(word);
    }
    const word = shellWords(head)[0] ?? "";
    const program = programName(word, true);
    if (INTERPRETER_RE.test(program) || WINDOWS_INTERPRETER_RE.test(program) || /[?*[$`]/.test(word)) return true;
    return top!.has(head) && !/^[\w.+-]*$/.test(program);
  });
}

/** Every spelling of a home-relative path, expanded; `/private` folded and
 * separators collapsed the way canonical() does, so a literal guard path in
 * free text compares against the canonical directory. */
function canonicalText(text: string, home: string): string {
  // Unescaped the way this shell reads it AND with every backslash dropped:
  // a single-quoted `Application\ Support` is literal here but is unescaped
  // by the shell the interpreter hands it to (`osascript -e 'do shell script
  // "rm …\ …"'`).
  return `${shellUnescaped(text)}\n${text.replace(/\\(.)/g, "$1")}`
    .replace(/(^|[^\w$])~(?=\/|$|[\s'"),;])/g, `$1${home}`)
    .replace(/\$\{?HOME\}?(?=\/|$|[^\w])/g, home)
    .replace(/\/+/g, "/")
    .replace(/\/(?:\.\/)+/g, "/")
    .replace(/(^|[^\w.-])\/private(?=\/(?:var|tmp|etc)(?:\/|$))/g, "$1")
    .toLowerCase();
}

/**
 * A guard path anywhere in free text — an interpreter's program, a string fed
 * to a shell — or undefined. Absolute and home paths by substring; a relative
 * token by resolving it against `cwd`. A substring hit is named the way the
 * text spells it (the word that names the directory), else as the guard
 * directory itself: never in the drive-less, lowercased form it is compared in.
 */
function guardPathInText(text: string, cwd: string | undefined, dirs: readonly string[], rules: PathRules): string | undefined {
  const flatten = (part: string): string => (rules.win ? canonicalTextWindows(part, rules) : canonicalText(part, rules.home));
  const flat = flatten(text);
  const dir = dirs.find((candidate) => namesDir(flat, candidate));
  if (dir !== undefined) {
    const word = text.split(/[\s'"`(),;=|&<>{}\[\]]+/).find((token) => token !== "" && namesDir(flatten(token), dir));
    return word ?? rules.shown.get(dir) ?? dir;
  }
  // `cd $G_PARENT && python3 -c "open('guard/policy.json','w')"`, or a cwd
  // inside the directory: relative tokens, resolved.
  if (cwd !== undefined) {
    for (const token of shellUnescaped(text).split(/[\s'"`(),;:=|&<>{}\[\]]+/)) {
      if (token === "" || token.startsWith("-") || (rules.win ? win32.isAbsolute(token) : posix.isAbsolute(token)) || token.startsWith("~") || token.startsWith("$")) continue;
      if (rules.win && token.startsWith("%")) continue;
      if (insideDir(token, cwd, dirs, rules)) return token;
    }
    if (within(rules.win ? canonicalWindows(cwd) : canonical(cwd), dirs, rules.win)) return cwd;
  }
  return undefined;
}

/** Does this canonical text name the directory: the directory's path followed
 * by the end of a word or a separator, not a longer name (`guard-backup`)? */
function namesDir(flat: string, dir: string): boolean {
  for (let at = flat.indexOf(dir); at !== -1; at = flat.indexOf(dir, at + 1)) {
    const next = flat[at + dir.length];
    if (next === undefined || !/[\w.-]/.test(next)) return true;
  }
  return false;
}

/** canonicalText with Windows rules: variables expanded, either separator
 * (and a literal backslash, as PowerShell and cmd read it), trailing dots
 * dropped the way Win32 drops them. */
function canonicalTextWindows(text: string, rules: PathRules): string {
  return expandWindowsVars(`${shellUnescaped(text)}\n${text.replace(/\\(.)/g, "$1")}\n${text}`, rules.vars)
    .replace(/(^|[^\w$])~(?=[\\/]|$|[\s'"),;])/gm, `$1${rules.home}`)
    .replace(/[\\/]+/g, "/")
    .replace(/\/(?:\.\/)+/g, "/")
    .replace(/(?<=[^/.\s])\.+(?=[/\s'"`),;]|$)/gm, "")
    .toUpperCase()
    .toLowerCase();
}

/**
 * Does this text name the tail of a guard directory below a known root
 * (`doorman/doorman/guard` below `%APPDATA%`) as whole components? PowerShell
 * builds paths at runtime (`Join-Path $env:APPDATA 'Doorman\doorman\guard'`,
 * `$env:APPDATA + '\Doorman\…'`), which no single word spells out.
 */
function namesRootedTail(text: string, rules: PathRules): boolean {
  if (rules.tails.length === 0) return false;
  const flat = canonicalTextWindows(text, rules);
  return rules.tails.some((tail) => {
    for (let at = flat.indexOf(tail); at !== -1; at = flat.indexOf(tail, at + 1)) {
      const before = flat[at - 1];
      const after = flat[at + tail.length];
      if ((before === undefined || !/[\w.-]/.test(before)) && (after === undefined || !/[\w.-]/.test(after))) return true;
    }
    return false;
  });
}

/** `env -C DIR …`, `sudo -D DIR …` and their long spellings: the program runs
 * IN that directory, which invocationHeads strips along with the wrapper. */
function chdirWrapperTargets(command: string, win: boolean): string[] {
  const out: string[] = [];
  for (const segment of commandSegments(command)) {
    const words = shellWords(segment);
    for (let i = 0; i < words.length; i += 1) {
      const program = programName(words[i]!, win);
      const short = program === "env" ? "C" : program === "sudo" ? "D" : undefined;
      if (short === undefined) continue;
      for (let j = i + 1; j < words.length; j += 1) {
        const w = words[j]!;
        if (!w.startsWith("-")) {
          if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(w)) continue;
          // sudo's other value flags (`-u root`) take the next word.
          if (program === "sudo" && /^-[ugphrtTUC]$/.test(words[j - 1] ?? "")) continue;
          break;
        }
        const long = /^--(?:chdir|directory)(?:=(.*))?$/.exec(w);
        if (long) {
          const to = long[1] ?? words[++j];
          if (to !== undefined) out.push(to);
          continue;
        }
        const at = w.indexOf(short);
        if (/^-[A-Za-z0-9]+/.test(w) && at > 0) {
          const to = at === w.length - 1 ? words[++j] : w.slice(at + 1);
          if (to !== undefined) out.push(to);
        }
      }
    }
  }
  return out;
}

/** `cp -t DIR`, `-tDIR`, `--target-directory[=]DIR`: the destination named by
 * a flag rather than by the last operand. */
function copyTargetDirectory(words: readonly string[]): string | undefined {
  for (let i = 1; i < words.length; i += 1) {
    const w = words[i]!;
    const long = /^--target-directory(?:=(.*))?$/.exec(w);
    if (long) return long[1] ?? words[i + 1];
    if (/^-[A-Za-z]*t/.test(w) && !w.startsWith("--")) {
      const at = w.indexOf("t");
      return at === w.length - 1 ? words[i + 1] : w.slice(at + 1);
    }
  }
  return undefined;
}

/** Programs whose path operands are read except the last, the destination. */
const COPY_PROGRAMS: ReadonlySet<string> = new Set(["cp", "rsync", "scp", "ditto"]);

function lastOperand(words: readonly string[]): number {
  for (let i = words.length - 1; i > 0; i -= 1) {
    const w = words[i]!;
    if (w === ">" || w === ">>" || (i > 0 && (words[i - 1] === ">" || words[i - 1] === ">>"))) continue;
    if (!w.startsWith("-")) return i;
  }
  return -1;
}

/** What one reading of a copy does with its words: the ones it only reads
 * (indices into the words), and whether it copies into the working directory
 * because it names no destination. */
interface CopyReading {
  sources: ReadonlySet<number>;
  intoCwd: boolean;
}

/**
 * A Windows copy's words as every program the name can be: `cp` is Git Bash's
 * cp or PowerShell's Copy-Item, `copy` is cmd's or Copy-Item. A word is a
 * source only when every reading reads it, so a copy OUT of the guard
 * directory passes while a destination there, by position or by
 * `-Destination`, is still checked. Undefined (check every word) for any other
 * program, or a copy no reading can be sure of.
 */
function windowsCopy(program: string, words: readonly string[], copyTarget: string | undefined): CopyReading | undefined {
  let readings: Array<CopyReading | undefined>;
  switch (program) {
    case "cp":
      readings = [cpReading(words, copyTarget), copyItemReading(words)];
      break;
    case "copy":
      readings = [cmdCopyReading(words), copyItemReading(words)];
      break;
    case "copy-item":
    case "cpi":
      readings = [copyItemReading(words)];
      break;
    case "xcopy":
      readings = [xcopyReading(words)];
      break;
    case "robocopy":
      readings = [robocopyReading(words)];
      break;
    default:
      return undefined;
  }
  if (readings.some((reading) => reading === undefined)) return undefined;
  const [first, ...rest] = readings as CopyReading[];
  return {
    sources: new Set([...first!.sources].filter((i) => rest.every((reading) => reading.sources.has(i)))),
    intoCwd: readings.some((reading) => reading!.intoCwd),
  };
}

/** Every word after the program except a redirect and its target. */
function argumentIndices(words: readonly string[]): number[] {
  const out: number[] = [];
  for (let i = 1; i < words.length; i += 1) {
    if (words[i] === ">" || words[i] === ">>") i += 1;
    else out.push(i);
  }
  return out;
}

/** A reading in which the program refuses the call and copies nothing. */
function copiesNothing(words: readonly string[]): CopyReading {
  return { sources: new Set(argumentIndices(words)), intoCwd: false };
}

/** GNU cp (Git Bash): every operand but the last, or all of them with `-t`. */
function cpReading(words: readonly string[], copyTarget: string | undefined): CopyReading {
  const operands = argumentIndices(words).filter((i) => !words[i]!.startsWith("-"));
  const sources = copyTarget === undefined ? operands.slice(0, -1) : operands.filter((i) => words[i] !== copyTarget);
  return { sources: new Set(sources), intoCwd: false };
}

/** Copy-Item's parameters (PowerShell 5.1 and 7, common ones included) by
 * lowercased name: whether each takes a value. */
const COPY_ITEM_PARAMETERS: Readonly<Record<string, boolean>> = {
  path: true, literalpath: true, destination: true, filter: true, include: true, exclude: true, credential: true,
  fromsession: true, tosession: true, erroraction: true, warningaction: true, informationaction: true,
  progressaction: true, errorvariable: true, warningvariable: true, informationvariable: true, outvariable: true,
  outbuffer: true, pipelinevariable: true, container: false, force: false, recurse: false, passthru: false,
  whatif: false, confirm: false, usetransaction: false, debug: false, verbose: false,
};

/** Copy-Item's parameter aliases. */
const COPY_ITEM_ALIASES: Readonly<Record<string, string>> = {
  lp: "literalpath", pspath: "literalpath", ea: "erroraction", wa: "warningaction", infa: "informationaction",
  proga: "progressaction", ev: "errorvariable", wv: "warningvariable", iv: "informationvariable",
  ov: "outvariable", ob: "outbuffer", pv: "pipelinevariable", wi: "whatif", cf: "confirm", usetx: "usetransaction",
  db: "debug", vb: "verbose",
};

/**
 * Copy-Item as PowerShell binds it: `-Name` / `-Name:value` by full name,
 * alias or unambiguous prefix; then `-Path` from the first positional word and
 * `-Destination` from the next. An ambiguous parameter, a missing value or a
 * word too many is an error that copies nothing. A parameter it does not have,
 * a splat, a subexpression or `--%` cannot be read here: undefined.
 */
function copyItemReading(words: readonly string[]): CopyReading | undefined {
  const args = argumentIndices(words);
  if (args.some((i) => /^@|[(){}]|^--%$/.test(words[i]!))) return undefined;
  const sources = new Set<number>();
  const positional: number[] = [];
  let pathBound = false;
  let destinationBound = false;
  for (let k = 0; k < args.length; k += 1) {
    const i = args[k]!;
    const flag = /^-([A-Za-z][\w-]*)(:.*)?$/.exec(words[i]!);
    if (!flag) {
      positional.push(i);
      continue;
    }
    const lower = flag[1]!.toLowerCase();
    const prefixed = Object.keys(COPY_ITEM_PARAMETERS).filter((name) => name.startsWith(lower));
    const name = Object.hasOwn(COPY_ITEM_ALIASES, lower)
      ? COPY_ITEM_ALIASES[lower]!
      : Object.hasOwn(COPY_ITEM_PARAMETERS, lower)
        ? lower
        : prefixed.length === 1
          ? prefixed[0]!
          : undefined;
    // Ambiguous (`-f`: -Force, -Filter, -FromSession) is PowerShell's error;
    // a name it does not have may be one this table lacks.
    if (name === undefined) return prefixed.length > 1 ? copiesNothing(words) : undefined;
    if (!COPY_ITEM_PARAMETERS[name]) continue;
    const value = flag[2] !== undefined ? i : args[++k];
    if (value === undefined) return copiesNothing(words);
    if (name === "destination") destinationBound = true;
    else {
      sources.add(value);
      if (name === "path" || name === "literalpath") pathBound = true;
    }
  }
  const slots = [...(pathBound ? [] : ["path"]), ...(destinationBound ? [] : ["destination"])];
  if (positional.length > slots.length) return copiesNothing(words);
  positional.forEach((i, n) => {
    if (slots[n] === "path") sources.add(i);
    else destinationBound = true;
  });
  return { sources, intoCwd: !destinationBound };
}

/** cmd's copy: switches are `/X` or `/-Y`; the last operand is the
 * destination, else the working directory. A `+` (`a+b`, `file +,,`, which
 * rewrites the file in place) is not read here: undefined. */
function cmdCopyReading(words: readonly string[]): CopyReading | undefined {
  const operands = argumentIndices(words).filter((i) => !/^\/-?[a-z]$/i.test(words[i]!));
  if (operands.some((i) => words[i]!.includes("+"))) return undefined;
  if (operands.length < 2) return { sources: new Set(operands), intoCwd: true };
  return { sources: new Set(operands.slice(0, -1)), intoCwd: false };
}

/** An xcopy or robocopy switch: `/Y`, `/-Y`, `/LOG:C:\x`, `/LOG+:x`. */
const SLASH_SWITCH_RE = /^\/-?[A-Za-z][A-Za-z0-9]*\+?(?::[\s\S]*)?$/;

/** xcopy SOURCE [DESTINATION] [switches]: the working directory without a
 * destination; a third operand is an error. */
function xcopyReading(words: readonly string[]): CopyReading {
  const operands = argumentIndices(words).filter((i) => !SLASH_SWITCH_RE.test(words[i]!));
  if (operands.length > 2) return copiesNothing(words);
  return { sources: new Set(operands.slice(0, 1)), intoCwd: operands.length < 2 };
}

/** robocopy SOURCE DESTINATION [FILE…] [switches]: everything but the second
 * word is read. Only when the first two words are those two operands. */
function robocopyReading(words: readonly string[]): CopyReading | undefined {
  const args = argumentIndices(words);
  if (args.length < 2 || args.slice(0, 2).some((i) => SLASH_SWITCH_RE.test(words[i]!))) return undefined;
  const destination = args[1]!;
  return { sources: new Set(args.filter((i) => i !== destination && !SLASH_SWITCH_RE.test(words[i]!))), intoCwd: false };
}

/** Split one invocation into words, honouring quotes; redirects come back as
 * their own `>`/`>>` tokens so a target glued to them (`>file`) is separable. */
function shellWords(text: string): string[] {
  const words: string[] = [];
  let current = "";
  let quote: string | undefined;
  let has = false;
  const flush = (): void => {
    if (has) words.push(current);
    current = "";
    has = false;
  };
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i]!;
    if (quote) {
      if (ch === quote) quote = undefined;
      else if (ch === "\\" && quote === '"' && i + 1 < text.length) current += text[++i];
      else current += ch;
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      has = true;
    } else if (ch === "\\" && i + 1 < text.length) {
      current += text[++i];
      has = true;
    } else if (/\s/.test(ch)) {
      flush();
    } else if (ch === ">" || ((ch === "&" || ch === "<") && text[i + 1] === ">")) {
      // Every output-redirection spelling becomes `>`/`>>`: `>`, `>>`, `>|`,
      // `&>`, `&>>`, `<>` (read-write), `N>`, `>&file`. An fd number glued in
      // front is not a word; `>&N` / `>&-` duplicate an fd and name no file.
      if (has && /^\d+$/.test(current)) {
        current = "";
        has = false;
      } else flush();
      if (ch !== ">") i += 1;
      const append = text[i + 1] === ">";
      if (append) i += 1;
      if (text[i + 1] === "|") i += 1;
      else if (text[i + 1] === "&") {
        const dup = /^(?:\d+|-)(?=$|[\s;|&)])/.exec(text.slice(i + 2));
        if (dup) {
          i += 1 + dup[0].length;
          continue;
        }
        i += 1;
      }
      words.push(append ? ">>" : ">");
    } else {
      current += ch;
      has = true;
    }
  }
  flush();
  return words;
}

function expandHome(path: string, home: string): string {
  if (path === "~" || path.startsWith("~/")) return posix.join(home, path.slice(1));
  return path.replace(/^\$\{?HOME\}?(?=\/|$)/, home);
}

/** Does `path` (relative to `cwd`) resolve inside `dir`? Case-folded: APFS and
 * NTFS are case-insensitive, so `…/Guard/policy.json` is the same file. */
function insideDir(path: string, cwd: string | undefined, dirs: readonly string[], rules: PathRules): boolean {
  let cleaned = path.replace(/^[a-z]+=/i, "").replace(/^--?[a-z-]+=/i, "");
  // PowerShell binds a parameter with a colon (`-Path:C:\…`), robocopy and
  // its kin take `/LOG:C:\…`.
  if (rules.win) cleaned = cleaned.replace(/^[-/][a-z][\w-]*\+?:(?=.)/i, "");
  // A short flag with its value glued on (`-o/…/policy.json`, `-C~/…`): the
  // value is the path. Only an absolute or home value is read this way — a
  // relative one is indistinguishable from a cluster of flags (`-rf`).
  if (cleaned.startsWith("-")) {
    const glued = (rules.win ? /^-[A-Za-z0-9]+?([/~\\%$].*|[A-Za-z]:[\\/].*)$/ : /^-[A-Za-z0-9]+?([/~].*|\$\{?HOME\b.*)$/).exec(cleaned);
    if (!glued) return false;
    cleaned = glued[1]!;
  }
  if (cleaned === "") return false;
  let full: string;
  if (rules.win) {
    const resolved = resolveWindows(cwd, expandWindowsPath(cleaned, rules));
    if (resolved === undefined) return false;
    full = canonicalWindows(resolved);
  } else {
    const expanded = expandHome(cleaned, rules.home);
    if (!posix.isAbsolute(expanded) && cwd === undefined) return false;
    full = canonical(posix.isAbsolute(expanded) ? expanded : posix.resolve(cwd!, expanded));
  }
  if (within(full, dirs, rules.win)) return true;
  // An unexpanded glob or brace (`…/gu?rd/policy.json`, `…/{guard,x}/…`) is
  // judged by what it COULD expand to — fail-closed, quoted or not.
  if (!/[?*[{]/.test(full)) return false;
  return braceExpansions(full).some((candidate) =>
    rules.win ? componentSuffixes(candidate).some((suffix) => globCouldEnter(suffix, dirs)) : globCouldEnter(candidate, dirs),
  );
}

/** Is this canonical path one of the directories or inside one? On Windows
 * the directories are drive-less (windowsDirKey) and match wherever they
 * start a component run: `/c:/…`, `/c/…` (Git Bash), `/mnt/c/…` (WSL),
 * `//?/c:/…`, `//localhost/c$/…` and a root-relative `/users/…` alike. */
function within(full: string, dirs: readonly string[], win: boolean): boolean {
  if (!win) return dirs.some((dir) => full === dir || full.startsWith(`${dir}/`));
  const padded = `${full}/`;
  return dirs.some((dir) => padded.includes(`${dir}/`));
}

/** `/a/b/c` → `/a/b/c`, `/b/c`, `/c`: a glob tested from every component. */
function componentSuffixes(path: string): string[] {
  const out: string[] = [];
  for (let i = path.indexOf("/"); i !== -1; i = path.indexOf("/", i + 1)) out.push(path.slice(i));
  return out;
}

/** Brace alternatives of a word (`a/{b,c}/d` → `a/b/d`, `a/c/d`), bounded. A
 * sequence (`{1..9}`) becomes `*`, which can only widen the match. */
function braceExpansions(word: string, limit = 64): string[] {
  const out: string[] = [];
  const queue = [word];
  while (queue.length > 0 && out.length + queue.length <= limit) {
    const current = queue.shift()!;
    const open = current.indexOf("{");
    let close = -1;
    let depth = 0;
    for (let i = open; open !== -1 && i < current.length; i += 1) {
      if (current[i] === "{") depth += 1;
      else if (current[i] === "}" && (depth -= 1) === 0) {
        close = i;
        break;
      }
    }
    if (open === -1 || close === -1) {
      out.push(current);
      continue;
    }
    const body = current.slice(open + 1, close);
    const before = current.slice(0, open);
    const after = current.slice(close + 1);
    const parts: string[] = [];
    let part = "";
    depth = 0;
    for (const ch of body) {
      if (ch === "{") depth += 1;
      else if (ch === "}") depth -= 1;
      if (ch === "," && depth === 0) {
        parts.push(part);
        part = "";
      } else part += ch;
    }
    parts.push(part);
    if (parts.length > 1) for (const p of parts) queue.push(`${before}${p}${after}`);
    else if (body.includes("..")) queue.push(`${before}*${after}`);
    else out.push(`${before}${body}${after}`.replace(/[{}]/g, ""));
  }
  // Past the bound, every remaining brace is a wildcard.
  for (const rest of queue) out.push(rest.replace(/\{[^}]*\}?/g, "*"));
  return out;
}

/** Could this (canonical, possibly globbed) path name something inside one of
 * the directories? Component by component; a `**` matches any depth. */
function globCouldEnter(path: string, dirs: readonly string[]): boolean {
  const parts = path.split("/");
  return dirs.some((dir) => {
    const want = dir.split("/");
    for (let i = 0; i < want.length; i += 1) {
      const part = parts[i];
      if (part === undefined) return false;
      if (part.includes("**")) return true;
      if (part === want[i]) continue;
      const re = /[?*[]/.test(part) ? globToRegExp(part) : undefined;
      if (re === undefined || !re.test(want[i]!)) return false;
    }
    return true;
  });
}

/** Lowercased, normalized, and with macOS's `/private` symlink targets folded
 * back (`/private/var/…` IS `/var/…`): the guard's own path arrives as a
 * realpath while an agent's cwd usually does not. */
function canonical(path: string): string {
  return posix
    .normalize(path)
    .replace(/\/+$/, "")
    .replace(/^\/private(?=\/(?:var|tmp|etc)(?:\/|$))/, "")
    .toLowerCase();
}

/** How paths read where the guard runs. POSIX rules unless Windows. */
interface PathRules {
  win: boolean;
  home: string;
  /** Windows: environment variables by lowercased name, profile defaults
   * filled in — for `%APPDATA%`, `$env:APPDATA`, `${env:APPDATA}`, `$APPDATA`. */
  vars: ReadonlyMap<string, string>;
  /** Windows: each guard directory below a known root (namesRootedTail). */
  tails: readonly string[];
  /** Each guard directory's canonical key → the directory as it was given,
   * for naming it to a person. */
  shown: ReadonlyMap<string, string>;
}

/** Where guardSelfWrite runs — injectable so Windows rules are testable on
 * any OS. A Windows-style guard directory (`C:\…`, `\\…`) selects Windows
 * rules when no platform is given. */
export interface SelfWriteHost {
  platform?: NodeJS.Platform;
  env?: Readonly<Record<string, string | undefined>>;
}

/** A Windows path, canonical: `/`-separated, lowercased, rooted at `/`, with
 * what Win32 ignores dropped — a component's alternate data stream
 * (`guard::$INDEX_ALLOCATION`, `policy.json:x`) and its trailing dots and
 * spaces (`guard.`). A drive stays as the first component (`/c:/…`). */
function canonicalWindows(path: string): string {
  const parts = win32
    .normalize(path)
    .replace(/\\/g, "/")
    .split("/")
    .map((part, i) => {
      if (part === "" || part === "." || part === "..") return part;
      const bare = i === 0 && /^[a-z]:$/i.test(part) ? part : part.replace(/:.*$/, "");
      const trimmed = bare.replace(/[. ]+$/, "");
      return trimmed === "" ? bare : trimmed;
    });
  // NTFS compares names upcased (its $UpCase table), so fold through upper
  // case: `ı` and `ſ` upcase to `I` and `S`, which lowercasing leaves apart.
  const out = parts.join("/").replace(/\/+$/, "").toUpperCase().toLowerCase();
  return out.startsWith("/") ? out : `/${out}`;
}

/** A guard directory as within() matches it on Windows: canonical, without
 * its drive or `\\?\` prefix. */
function windowsDirKey(dir: string): string {
  const key = canonicalWindows(dir)
    .replace(/^\/\/[?.]\/(?:unc\/)?/, "/")
    .replace(/^\/[a-z]:(?=\/|$)/, "");
  return key === "" ? "/" : key;
}

/** `path` against `cwd` with Windows rules; a drive-relative `D:x` on another
 * drive than the cwd's is read from that drive's root. */
function resolveWindows(cwd: string | undefined, path: string): string | undefined {
  if (win32.isAbsolute(path)) return path;
  const drive = /^([a-z]):(?![\\/])([\s\S]*)$/i.exec(path);
  if (drive) {
    const sameDrive = cwd !== undefined && cwd.slice(0, 2).toLowerCase() === `${drive[1]!.toLowerCase()}:`;
    return sameDrive ? win32.join(cwd!, drive[2]!) : `${drive[1]}:\\${drive[2]}`;
  }
  return cwd === undefined ? undefined : win32.join(cwd, path);
}

function windowsVars(env: Readonly<Record<string, string | undefined>>, home: string): Map<string, string> {
  const vars = new Map<string, string>();
  for (const [name, value] of Object.entries(env)) if (typeof value === "string" && value !== "") vars.set(name.toLowerCase(), value);
  const profile = vars.get("userprofile") ?? home;
  if (!vars.has("userprofile")) vars.set("userprofile", home);
  if (!vars.has("appdata")) vars.set("appdata", win32.join(profile, "AppData", "Roaming"));
  if (!vars.has("localappdata")) vars.set("localappdata", win32.join(profile, "AppData", "Local"));
  // PowerShell's `$HOME` and `~` are the profile whatever HOME says.
  vars.set("home", home);
  return vars;
}

/** cmd's `%NAME%` (and its `%NAME:~0,9%` / `%NAME:a=b%` edits, read as the
 * whole value), delayed `!NAME!`, PowerShell's `$env:NAME`, `${env:NAME}` and
 * `$($env:NAME)`, and bash's `$NAME` / `${NAME}`, case-insensitively. An
 * unknown variable stays as written. */
function expandWindowsVars(text: string, vars: ReadonlyMap<string, string>): string {
  const value = (match: string, name: string | undefined, other?: string): string => vars.get((name ?? other ?? "").toLowerCase()) ?? match;
  return text
    .replace(/\$\(\s*(\$(?:\{env:[^}]+\}|env:\w+|\w+))\s*\)/gi, "$1")
    .replace(/%([A-Za-z_][\w()]*)(?::[^%]*)?%/g, value)
    .replace(/!([A-Za-z_][\w()]*)!/g, value)
    .replace(/\$\{env:([^}]+)\}/gi, value)
    .replace(/\$env:([A-Za-z_]\w*)/gi, value)
    .replace(/\$\{([A-Za-z_]\w*)\}|\$([A-Za-z_]\w*)/g, value);
}

function expandWindowsPath(path: string, rules: PathRules): string {
  const expanded = expandWindowsVars(path, rules.vars);
  return /^~(?=$|[\\/])/.test(expanded) ? `${rules.home}${expanded.slice(1)}` : expanded;
}

/** Each guard directory's tail below every variable that names one of its
 * ancestors, when that tail is at least two components long. */
function rootedTails(dirs: readonly string[], vars: ReadonlyMap<string, string>): string[] {
  const tails = new Set<string>();
  for (const value of vars.values()) {
    if (!/^(?:[a-z]:)?[\\/]/i.test(value)) continue;
    const root = windowsDirKey(value);
    if (root.length <= 1) continue;
    for (const dir of dirs) {
      const tail = dir.startsWith(`${root}/`) ? dir.slice(root.length + 1) : "";
      if (tail.includes("/")) tails.add(tail);
    }
  }
  return [...tails];
}

/** The command as each Windows shell reads it: PowerShell (backslash literal,
 * backtick escapes and continuations), bash (as written) and cmd (caret
 * escapes, `'` not a quote, braces nothing special — dropped so text a quote
 * no longer hides is not read as a PowerShell script block). Backslashes
 * become `/`, which every Windows path API takes, so neither literal reading
 * has an escape character left. */
function windowsReadings(command: string): string[] {
  const literal = command.replace(/[`^]\r?\n/g, " ").replace(/[`^]/g, "").replace(/\\/g, "/");
  return [...new Set([literal, command, literal.replace(/['{}]/g, "")])];
}

/** invocationHeads plus what PowerShell runs inside a head: a `( … )`
 * subexpression, a `{ … }` script block, a `$( … )` in a double-quoted
 * string — `Get-Content (Remove-Item $G\policy.json)` hides a writer behind
 * a reader otherwise. */
function windowsHeads(command: string): string[] {
  const out: string[] = [];
  const visit = (text: string, depth: number): void => {
    for (const head of invocationHeads(text)) {
      out.push(head);
      if (depth < 3) for (const group of bracketGroups(head)) visit(group, depth + 1);
    }
  };
  visit(command, 0);
  return out;
}

/** Top-level `( … )` / `{ … }` bodies outside single quotes, and `$( … )`
 * inside double ones; an unclosed one runs to the end. */
function bracketGroups(text: string): string[] {
  const out: string[] = [];
  let quote: string | undefined;
  let depth = 0;
  let start = 0;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i]!;
    if (depth > 0) {
      if (ch === "(" || ch === "{") depth += 1;
      else if ((ch === ")" || ch === "}") && (depth -= 1) === 0) out.push(text.slice(start, i));
    } else if (quote === "'") {
      if (ch === "'") quote = undefined;
    } else if (quote === '"') {
      if (ch === '"') quote = undefined;
      else if (ch === "$" && text[i + 1] === "(") {
        depth = 1;
        start = i + 2;
        i += 1;
      }
    } else if (ch === "'" || ch === '"') quote = ch;
    else if (ch === "(" || ch === "{") {
      depth = 1;
      start = i + 1;
    }
  }
  if (depth > 0) out.push(text.slice(start));
  return out;
}

/** The directory a Windows `cd`/`chdir`/`Set-Location`/`Push-Location` goes
 * to: `-Path:DIR` bound, cmd's `/d` skipped, and the operands joined — cmd
 * reads an unquoted `cd C:\Users\A B\…` whole. */
function windowsCdTarget(words: readonly string[]): string | undefined {
  const operands: string[] = [];
  for (let i = 1; i < words.length; i += 1) {
    const w = words[i]!;
    if (w === ">" || w === ">>") break;
    const bound = /^-(?:path|literalpath|lp|pspath):(.+)$/i.exec(w);
    if (bound) return bound[1];
    if (w === "-" && operands.length === 0) return w;
    if (w.startsWith("-")) continue;
    if (/^\/[a-z]$/i.test(w) && i < words.length - 1) continue;
    operands.push(w);
  }
  return operands.length === 0 ? undefined : operands.join(" ");
}

/** `powershell -EncodedCommand <base64>` (and `-enc`, `-ec`, `-e`): the
 * UTF-16LE script it runs, appended so its text is searched like `-Command`'s. */
function encodedCommands(words: readonly string[], program: string): string {
  if (program !== "powershell" && program !== "pwsh") return "";
  let out = "";
  for (let i = 1; i < words.length - 1; i += 1) {
    if (/^[-/](?:e|ec|en\w*)$/i.test(words[i]!)) out += `\n${Buffer.from(words[i + 1]!, "base64").toString("utf16le")}`;
  }
  return out;
}

/**
 * Would this tool call change the guard's own directory? Returns what it
 * touches, or undefined. `guardDirs` is the directory as the guard sees it
 * plus its realpath when they differ.
 */
export function guardSelfWrite(
  toolName: string | undefined,
  toolInput: unknown,
  cwd: string | undefined,
  guardDirs: readonly string[],
  home: string = homedir(),
  host: SelfWriteHost = {},
): string | undefined {
  const win =
    host.platform === undefined
      ? process.platform === "win32" || guardDirs.some((dir) => /^[A-Za-z]:[\\/]|^\\\\/.test(dir))
      : host.platform === "win32";
  const vars = win ? windowsVars(host.env ?? process.env, home) : new Map<string, string>();
  const shown = new Map<string, string>();
  const base: PathRules = { win, home, vars, tails: [], shown };
  for (const dir of guardDirs) {
    const key = win ? windowsDirKey(expandWindowsPath(dir, base)) : canonical(dir);
    if (!shown.has(key)) shown.set(key, dir);
  }
  const dirs = [...shown.keys()];
  if (dirs.length === 0) return undefined;
  const rules: PathRules = win ? { ...base, tails: rootedTails(dirs, vars) } : base;
  const command = commandOfInput(toolName, toolInput);
  if (command === undefined) {
    if (!isWriteTool(toolName)) return undefined;
    return writePaths(toolInput).find((path) => insideDir(path, cwd, dirs, rules));
  }
  if (!win) return selfWriteIn(command, cwd, dirs, rules);
  for (const reading of windowsReadings(command)) {
    const hit = selfWriteIn(reading, cwd, dirs, rules);
    if (hit !== undefined) return shownWindowsPath(hit, rules);
  }
  return undefined;
}

/** What a Windows command touches, as the person would write it: variables
 * expanded (`%APPDATA%` → `C:\Users\…\AppData\Roaming`), and a drive or UNC
 * path with `\` separators, whichever reading of the command found it. */
function shownWindowsPath(hit: string, rules: PathRules): string {
  const expanded = expandWindowsPath(hit, rules);
  return /^(?:[A-Za-z]:[\\/]|[\\/]{2}[^\\/])/.test(expanded) ? win32.normalize(expanded) : expanded;
}

/** guardSelfWrite for one reading of a shell command. */
function selfWriteIn(command: string, cwd: string | undefined, dirs: readonly string[], rules: PathRules): string | undefined {
  const { win } = rules;
  const heads = win ? windowsHeads(command) : invocationHeads(command);
  const fed = feedsAWriter(command, win);
  // A command that runs an interpreter: any guard path in the whole text.
  // `cd` targets are resolved first so a relative path after `cd` counts.
  const interpreted = runsInterpreter(command, heads, win);
  for (const to of chdirWrapperTargets(command, win)) if (insideDir(to, cwd, dirs, rules)) return to;
  let here = cwd;
  for (const head of heads) {
    const words = shellWords(head);
    const program = programName(words[0] ?? "", win);
    if (program === "cd" || program === "pushd" || (win && /^(?:chdir|set-location|sl|push-location)$/.test(program))) {
      // `cd -P DIR`, `cd -L -- DIR`: the first operand after the flags.
      const to = win ? windowsCdTarget(words) : words.slice(1).find((w) => w === "-" || !w.startsWith("-"));
      if (to !== undefined && to !== "-") {
        if (win) here = resolveWindows(here, expandWindowsPath(to, rules));
        else {
          const expanded = expandHome(to, rules.home);
          here = posix.isAbsolute(expanded) ? expanded : here === undefined ? undefined : posix.resolve(here, expanded);
        }
      }
      continue;
    }
    if (interpreted) {
      const hit = guardPathInText(win ? `${head}${encodedCommands(words, program)}` : head, here, dirs, rules);
      if (hit !== undefined) return hit;
    }
    const copyTarget = program === "cp" ? copyTargetDirectory(words) : undefined;
    if (copyTarget !== undefined && insideDir(copyTarget, here, dirs, rules)) return copyTarget;
    const copy = win && !fed ? windowsCopy(program, words, copyTarget) : undefined;
    if (copy?.intoCwd && insideDir(".", here, dirs, rules)) return here;
    const readOnly =
      !fed &&
      (READ_ONLY_PROGRAMS.has(program) || (win && Object.hasOwn(WINDOWS_READ_ONLY_PROGRAMS, program))) &&
      !writesDespiteReadOnly(program, words);
    for (let i = 1; i < words.length; i += 1) {
      const word = words[i]!;
      if (word === ">" || word === ">>") {
        const to = words[i + 1];
        if (to !== undefined && (insideDir(to, here, dirs, rules) || (win && namesRootedTail(to, rules)))) return to;
        i += 1;
        continue;
      }
      if (readOnly) continue;
      // A copy reads its sources: only the destination (the last operand) is
      // changed. `mv` is not in this list — moving a file OUT removes it.
      // With `-t DIR` every operand is a source. On Windows, a word only every
      // reading of the copy takes as a source (windowsCopy).
      if (!win && COPY_PROGRAMS.has(program) && (copyTarget !== undefined || i !== lastOperand(words))) continue;
      if (copy?.sources.has(i)) continue;
      if (insideDir(word, here, dirs, rules)) return word;
      // Fed to a shell, one quoted word can be a whole command line: any
      // absolute or home path starting inside it counts.
      if (fed) {
        const unquoted = word.replace(/["']/g, "");
        for (const match of unquoted.matchAll(win ? /(?<=^|[\s=])(?:[/~\\%$]|[a-z]:)/gi : /(?<=^|[\s=])[/~]/g)) {
          const rest = unquoted.slice(match.index);
          if (insideDir(rest, here, dirs, rules)) return rest;
        }
      }
    }
    // A path assembled at runtime from a variable and the rest of the guard
    // directory: the head itself is what touches it — for a copy, a word it
    // does not only read.
    if (win && !readOnly && namesRootedTail(copy === undefined ? head : words.filter((_, i) => i > 0 && !copy.sources.has(i)).join(" "), rules)) return head;
  }
  return undefined;
}

/** Keys a write tool names a file it changes under — host-normalized
 * (`file_path`, `file_paths`) and the MCP filesystem vocabulary (`source` and
 * `destination` of a move: moving a file OUT removes it). */
const WRITE_PATH_KEYS = [
  "file_path", "path", "notebook_path", "filePath", "file", "filename", "target_file",
  "source", "destination", "src", "dest", "dst", "new_path", "old_path", "from", "to",
] as const;
const WRITE_PATH_LIST_KEYS = ["file_paths", "paths", "files", "edits"] as const;

/** Every path a non-shell write names — not just the first, which is all
 * toolTarget returns: a multi-file patch or a move changes each of them. */
function writePaths(input: unknown): string[] {
  if (!input || typeof input !== "object") return [];
  const record = input as Record<string, unknown>;
  const out: string[] = [];
  const add = (value: unknown): void => {
    if (typeof value === "string" && value !== "") out.push(value);
  };
  for (const key of WRITE_PATH_KEYS) add(record[key]);
  for (const key of WRITE_PATH_LIST_KEYS) {
    const list = record[key];
    if (!Array.isArray(list)) continue;
    for (const item of list) {
      if (item && typeof item === "object") {
        const entry = item as Record<string, unknown>;
        add(entry.file_path);
        add(entry.path);
      } else if (key !== "edits") add(item);
    }
  }
  return out;
}


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
import { isAbsolute, join, normalize, resolve } from "node:path";
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

/** Programs that only READ their path arguments. Anything else naming a path
 * inside the guard directory is treated as changing it. */
const READ_ONLY_PROGRAMS: ReadonlySet<string> = new Set([
  "cat", "less", "more", "head", "tail", "grep", "egrep", "fgrep", "rg", "ag", "ls", "stat", "wc", "file",
  "jq", "diff", "cmp", "md5", "md5sum", "shasum", "sha256sum", "du", "find", "tree", "realpath", "readlink",
  "basename", "dirname", "echo", "printf", "test", "[", "open", "code", "bat", "xxd", "hexdump", "od", "strings",
]);

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
function feedsAWriter(command: string): boolean {
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
    const program = (words[0] ?? "").split("/").pop()?.toLowerCase() ?? "";
    if (program === "" || program === "xargs" || program === "parallel") continue;
    if (READ_ONLY_PROGRAMS.has(program) && !writesDespiteReadOnly(program, words)) continue;
    return true;
  }
  return false;
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

/** Does some invocation in this command run an interpreter? A program word
 * the guard cannot read statically (a glob, a variable) counts. */
function runsInterpreter(command: string): boolean {
  return invocationHeads(command).some((head) => {
    const word = shellUnescaped(head.trim().split(/\s+/, 1)[0] ?? "");
    const program = (word.split("/").pop() ?? word).toLowerCase();
    return INTERPRETER_RE.test(program) || /[?*[$`]/.test(word);
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
 * token by resolving it against `cwd`.
 */
function guardPathInText(text: string, cwd: string | undefined, dirs: readonly string[], home: string): string | undefined {
  const flat = canonicalText(text, home);
  for (const dir of dirs) {
    let at = flat.indexOf(dir);
    while (at !== -1) {
      const next = flat[at + dir.length];
      if (next === undefined || !/[\w.-]/.test(next)) return dir;
      at = flat.indexOf(dir, at + 1);
    }
  }
  // `cd $G_PARENT && python3 -c "open('guard/policy.json','w')"`, or a cwd
  // inside the directory: relative tokens, resolved.
  if (cwd !== undefined) {
    for (const token of shellUnescaped(text).split(/[\s'"`(),;:=|&<>{}\[\]]+/)) {
      if (token === "" || token.startsWith("-") || isAbsolute(token) || token.startsWith("~") || token.startsWith("$")) continue;
      if (insideDir(token, cwd, dirs, home)) return token;
    }
    if (dirs.some((dir) => canonical(cwd) === dir || canonical(cwd).startsWith(`${dir}/`))) return cwd;
  }
  return undefined;
}

/** `env -C DIR …`, `sudo -D DIR …` and their long spellings: the program runs
 * IN that directory, which invocationHeads strips along with the wrapper. */
function chdirWrapperTargets(command: string): string[] {
  const out: string[] = [];
  for (const segment of commandSegments(command)) {
    const words = shellWords(segment);
    for (let i = 0; i < words.length; i += 1) {
      const program = (words[i]!.split("/").pop() ?? "").toLowerCase();
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
  if (path === "~" || path.startsWith("~/")) return join(home, path.slice(1));
  return path.replace(/^\$\{?HOME\}?(?=\/|$)/, home);
}

/** Does `path` (relative to `cwd`) resolve inside `dir`? Case-folded: APFS is
 * case-insensitive, so `…/Guard/policy.json` is the same file. */
function insideDir(path: string, cwd: string | undefined, dirs: readonly string[], home: string): boolean {
  let cleaned = path.replace(/^[a-z]+=/i, "").replace(/^--?[a-z-]+=/i, "");
  // A short flag with its value glued on (`-o/…/policy.json`, `-C~/…`): the
  // value is the path. Only an absolute or home value is read this way — a
  // relative one is indistinguishable from a cluster of flags (`-rf`).
  if (cleaned.startsWith("-")) {
    const glued = /^-[A-Za-z0-9]+?([/~].*|\$\{?HOME\b.*)$/.exec(cleaned);
    if (!glued) return false;
    cleaned = glued[1]!;
  }
  if (cleaned === "") return false;
  const expanded = expandHome(cleaned, home);
  if (!isAbsolute(expanded) && cwd === undefined) return false;
  const full = canonical(isAbsolute(expanded) ? expanded : resolve(cwd!, expanded));
  if (dirs.some((dir) => full === dir || full.startsWith(`${dir}/`))) return true;
  // An unexpanded glob or brace (`…/gu?rd/policy.json`, `…/{guard,x}/…`) is
  // judged by what it COULD expand to — fail-closed, quoted or not.
  return /[?*[{]/.test(full) && braceExpansions(full).some((candidate) => globCouldEnter(candidate, dirs));
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
  return normalize(path)
    .replace(/\/+$/, "")
    .replace(/^\/private(?=\/(?:var|tmp|etc)(?:\/|$))/, "")
    .toLowerCase();
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
): string | undefined {
  const dirs = [...new Set(guardDirs.map(canonical))];
  if (dirs.length === 0) return undefined;
  const command = commandOfInput(toolName, toolInput);
  if (command === undefined) {
    if (!isWriteTool(toolName)) return undefined;
    return writePaths(toolInput).find((path) => insideDir(path, cwd, dirs, home));
  }
  const fed = feedsAWriter(command);
  // A command that runs an interpreter: any guard path in the whole text.
  // `cd` targets are resolved first so a relative path after `cd` counts.
  const interpreted = runsInterpreter(command);
  for (const to of chdirWrapperTargets(command)) if (insideDir(to, cwd, dirs, home)) return to;
  let here = cwd;
  for (const head of invocationHeads(command)) {
    const words = shellWords(head);
    const program = (words[0] ?? "").split("/").pop()?.toLowerCase() ?? "";
    if (program === "cd" || program === "pushd") {
      // `cd -P DIR`, `cd -L -- DIR`: the first operand after the flags.
      const to = words.slice(1).find((w) => w === "-" || !w.startsWith("-"));
      if (to !== undefined && to !== "-") {
        const expanded = expandHome(to, home);
        here = isAbsolute(expanded) ? expanded : here === undefined ? undefined : resolve(here, expanded);
      }
      continue;
    }
    if (interpreted) {
      const hit = guardPathInText(head, here, dirs, home);
      if (hit !== undefined) return hit;
    }
    const copyTarget = program === "cp" ? copyTargetDirectory(words) : undefined;
    if (copyTarget !== undefined && insideDir(copyTarget, here, dirs, home)) return copyTarget;
    const readOnly = !fed && READ_ONLY_PROGRAMS.has(program) && !writesDespiteReadOnly(program, words);
    for (let i = 1; i < words.length; i += 1) {
      const word = words[i]!;
      if (word === ">" || word === ">>") {
        const to = words[i + 1];
        if (to !== undefined && insideDir(to, here, dirs, home)) return to;
        i += 1;
        continue;
      }
      if (readOnly) continue;
      // A copy reads its sources: only the destination (the last operand) is
      // changed. `mv` is not in this list — moving a file OUT removes it.
      // With `-t DIR` every operand is a source.
      if (COPY_PROGRAMS.has(program) && (copyTarget !== undefined || i !== lastOperand(words))) continue;
      if (insideDir(word, here, dirs, home)) return word;
      // Fed to a shell, one quoted word can be a whole command line: any
      // absolute or home path starting inside it counts.
      if (fed) {
        const unquoted = word.replace(/["']/g, "");
        for (const match of unquoted.matchAll(/(?<=^|[\s=])[/~]/g)) {
          const rest = unquoted.slice(match.index);
          if (insideDir(rest, here, dirs, home)) return rest;
        }
      }
    }
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


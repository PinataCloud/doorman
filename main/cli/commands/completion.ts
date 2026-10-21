import { exposureGroups, exposurePlace, radarFeedRows, radarRows } from "../../lib/app-views.js";
import { hiddenConfidenceBands } from "../../state.js";
import type { CliCommand } from "../command.js";
import { GLOBAL_FLAGS, HELP_GROUPS } from "../help.js";
import { CliError } from "../output.js";
import { cardTitle, oneLine, plain, ruleLabels, withEngine } from "./data-shared.js";

/**
 * `doorman completion <shell>`: a Tab-completion script built from the
 * command registry, so it names exactly the commands, subcommands and flags
 * this version has. Exposure ids are the one thing it asks for as you type:
 * it runs `doorman completion --ids` (hidden: not in `--help`), quietly.
 *
 * All three scripts share one model: a node per command path (`doorman
 * findings show`) with its subcommands, flags and what its arguments take.
 * Values are a word list, or `@ids`, `@files`, `@dirs`, or `@any` (takes a
 * value, nothing to suggest).
 */

export const SHELLS = ["zsh", "bash", "fish"] as const;
export type Shell = (typeof SHELLS)[number];

interface Flag {
  name: string;
  what: string;
  /** What the word after it takes; absent for a switch. */
  values?: string;
}

export interface CompletionNode {
  /** `doorman`, `doorman findings`, `doorman mcp server`. */
  at: string;
  subs: (readonly [word: string, what: string])[];
  flags: Flag[];
  /** The first `max` arguments complete to `values`. */
  args?: { max: number; values: string };
}

const WORD = /^[\w.-]+$/;

/** A flag's value from how `--help` writes it: `<file>`, `<dir>`, `md|json`, `<n>`. */
function valuesOf(placeholders: readonly string[]): string {
  const named = placeholders.filter((p) => p.startsWith("<"));
  if (named.some((p) => p.includes("file"))) return "@files";
  if (named.some((p) => p.includes("dir"))) return "@dirs";
  const words = placeholders.flatMap((p) => p.split("|"));
  return named.length === 0 && words.length > 0 && words.every((w) => WORD.test(w)) ? [...new Set(words)].join(" ") : "@any";
}

/** The flags `--help` documents; an option it leaves out is internal (`completion --ids`). */
function flagsOf(command: CliCommand): Flag[] {
  const out: Flag[] = [];
  for (const [key, spec] of Object.entries(command.options ?? {})) {
    const name = `--${key}`;
    const docs = (command.flags ?? []).filter(([flag]) => flag === name || flag.startsWith(`${name} `) || flag.startsWith(`${name},`));
    if (docs.length === 0) continue;
    const values = spec.type === "string" ? valuesOf(docs.map(([flag]) => flag.slice(name.length).replace(/^,?\s*/, ""))) : undefined;
    out.push({ name, what: docs[0]![1], ...(values ? { values } : {}) });
  }
  return out;
}

/** What the command's first argument takes, read off its usage line. */
function argsOf(command: CliCommand): CompletionNode["args"] {
  const max = command.positionals?.max ?? 0;
  const first = /^<([^>]*)>/.exec(command.usage ?? "")?.[1];
  if (max === 0 || first === undefined) return undefined;
  if (first.startsWith("finding-id")) return { max, values: "@ids" };
  if (first.includes("file")) return { max: 1, values: "@files" };
  // `<zsh|bash|fish>`: one of those words. A placeholder among them
  // (`<rule|any> <pattern>`) is a two-argument command, left alone.
  const words = first.split("|");
  return max === 1 && words.length > 1 && words.every((w) => WORD.test(w)) ? { max: 1, values: words.join(" ") } : undefined;
}

/** Every command path, with what completes after it. */
export function completionTree(commands: readonly CliCommand[]): CompletionNode[] {
  const globals: Flag[] = GLOBAL_FLAGS.map(([flag, what]) => ({ name: /--[\w-]+/.exec(flag)![0], what }));
  // `--version` is only read as the first word.
  const everywhere = globals.filter((f) => f.name !== "--version");
  const blurbs = new Map(HELP_GROUPS.flatMap((g) => g.families));
  const byName = new Map(commands.map((c) => [c.name, c]));
  const nodes = new Map<string, CompletionNode>();
  const nodeAt = (words: readonly string[]): CompletionNode => {
    const at = ["doorman", ...words].join(" ");
    let node = nodes.get(at);
    if (!node) nodes.set(at, (node = { at, subs: [], flags: everywhere }));
    return node;
  };
  /** A family's blurb, else the command's summary, else (`mcp server`) the words under it. */
  const describe = (words: readonly string[]): string => {
    const name = words.join(" ");
    const under = [...new Set(commands.filter((c) => c.name.startsWith(`${name} `)).map((c) => c.name.split(" ")[words.length]!))];
    return plain(oneLine((words.length === 1 ? blurbs.get(name) : undefined) ?? byName.get(name)?.summary ?? under.join(", ")));
  };
  const root = nodeAt([]);
  root.flags = globals;
  for (const command of commands) {
    const words = command.name.split(" ");
    words.forEach((word, i) => {
      const parent = nodeAt(words.slice(0, i));
      if (!parent.subs.some(([w]) => w === word)) parent.subs.push([word, describe(words.slice(0, i + 1))]);
    });
    const node = nodeAt(words);
    node.flags = [...flagsOf(command), ...everywhere];
    const args = argsOf(command);
    if (args) node.args = args;
  }
  const families = root.subs.map(([w]) => w);
  root.subs.push(["help", "Usage, options and examples for a command"]);
  nodeAt(["help"]).args = { max: 1, values: families.join(" ") };
  return [...nodes.values()];
}

/** Single-quoted for bash and zsh. */
const sq = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;
/** Single-quoted for fish. */
const fq = (s: string) => `'${s.replace(/\\/g, "\\\\").replace(/'/g, "\\'")}'`;

/** `key` → `"word word"` lookups as bash `case` functions setting `_doorman_r`. */
function bashLookup(fn: string, subject: string, rows: readonly (readonly [key: string, value: string])[]): string[] {
  return [
    `${fn}() {`,
    `  case ${subject} in`,
    ...rows.filter(([, v]) => v !== "").map(([k, v]) => `    ${sq(k)}) _doorman_r=${sq(v)} ;;`),
    "    *) _doorman_r= ;;",
    "  esac",
    "}",
  ];
}

const valueRows = (nodes: readonly CompletionNode[]) => nodes.flatMap((n) => n.flags.filter((f) => f.values).map((f) => [`${n.at} ${f.name}`, f.values!] as const));
const argRows = (nodes: readonly CompletionNode[]) => nodes.flatMap((n) => (n.args ? [[n.at, `${n.args.max} ${n.args.values}`] as const] : []));

function bashScript(nodes: readonly CompletionNode[]): string[] {
  return [
    "# doorman completion for bash, from `doorman completion bash`. Load it from ~/.bashrc:",
    "#   source <(doorman completion bash)",
    '# (bash 3.2, macOS\'s own: eval "$(doorman completion bash)")',
    "",
    ...bashLookup("_doorman_subs", "$1", nodes.map((n) => [n.at, n.subs.map(([w]) => w).join(" ")])),
    ...bashLookup("_doorman_flags", "$1", nodes.map((n) => [n.at, n.flags.map((f) => f.name).join(" ")])),
    ...bashLookup("_doorman_value", '"$1 $2"', valueRows(nodes)),
    ...bashLookup("_doorman_args", "$1", argRows(nodes)),
    "",
    "# Adds what $1 (a word list, @ids, @files, @dirs or @any) offers for $2.",
    "_doorman_values() {",
    "  local line id",
    "  case $1 in",
    "    @any) ;;",
    "    @files|@dirs)",
    '      while IFS= read -r line; do COMPREPLY+=("$line"); done < <(if [[ $1 == @dirs ]]; then compgen -d -- "$2"; else compgen -f -- "$2"; fi)',
    "      type compopt >/dev/null 2>&1 && compopt -o filenames ;;",
    "    @ids)",
    "      while IFS= read -r line; do",
    "        id=${line%%$'\\t'*}",
    '        [[ -n $id && $id == "$2"* ]] && COMPREPLY+=("$id")',
    "      done < <(doorman completion --ids 2>/dev/null) ;;",
    '    *) COMPREPLY+=($(compgen -W "$1" -- "$2")) ;;',
    "  esac",
    "}",
    "",
    "_doorman() {",
    "  local cur=${COMP_WORDS[COMP_CWORD]} at=doorman pending= nargs=0 w i _doorman_r",
    "  COMPREPLY=()",
    "  for ((i = 1; i < COMP_CWORD; i++)); do",
    "    w=${COMP_WORDS[i]}",
    "    # A flag's value (bash splits `--out=x` around the `=`).",
    "    if [[ -n $pending ]]; then [[ $w == = ]] || pending=; continue; fi",
    "    case $w in",
    "      --*=*) continue ;;",
    '      -*) _doorman_value "$at" "$w"; pending=$_doorman_r; continue ;;',
    "    esac",
    "    if ((nargs == 0)); then",
    '      _doorman_subs "$at"',
    '      if [[ " $_doorman_r " == *" $w "* ]]; then at="$at $w"; continue; fi',
    "    fi",
    "    nargs=$((nargs + 1))",
    "  done",
    '  if [[ -n $pending ]]; then _doorman_values "$pending" "$cur"; return 0; fi',
    "  if [[ $cur == -* ]]; then",
    '    _doorman_flags "$at"',
    '    COMPREPLY=($(compgen -W "$_doorman_r" -- "$cur"))',
    "    return 0",
    "  fi",
    "  if ((nargs == 0)); then",
    '    _doorman_subs "$at"',
    '    COMPREPLY=($(compgen -W "$_doorman_r" -- "$cur"))',
    "  fi",
    '  _doorman_args "$at"',
    '  if [[ -n $_doorman_r ]] && ((nargs < ${_doorman_r%% *})); then _doorman_values "${_doorman_r#* }" "$cur"; fi',
    "  return 0",
    "}",
    "",
    "complete -F _doorman doorman",
  ];
}

/** `name:what` lines for `_describe` (a colon in the name is escaped). */
const describeLines = (rows: readonly (readonly [string, string])[]) => rows.map(([name, what]) => `${name.replace(/:/g, "\\:")}:${what}`).join("\n");

function zshAssoc(name: string, rows: readonly (readonly [key: string, value: string])[]): string[] {
  return [`  ${name}=(`, ...rows.filter(([, v]) => v !== "").map(([k, v]) => `    ${sq(k)} ${sq(v)}`), "  )"];
}

function zshScript(nodes: readonly CompletionNode[]): string[] {
  return [
    "#compdef doorman",
    "# doorman completion for zsh, from `doorman completion zsh`. Install it with",
    '#   doorman completion zsh > "${fpath[1]}/_doorman"',
    "# and open a new shell (compinit loads it), or load it from ~/.zshrc after compinit:",
    "#   source <(doorman completion zsh)",
    "",
    "# Offers what $1 (a word list, @ids, @files, @dirs or @any) takes.",
    "_doorman_values() {",
    "  local line",
    "  local -a choices",
    "  case $1 in",
    "    @any) _message value ;;",
    "    @files) _files ;;",
    "    @dirs) _files -/ ;;",
    "    @ids)",
    '      for line in "${(@f)$(doorman completion --ids 2>/dev/null)}"; do',
    "        [[ -n $line ]] && choices+=(\"${${line%%$'\\t'*}//:/\\\\:}:${line#*$'\\t'}\")",
    "      done",
    "      _describe -t exposures exposure choices ;;",
    "    *) choices=(${(s: :)1}); compadd -a choices ;;",
    "  esac",
    "}",
    "",
    "_doorman() {",
    // No `emulate -L zsh`: _describe and _files need the options compsys set.
    "  local -A subs names flags values args",
    ...zshAssoc("subs", nodes.map((n) => [n.at, describeLines(n.subs)])),
    ...zshAssoc("names", nodes.map((n) => [n.at, n.subs.length > 0 ? ` ${n.subs.map(([w]) => w).join(" ")} ` : ""])),
    ...zshAssoc("flags", nodes.map((n) => [n.at, describeLines(n.flags.map((f) => [f.name, f.what]))])),
    ...zshAssoc("values", valueRows(nodes)),
    ...zshAssoc("args", argRows(nodes)),
    "  local at=doorman pending= w key ret=1",
    "  local -a specs",
    "  integer nargs=0",
    '  for w in "${(@)words[2,CURRENT-1]}"; do',
    "    if [[ -n $pending ]]; then pending=; continue; fi",
    "    case $w in",
    "      --*=*) continue ;;",
    '      -*) key="$at $w"; pending=${values[$key]}; continue ;;',
    "    esac",
    '    if (( nargs == 0 )) && [[ ${names[$at]} == *" $w "* ]]; then at="$at $w"; continue; fi',
    "    (( nargs++ ))",
    "  done",
    '  if [[ -n $pending ]]; then _doorman_values "$pending"; return; fi',
    "  if [[ $PREFIX == -* ]]; then",
    '    specs=("${(@f)flags[$at]}")',
    "    _describe -t options option specs",
    "    return",
    "  fi",
    "  if (( nargs == 0 )) && [[ -n ${subs[$at]} ]]; then",
    '    specs=("${(@f)subs[$at]}")',
    "    _describe -t commands command specs && ret=0",
    "  fi",
    "  key=${args[$at]}",
    '  if [[ -n $key ]] && (( nargs < ${key%% *} )); then _doorman_values "${key#* }" && ret=0; fi',
    "  return ret",
    "}",
    "",
    "# Autoloaded from $fpath: complete now. Sourced: register with compinit.",
    "if [[ $funcstack[1] == _doorman ]]; then",
    '  _doorman "$@"',
    "elif (( $+functions[compdef] )); then",
    "  compdef _doorman doorman",
    "fi",
  ];
}

/** A fish `switch` printing `word<TAB>what` lines per key. */
function fishTable(fn: string, rows: readonly (readonly [key: string, entries: readonly (readonly [string, string])[]])[]): string[] {
  return [
    `function ${fn} --argument-names at`,
    "    switch $at",
    ...rows
      .filter(([, entries]) => entries.length > 0)
      .flatMap(([key, entries]) => [`        case ${fq(key)}`, ...entries.map(([word, what]) => `            printf '%s\\t%s\\n' ${fq(word)} ${fq(what)}`)]),
    "    end",
    "end",
  ];
}

function fishLookup(fn: string, params: string, subject: string, rows: readonly (readonly [key: string, value: string])[]): string[] {
  return [`function ${fn} --argument-names ${params}`, `    switch ${subject}`, ...rows.flatMap(([k, v]) => [`        case ${fq(k)}`, `            echo ${fq(v)}`]), "    end", "end"];
}

function fishScript(nodes: readonly CompletionNode[]): string[] {
  return [
    "# doorman completion for fish, from `doorman completion fish`. Install it with",
    "#   doorman completion fish > ~/.config/fish/completions/doorman.fish",
    "",
    ...fishTable("__doorman_subs", nodes.map((n) => [n.at, n.subs])),
    ...fishTable("__doorman_flags", nodes.map((n) => [n.at, n.flags.map((f) => [f.name, f.what] as const)])),
    ...fishLookup("__doorman_value", "at flag", '"$at $flag"', valueRows(nodes)),
    ...fishLookup("__doorman_args", "at", "$at", argRows(nodes)),
    "",
    "# Prints what $spec (a word list, @ids, @files, @dirs or @any) offers.",
    "function __doorman_values --argument-names spec",
    "    switch $spec",
    "        case '@any'",
    "        case '@files'",
    "            __fish_complete_path (commandline -ct)",
    "        case '@dirs'",
    "            __fish_complete_directories (commandline -ct)",
    "        case '@ids'",
    "            doorman completion --ids 2>/dev/null",
    "        case '*'",
    "            string split ' ' -- $spec",
    "    end",
    "end",
    "",
    "function __doorman_complete",
    "    set -l tokens (commandline -opc)",
    "    set -e tokens[1]",
    "    set -l at doorman",
    "    set -l pending",
    "    set -l nargs 0",
    "    for w in $tokens",
    "        if test -n \"$pending\"",
    "            set pending",
    "            continue",
    "        end",
    "        switch $w",
    "            case '--*=*'",
    "                continue",
    "            case '-*'",
    "                set pending (__doorman_value $at $w)",
    "                continue",
    "        end",
    "        if test $nargs -eq 0; and contains -- $w (__doorman_subs $at | string replace -r '\\t.*' '')",
    '            set at "$at $w"',
    "            continue",
    "        end",
    "        set nargs (math $nargs + 1)",
    "    end",
    "    if test -n \"$pending\"",
    "        __doorman_values $pending",
    "        return",
    "    end",
    "    if string match -q -- '-*' (commandline -ct)",
    "        __doorman_flags $at",
    "        return",
    "    end",
    "    test $nargs -eq 0; and __doorman_subs $at",
    "    set -l spec (string split -m1 ' ' -- (__doorman_args $at))",
    "    if test -n \"$spec[1]\"; and test $nargs -lt $spec[1]",
    "        __doorman_values $spec[2]",
    "    end",
    "end",
    "",
    "complete -c doorman -f -a '(__doorman_complete)'",
  ];
}

/** The completion script for `shell`, without a trailing newline. */
export function completionScript(shell: Shell, commands: readonly CliCommand[]): string {
  const nodes = completionTree(commands);
  const lines = shell === "bash" ? bashScript(nodes) : shell === "zsh" ? zshScript(nodes) : fishScript(nodes);
  return lines.join("\n");
}

/** `doorman completion`; `registry` is every command, this one included. */
export function completionCommand(registry: () => readonly CliCommand[]): CliCommand {
  return {
    name: "completion",
    summary: "Print a Tab-completion script for zsh, bash or fish",
    usage: "<zsh|bash|fish>",
    positionals: { min: 0, max: 1 },
    // --ids: what the scripts call for exposure ids, one `id<TAB>what` line
    // each, open ones first. Not in `flags`, so neither --help nor Tab offers it.
    options: { ids: { type: "boolean", default: false } },
    notes: [
      "Prints the script on stdout. It completes every command, subcommand and flag this version has, and exposure ids after `doorman findings show` and the other findings commands, read from Doorman as you press Tab.",
      "Install it once, then open a new shell:",
      '  zsh   doorman completion zsh > "${fpath[1]}/_doorman"',
      "  bash  add source <(doorman completion bash) to ~/.bashrc",
      "  fish  doorman completion fish > ~/.config/fish/completions/doorman.fish",
      'zsh needs compinit (most setups run it). macOS\'s own bash 3.2 can\'t source <(...): add eval "$(doorman completion bash)" instead. A saved script (zsh, fish) knows the commands of the version that wrote it: save it again after `doorman update`.',
    ],
    examples: [
      ['doorman completion zsh > "${fpath[1]}/_doorman"', "zsh: install for the next shell"],
      ["doorman completion fish > ~/.config/fish/completions/doorman.fish", "fish: install"],
    ],
    async run(ctx, args) {
      if (args.values.ids === true) {
        const prefs = ctx.prefs();
        const labels = ruleLabels(ctx);
        return withEngine(ctx, false, ({ engine }) => {
          const rows = radarFeedRows(radarRows(engine.shownFindings(), ctx.io.home), {
            hiddenBands: hiddenConfidenceBands(prefs),
            showFalsePositives: prefs.show_false_positives === true,
          });
          const groups = exposureGroups(rows).sort((a, b) => Number(a.bucket !== "open") - Number(b.bucket !== "open"));
          const exposures = groups.map((g) => ({
            id: g.face.finding_id,
            severity: g.face.severity,
            title: oneLine(cardTitle(g.face, labels)),
            place: exposurePlace(g.face),
            status: g.bucket === "open" ? "open" : g.face.status,
          }));
          const text = exposures.map((e) => {
            const what = [e.severity, `${e.title}${e.place ? ` (${e.place})` : ""}`, ...(e.status === "open" ? [] : [e.status.replace(/_/g, " ")])];
            return `${e.id}\t${what.join(", ")}`;
          });
          return { data: { exposures }, text, raw: true };
        });
      }
      const shell = args.positionals[0];
      if (shell === undefined) throw new CliError("Which shell: zsh, bash or fish?", 2, "`doorman completion --help` says how to install each.");
      if (!(SHELLS as readonly string[]).includes(shell)) throw new CliError(`No completion for "${shell}": zsh, bash or fish.`, 2);
      const script = completionScript(shell as Shell, registry());
      return { data: { shell, script }, text: script.split("\n"), raw: true };
    },
  };
}

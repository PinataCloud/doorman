/**
 * Shipped rule packs — new deterministic detections expressed in the custom
 * rule format (custom-rules.ts) instead of TypeScript, so they read as worked
 * examples of what a person can write, ship without a release, and can be
 * switched off per machine. A pack is a labelled set of rules; enabling it
 * copies the rules into the live policy under `pack:<pack>/<rule>` ids, where
 * the person can edit them like their own.
 *
 * Only shapes that fit a `when` clause belong here. Detections that need the
 * redactor, a checksum, or the flow engine's taints stay in security-detect.ts
 * and flow-rules.ts.
 *
 * Self-containment rule: this directory is copied verbatim to userData; nothing
 * here may import from outside main/guard/.
 */

import type { CustomRule } from "./custom-rules.js";
import { rulePackShown } from "./rule-scope.js";

export interface RulePack {
  id: string;
  label: string;
  blurb: string;
  /** Packs that ship enabled. The rest are offered, not imposed. */
  default_on: boolean;
  rules: CustomRule[];
}

/**
 * Every pack Doorman ships, BEFORE the scope. Exported for one
 * reason: so a hidden pack's patterns keep their tests while the pack is
 * hidden (they come back the day it does). App code reads `RULE_PACKS` —
 * test/rule-scope.test.ts fails if anything under main/ but this file
 * names this constant.
 */
export const SHIPPED_RULE_PACKS: readonly RulePack[] = [
  {
    id: "publish_actions",
    label: "Publish & outward pushes",
    blurb:
      "Irreversible, outward-facing commands: publishing a package, pushing an image, cutting a release, adding a remote or pushing straight to a URL. Warn-grade — the same reason the five default-ask rules exist, one band softer until its noise level is known.",
    default_on: true,
    rules: [
      {
        id: "npm_publish",
        label: "npm package published",
        severity: "medium",
        mode: "warn",
        when: { command: "(?:^|\\s|&&|;|\\|)\\s*(?:npm|pnpm|yarn)\\s+publish\\b" },
      },
      {
        id: "pypi_upload",
        label: "Python package uploaded",
        severity: "medium",
        mode: "warn",
        when: { command: "(?:^|\\s)(?:twine\\s+upload|python3?\\s+-m\\s+twine\\s+upload|uv\\s+publish|poetry\\s+publish|flit\\s+publish)\\b" },
      },
      {
        id: "gem_push",
        label: "Ruby gem pushed",
        severity: "medium",
        mode: "warn",
        when: { command: "(?:^|\\s)gem\\s+push\\b" },
      },
      {
        id: "cargo_publish",
        label: "Rust crate published",
        severity: "medium",
        mode: "warn",
        when: { command: "(?:^|\\s)cargo\\s+publish\\b" },
      },
      {
        id: "docker_push",
        label: "Container image pushed",
        severity: "medium",
        mode: "warn",
        when: { command: "(?:^|\\s)(?:docker|podman|nerdctl)\\s+push\\b" },
      },
      {
        id: "gh_release",
        label: "GitHub release created",
        severity: "medium",
        mode: "warn",
        when: { command: "(?:^|\\s)gh\\s+release\\s+(?:create|upload)\\b" },
      },
      {
        id: "git_remote_added",
        label: "Git remote added or re-pointed",
        severity: "medium",
        mode: "warn",
        when: { command: "(?:^|\\s)git\\s+remote\\s+(?:add|set-url)\\b" },
      },
      {
        id: "git_push_to_url",
        label: "Git push straight to a URL",
        severity: "medium",
        mode: "warn",
        // No nested quantifier (`(\S+\s+)*` would be refused as pathological):
        // anything up to a separator, then a URL-shaped remote after a space.
        when: { command: "(?:^|\\s)git\\s+push\\b[^|;\\n]*?\\s(?:https?://|git@|ssh://)" },
      },
    ],
  },
  {
    id: "external_recipients",
    label: "Messages to external recipients",
    blurb:
      "An MCP send/reply/forward/share tool addressed to an email outside your own domain. Edit the `to` pattern to name your domain — as shipped it matches any address, so it is a template more than a verdict.",
    default_on: false,
    rules: [
      {
        id: "send_to_address",
        label: "Message sent to an outside address",
        blurb: "Replace `example\\.com` in the `to` pattern with your organization's domain.",
        severity: "medium",
        mode: "warn",
        when: {
          // Lazy up to the `__` that ends the server segment — a nested
          // quantifier (`(?:_[^_]+)*`) would be refused as pathological.
          tool: "^mcp__\\S+?__(?:send|reply|forward|share|invite|email|message|dm)",
          // An address whose domain is NOT example.com (or a subdomain of it).
          arg: { to: "@(?![^\\s@]*\\bexample\\.com\\b)" },
        },
      },
    ],
  },
  {
    id: "container_privilege",
    label: "Privileged containers",
    blurb:
      "A container started with the host's privileges: `--privileged`, `--cap-add SYS_ADMIN`, the Docker socket or the root filesystem mounted in. Each hands the container the machine.",
    default_on: true,
    rules: [
      {
        id: "privileged_container",
        label: "Privileged container started",
        severity: "high",
        mode: "warn",
        when: {
          command:
            "(?:^|\\s)(?:docker|podman|nerdctl)\\s+(?:run|create)\\b[^|;\\n]*(?:--privileged\\b|--cap-add[= ]\\s*(?:SYS_ADMIN|ALL)\\b|-v\\s+/var/run/docker\\.sock:|-v\\s+/:/|--pid[= ]host\\b)",
        },
      },
    ],
  },
  {
    id: "crypto_operations",
    label: "Crypto wallets: transfers, key exports, exchange APIs",
    blurb:
      "Commands that move funds or export wallet keys — bitcoin-cli sends and dumps, cast send / forge --broadcast / Hardhat on a live network, solana transfer, a signer key on the command line — held for a keystroke, the way a terraform destroy is. Exchange API hosts and mainnet RPC endpoints are recorded only. The checksum-verified address and seed-phrase rules live in the Crypto wallets & keys family; this pack is the command-shaped half, and you can edit it.",
    default_on: true,
    rules: [
      {
        id: "btc_send",
        label: "Bitcoin sent from a node wallet",
        severity: "high",
        mode: "ask",
        when: { command: "(?:^|\\s)bitcoin-cli\\b[^|;\\n]*?\\s(?:sendtoaddress|sendmany|send|sendall|walletprocesspsbt|signrawtransactionwithwallet)\\b|(?:^|\\s)electrum\\b[^|;\\n]*?\\s(?:payto|paytomany|broadcast)\\b" },
      },
      {
        id: "btc_key_export",
        label: "Bitcoin wallet keys exported",
        severity: "critical",
        mode: "ask",
        when: { command: "(?:^|\\s)bitcoin-cli\\b[^|;\\n]*?\\s(?:dumpprivkey|dumpwallet|walletpassphrase)\\b|(?:^|\\s)bitcoin-cli\\b[^|;\\n]*?\\slistdescriptors\\s+true\\b|(?:^|\\s)electrum\\b[^|;\\n]*?\\s(?:getprivatekeys|getseed|getmasterprivate)\\b" },
      },
      {
        id: "evm_send",
        label: "EVM transaction sent with cast",
        blurb: "cast send / publish / mktx against a LIVE network. A local node (127.0.0.1, localhost, anvil, chain id 31337) or a named testnet (sepolia, holesky, goerli) is a dev loop, not money, and does not fire.",
        severity: "high",
        mode: "ask",
        when: { command: "(?:^|\\s)cast\\s+(?:send|publish|mktx)\\b(?![^|;\\n]*(?:--rpc-url|-r|--fork-url)[= ]\\S*(?:127\\.0\\.0\\.1|localhost|anvil)\\b)(?![^|;\\n]*--chain(?:-id)?[= ](?:31337|anvil|localhost|sepolia|holesky|goerli)\\b)" },
      },
      {
        id: "evm_broadcast",
        label: "Forge script broadcast",
        blurb: "forge script --broadcast against a live network; local and testnet targets are exempt as above. The exemption sits right after the verb so it sees an --rpc-url written before or after --broadcast.",
        severity: "high",
        mode: "ask",
        when: { command: "(?:^|\\s)forge\\s+script\\b(?![^|;\\n]*(?:--rpc-url|-r|--fork-url)[= ]\\S*(?:127\\.0\\.0\\.1|localhost|anvil)\\b)(?![^|;\\n]*--chain(?:-id)?[= ](?:31337|anvil|localhost|sepolia|holesky|goerli)\\b)[^|;\\n]*--broadcast\\b" },
      },
      {
        id: "evm_live_network",
        label: "EVM deploy or raw transaction on a live network",
        blurb: "Hardhat run / Ignition deploy on any network that isn't local or a named testnet, or a raw eth_sendRawTransaction not aimed at localhost.",
        severity: "high",
        mode: "ask",
        when: { command: "(?:^|\\s)hardhat\\s+(?:run|ignition\\s+deploy)\\b[^|;\\n]*--network\\s+(?!localhost\\b|hardhat\\b|anvil\\b|sepolia\\b|holesky\\b|goerli\\b)\\S|(?<!(?:127\\.0\\.0\\.1|localhost)[^|;\\n]*)\\beth_sendRawTransaction\\b" },
      },
      {
        id: "signer_key_in_argv",
        label: "Signer key or mnemonic on the command line",
        blurb: "A --private-key or --mnemonic argument, or cast wallet import / private-key / decrypt-keystore. The key lands in shell history and the process list.",
        severity: "critical",
        mode: "ask",
        when: { command: "--private-key[= ]\\s*(?:0x)?[0-9a-fA-F]{64}\\b|--mnemonic[= ]|(?:^|\\s)cast\\s+wallet\\s+(?:import|private-key|decrypt-keystore)\\b" },
      },
      {
        id: "sol_transfer",
        label: "Solana transfer",
        blurb: "solana transfer, spl-token transfer / burn / close, a mainnet program deploy. Localhost, devnet and testnet (-ul / -ud / -ut, --url localhost|devnet|testnet) are a dev loop and do not fire.",
        severity: "high",
        mode: "ask",
        when: { command: "(?:^|\\s)solana\\s+transfer(?![\\w-])(?![^|;\\n]*(?:-u\\s*[ldt]\\b|--url[= ]\\S*(?:localhost|devnet|testnet|127\\.0\\.0\\.1)\\b|--url[= ][ldt]\\b))|(?:^|\\s)spl-token\\s+(?:transfer|burn|close)\\b(?![^|;\\n]*(?:-u\\s*[ldt]\\b|--url[= ]\\S*(?:localhost|devnet|testnet|127\\.0\\.0\\.1)\\b|--url[= ][ldt]\\b))|(?:^|\\s)solana\\s+program\\s+(?:deploy|close)\\b[^|;\\n]*(?:-um\\b|-u\\s*m\\b|--url\\s+(?:m|mainnet\\S*))" },
      },
      {
        id: "sol_key_export",
        label: "Solana keypair recovered or generated",
        severity: "high",
        mode: "ask",
        when: { command: "(?:^|\\s)solana-keygen\\s+(?:recover|new|grind)\\b" },
      },
      {
        id: "other_chain_transfer",
        label: "Sui / Aptos / NEAR / Cosmos transfer",
        severity: "high",
        mode: "ask",
        when: { command: "(?:^|\\s)sui\\s+client\\s+(?:transfer|transfer-sui|pay|pay-sui|pay-all-sui|call)\\b|(?:^|\\s)aptos\\s+(?:account\\s+transfer|move\\s+run)\\b|(?:^|\\s)near\\s+(?:send|send-near)\\b|(?:^|\\s)\\w+d\\s+tx\\s+bank\\s+send\\b" },
      },
      {
        id: "exchange_api_use",
        label: "Exchange API called",
        blurb: "Binance, Kraken, Coinbase Advanced Trade, Robinhood (official or robin_stocks). A record that the agent touched a trading account, not a verdict.",
        severity: "medium",
        mode: "observe",
        when: { command: "api\\.binance\\.com|api\\.kraken\\.com/0/private|api\\.coinbase\\.com/api/v3/brokerage|(?:trading|api)\\.robinhood\\.com|\\brobin_stocks\\b|\\brs\\.login\\(" },
      },
      {
        id: "mainnet_rpc",
        label: "Mainnet RPC endpoint called",
        blurb: "Alchemy / Infura / QuickNode mainnet endpoints, Solana's mainnet-beta. The fact of touching a live chain, recorded only.",
        severity: "low",
        mode: "observe",
        when: { command: "(?:eth|polygon|arb|opt|base)-mainnet\\.g\\.alchemy\\.com|mainnet\\.infura\\.io|api\\.mainnet-beta\\.solana\\.com|\\.quiknode\\.pro/" },
      },
      {
        id: "ens_name_written",
        label: "ENS name written",
        blurb: "A human-readable payee (`vitalik.eth`) in a file this session is writing — the same address-swap target, spelled for people.",
        severity: "low",
        mode: "observe",
        when: { tool: "^(?:Write|Edit|MultiEdit|NotebookEdit|write_file|edit_file|apply_patch)$", arg: { content: "(?<![\\w.-])[a-z0-9-]{3,}\\.eth\\b" } },
      },
    ],
  },
  {
    id: "privilege_escalation",
    label: "Privilege escalation",
    blurb:
      "`sudo`, `su`, `doas` — routine on a developer Mac, which is why this ships observe-only: a record of when the agent ran as root, never an interruption.",
    default_on: false,
    rules: [
      {
        id: "ran_as_root",
        label: "Command run as root",
        severity: "low",
        mode: "observe",
        when: { command: "(?:^|\\s|&&|;|\\|)\\s*(?:sudo|doas)\\s+(?!-[nv]\\s+true\\b)\\S|(?:^|\\s)su\\s+(?:-(?:\\s|$)|-l\\b|root\\b)" },
      },
    ],
  },
];

/**
 * The packs the app SHOWS — offered on Guardrails, storable in prefs,
 * contributing rules to the policy. Narrowed through guard/rule-scope.ts
 *: a hidden pack is absent from every one of those, so it is not
 * "off", it is not there.
 */
export const RULE_PACKS: readonly RulePack[] = SHIPPED_RULE_PACKS.filter((p) => rulePackShown(p.id));

export const RULE_PACK_IDS: readonly string[] = RULE_PACKS.map((p) => p.id);

/** The rule id a pack rule takes once it is in the live policy. */
export function packRuleId(packId: string, ruleId: string): string {
  return `${packId}--${ruleId}`;
}

/**
 * The rules an enabled-pack list contributes, id-prefixed and tagged with their
 * pack. A person's own rules (custom_rules) are merged on top by the caller —
 * an edited copy of a pack rule (same id) replaces the shipped one.
 */
export function packRules(enabled: readonly string[], from: readonly RulePack[] = RULE_PACKS): CustomRule[] {
  const on = new Set(enabled);
  const out: CustomRule[] = [];
  for (const pack of from) {
    if (!on.has(pack.id)) continue;
    for (const rule of pack.rules) {
      out.push({ ...rule, id: packRuleId(pack.id, rule.id), pack: pack.id });
    }
  }
  return out;
}

/** The packs that are on when nobody has chosen. */
export function defaultEnabledPacks(): string[] {
  return RULE_PACKS.filter((p) => p.default_on).map((p) => p.id);
}

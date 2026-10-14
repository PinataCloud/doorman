// Wallet codec — recognises cryptocurrency addresses and wallet KEY MATERIAL in
// text, by checksum wherever a chain has one.
//
// This is the validator half of the crypto-wallet detector family (see
// security-detect.ts `wallet_address_exposed` / `wallet_key_material`). It is
// deliberately a CODEC, not a detector: it answers "is this token a valid
// address, for which chain, how sure" and "is this run of words a BIP-39
// mnemonic" — never what to do about it. Confidence comes from the checksum:
// a Base58Check, bech32m, EIP-55, CRC16 or BIP-39 checksum that verifies is
// `high`; a shape that merely fits (an all-lowercase EVM address, a Solana key
// that is just 32 bytes of Base58) is `medium` or `low`, and the enforcement
// folds never hold a call on those.
//
// IMPORTANT: like redact.ts, this file is part of the guard bundle, which is
// copied to userData and run with plain `node` from the agents' hook entries —
// so it must import nothing at all (not even Node built-ins). Every hash below is therefore written out in plain
// TypeScript:
//   · SHA-256 per FIPS 180-4 (double-SHA-256 is the Base58Check checksum of
//     BIP-13/BIP-32/BIP-38, and the BIP-39 mnemonic checksum);
//   · Keccak-f[1600] per the Keccak reference (EIP-55 mixed-case checksum);
//   · bech32 / bech32m per BIP-173 and BIP-350; CashAddr per the Bitcoin Cash
//     spec (spec/cashaddr.md); CRC16-XModem for Stellar strkeys (SEP-23) and
//     TON user-friendly addresses (docs.ton.org/learn/overviews/addresses).
//
// THE INVARIANT this module shares with the detector: nothing here stores or
// returns anything but positions, chains and confidences — plus, for the
// "My wallets" list, a SALTED hash of an address. An address is public by
// design, but a file listing the person's wallets is itself a leak, so the
// list is stored as `walletAddressHash` values and compared by hashing the
// candidate, never by reading the addresses back.

export type WalletChain =
  | "btc"
  | "ltc"
  | "doge"
  | "bch"
  | "evm"
  | "sol"
  | "trx"
  | "xrp"
  | "ada"
  | "atom"
  | "xlm"
  | "ton"
  | "xtz"
  | "dot"
  | "algo"
  | "xmr"
  | "sui"
  | "apt";

export const WALLET_CHAINS: readonly WalletChain[] = [
  "btc",
  "ltc",
  "doge",
  "bch",
  "evm",
  "sol",
  "trx",
  "xrp",
  "ada",
  "atom",
  "xlm",
  "ton",
  "xtz",
  "dot",
  "algo",
  "xmr",
  "sui",
  "apt",
];

export const WALLET_CHAIN_LABELS: Readonly<Record<WalletChain, string>> = {
  btc: "Bitcoin",
  ltc: "Litecoin",
  doge: "Dogecoin",
  bch: "Bitcoin Cash",
  evm: "Ethereum / EVM",
  sol: "Solana",
  trx: "TRON",
  xrp: "XRP",
  ada: "Cardano",
  atom: "Cosmos",
  xlm: "Stellar",
  ton: "TON",
  xtz: "Tezos",
  dot: "Polkadot",
  algo: "Algorand",
  xmr: "Monero",
  sui: "Sui",
  apt: "Aptos",
};

/**
 * Chains on by default: every chain whose address carries a checksum this
 * module can verify, plus the two big ones that don't (EVM's all-lowercase
 * form, Solana) at reduced confidence. Polkadot (SS58, blake2b), Algorand
 * (SHA-512/256) and Monero (block base58 + keccak) verify too and are on.
 * NOT sui / apt (`0x` + 64 hex is every transaction hash on earth).
 */
export const DEFAULT_WALLET_CHAINS: readonly WalletChain[] = [
  "btc",
  "ltc",
  "doge",
  "bch",
  "evm",
  "sol",
  "trx",
  "xrp",
  "ada",
  "atom",
  "xlm",
  "ton",
  "xtz",
  "dot",
  "algo",
  "xmr",
];

export type WalletConfidence = "high" | "medium" | "low";

export interface WalletAddressHit {
  chain: WalletChain;
  value: string;
  start: number;
  end: number;
  confidence: WalletConfidence;
}

export type WalletKeyKind = "bip39_mnemonic" | "wif" | "xprv" | "xpub" | "solana_keypair" | "eth_keystore";

export interface WalletKeyHit {
  kind: WalletKeyKind;
  start: number;
  end: number;
  confidence: WalletConfidence;
  /** Word count, for mnemonics. */
  words?: number;
}

/** Cap on scanned text — the same bound security-detect.ts uses. */
const SCAN_MAX_CHARS = 64_000;

// ── Byte helpers ─────────────────────────────────────────────────────────────

/**
 * UTF-8 by hand rather than `TextEncoder`: this file runs wherever the
 * detectors run — a Node hook, a Chrome content script, and a bare `vm`
 * context in tests — and a bare context has no TextEncoder global. Nothing
 * here may depend on a host-provided object beyond the language itself.
 */
function utf8Bytes(text: string): Uint8Array {
  const out: number[] = [];
  for (let i = 0; i < text.length; i += 1) {
    let code = text.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff && i + 1 < text.length) {
      const low = text.charCodeAt(i + 1);
      if (low >= 0xdc00 && low <= 0xdfff) {
        code = 0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00);
        i += 1;
      }
    }
    if (code < 0x80) out.push(code);
    else if (code < 0x800) out.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
    else if (code < 0x10000) out.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
    else out.push(0xf0 | (code >> 18), 0x80 | ((code >> 12) & 0x3f), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
  }
  return Uint8Array.from(out);
}

function toBytes(input: string | Uint8Array): Uint8Array {
  return typeof input === "string" ? utf8Bytes(input) : input;
}

const HEX = "0123456789abcdef";

function hex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 1) {
    const b = bytes[i]!;
    out += HEX[b >> 4]! + HEX[b & 15]!;
  }
  return out;
}

function bytesEqual(a: Uint8Array, aStart: number, b: Uint8Array, bStart: number, length: number): boolean {
  for (let i = 0; i < length; i += 1) if (a[aStart + i] !== b[bStart + i]) return false;
  return true;
}

// ── SHA-256 (FIPS 180-4) ─────────────────────────────────────────────────────

const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function sha256Bytes(input: Uint8Array): Uint8Array {
  const length = input.length;
  // Padding: 0x80, zeros, 64-bit big-endian bit length; total a multiple of 64.
  const padded = new Uint8Array(((length + 9 + 63) >> 6) << 6);
  padded.set(input);
  padded[length] = 0x80;
  const bits = length * 8;
  const view = new DataView(padded.buffer);
  view.setUint32(padded.length - 8, Math.floor(bits / 0x1_0000_0000));
  view.setUint32(padded.length - 4, bits >>> 0);

  const h = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ]);
  const w = new Uint32Array(64);
  for (let offset = 0; offset < padded.length; offset += 64) {
    for (let i = 0; i < 16; i += 1) w[i] = view.getUint32(offset + i * 4);
    for (let i = 16; i < 64; i += 1) {
      const w15 = w[i - 15]!;
      const w2 = w[i - 2]!;
      const s0 = ((w15 >>> 7) | (w15 << 25)) ^ ((w15 >>> 18) | (w15 << 14)) ^ (w15 >>> 3);
      const s1 = ((w2 >>> 17) | (w2 << 15)) ^ ((w2 >>> 19) | (w2 << 13)) ^ (w2 >>> 10);
      w[i] = (w[i - 16]! + s0 + w[i - 7]! + s1) >>> 0;
    }
    let a = h[0]!;
    let b = h[1]!;
    let c = h[2]!;
    let d = h[3]!;
    let e = h[4]!;
    let f = h[5]!;
    let g = h[6]!;
    let hh = h[7]!;
    for (let i = 0; i < 64; i += 1) {
      const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      const ch = (e & f) ^ (~e & g);
      const t1 = (hh + S1 + ch + SHA256_K[i]! + w[i]!) >>> 0;
      const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      hh = g;
      g = f;
      f = e;
      e = (d + t1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) >>> 0;
    }
    h[0] = (h[0]! + a) >>> 0;
    h[1] = (h[1]! + b) >>> 0;
    h[2] = (h[2]! + c) >>> 0;
    h[3] = (h[3]! + d) >>> 0;
    h[4] = (h[4]! + e) >>> 0;
    h[5] = (h[5]! + f) >>> 0;
    h[6] = (h[6]! + g) >>> 0;
    h[7] = (h[7]! + hh) >>> 0;
  }
  const out = new Uint8Array(32);
  const outView = new DataView(out.buffer);
  for (let i = 0; i < 8; i += 1) outView.setUint32(i * 4, h[i]!);
  return out;
}

export function sha256Hex(input: string | Uint8Array): string {
  return hex(sha256Bytes(toBytes(input)));
}

/** Base58Check's checksum: the first four bytes of SHA-256(SHA-256(payload)). */
function doubleSha256(input: Uint8Array): Uint8Array {
  return sha256Bytes(sha256Bytes(input));
}

// ── Keccak-256 (Keccak reference, as used by Ethereum / EIP-55) ─────────────
//
// BigInt lanes: the input here is at most a 40-character address, so the
// clarity of 64-bit lanes is worth more than the speed of a split-word port.

const KECCAK_ROUNDS = 24;
const KECCAK_RC: readonly bigint[] = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];
const KECCAK_ROT: readonly number[] = [
  0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];
const MASK64 = (1n << 64n) - 1n;

function rotl64(x: bigint, n: number): bigint {
  if (n === 0) return x;
  return ((x << BigInt(n)) | (x >> BigInt(64 - n))) & MASK64;
}

function keccakF(state: bigint[]): void {
  for (let round = 0; round < KECCAK_ROUNDS; round += 1) {
    // θ
    const c: bigint[] = [];
    for (let x = 0; x < 5; x += 1) {
      c[x] = state[x]! ^ state[x + 5]! ^ state[x + 10]! ^ state[x + 15]! ^ state[x + 20]!;
    }
    for (let x = 0; x < 5; x += 1) {
      const d = c[(x + 4) % 5]! ^ rotl64(c[(x + 1) % 5]!, 1);
      for (let y = 0; y < 25; y += 5) state[x + y] = state[x + y]! ^ d;
    }
    // ρ and π
    const b: bigint[] = new Array<bigint>(25);
    for (let x = 0; x < 5; x += 1) {
      for (let y = 0; y < 5; y += 1) {
        const index = x + 5 * y;
        b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(state[index]!, KECCAK_ROT[index]!);
      }
    }
    // χ
    for (let y = 0; y < 25; y += 5) {
      for (let x = 0; x < 5; x += 1) {
        state[x + y] = b[x + y]! ^ (~b[((x + 1) % 5) + y]! & MASK64 & b[((x + 2) % 5) + y]!);
      }
    }
    // ι
    state[0] = state[0]! ^ KECCAK_RC[round]!;
  }
}

function keccak256Bytes(input: Uint8Array): Uint8Array {
  const rate = 136; // 1600 − 2·256 bits, in bytes
  const state: bigint[] = new Array<bigint>(25).fill(0n);
  // Pad: 0x01 … 0x80 (Keccak, NOT the SHA-3 0x06 domain byte — Ethereum uses
  // the original Keccak padding, which is why its hash differs from SHA3-256).
  const padded = new Uint8Array(Math.ceil((input.length + 1) / rate) * rate);
  padded.set(input);
  padded[input.length] = padded[input.length]! | 0x01;
  padded[padded.length - 1] = padded[padded.length - 1]! | 0x80;
  for (let offset = 0; offset < padded.length; offset += rate) {
    for (let lane = 0; lane < rate / 8; lane += 1) {
      let value = 0n;
      for (let i = 7; i >= 0; i -= 1) value = (value << 8n) | BigInt(padded[offset + lane * 8 + i]!);
      state[lane] = state[lane]! ^ value;
    }
    keccakF(state);
  }
  const out = new Uint8Array(32);
  for (let lane = 0; lane < 4; lane += 1) {
    let value = state[lane]!;
    for (let i = 0; i < 8; i += 1) {
      out[lane * 8 + i] = Number(value & 0xffn);
      value >>= 8n;
    }
  }
  return out;
}

export function keccak256Hex(input: string | Uint8Array): string {
  return hex(keccak256Bytes(toBytes(input)));
}

// ── BLAKE2b-512 (RFC 7693) — the SS58 checksum hash ─────────────────────────
//
// BigInt lanes again: the input is "SS58PRE" plus at most 36 bytes, one block.

const BLAKE2B_IV: readonly bigint[] = [
  0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n,
];
const BLAKE2B_SIGMA: readonly (readonly number[])[] = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

function rotr64(x: bigint, n: number): bigint {
  return ((x >> BigInt(n)) | (x << BigInt(64 - n))) & MASK64;
}

function readLe64(bytes: Uint8Array, offset: number): bigint {
  let value = 0n;
  for (let i = 7; i >= 0; i -= 1) value = (value << 8n) | BigInt(bytes[offset + i]!);
  return value;
}

function blake2b512Bytes(input: Uint8Array): Uint8Array {
  const h: bigint[] = BLAKE2B_IV.slice();
  // Parameter block: digest length 64, no key, fanout 1, depth 1.
  h[0] = h[0]! ^ 0x01010040n;
  const blocks = Math.max(1, Math.ceil(input.length / 128));
  const padded = new Uint8Array(blocks * 128);
  padded.set(input);
  for (let block = 0; block < blocks; block += 1) {
    const last = block === blocks - 1;
    const counter = BigInt(last ? input.length : (block + 1) * 128);
    const m: bigint[] = [];
    for (let i = 0; i < 16; i += 1) m.push(readLe64(padded, block * 128 + i * 8));
    const v: bigint[] = [...h, ...BLAKE2B_IV];
    v[12] = v[12]! ^ (counter & MASK64);
    v[13] = v[13]! ^ (counter >> 64n);
    if (last) v[14] = ~v[14]! & MASK64;
    const g = (a: number, b: number, c: number, d: number, x: bigint, y: bigint): void => {
      v[a] = (v[a]! + v[b]! + x) & MASK64;
      v[d] = rotr64(v[d]! ^ v[a]!, 32);
      v[c] = (v[c]! + v[d]!) & MASK64;
      v[b] = rotr64(v[b]! ^ v[c]!, 24);
      v[a] = (v[a]! + v[b]! + y) & MASK64;
      v[d] = rotr64(v[d]! ^ v[a]!, 16);
      v[c] = (v[c]! + v[d]!) & MASK64;
      v[b] = rotr64(v[b]! ^ v[c]!, 63);
    };
    for (let round = 0; round < 12; round += 1) {
      const sg = BLAKE2B_SIGMA[round]!;
      g(0, 4, 8, 12, m[sg[0]!]!, m[sg[1]!]!);
      g(1, 5, 9, 13, m[sg[2]!]!, m[sg[3]!]!);
      g(2, 6, 10, 14, m[sg[4]!]!, m[sg[5]!]!);
      g(3, 7, 11, 15, m[sg[6]!]!, m[sg[7]!]!);
      g(0, 5, 10, 15, m[sg[8]!]!, m[sg[9]!]!);
      g(1, 6, 11, 12, m[sg[10]!]!, m[sg[11]!]!);
      g(2, 7, 8, 13, m[sg[12]!]!, m[sg[13]!]!);
      g(3, 4, 9, 14, m[sg[14]!]!, m[sg[15]!]!);
    }
    for (let i = 0; i < 8; i += 1) h[i] = h[i]! ^ v[i]! ^ v[i + 8]!;
  }
  const out = new Uint8Array(64);
  for (let i = 0; i < 8; i += 1) {
    let value = h[i]!;
    for (let j = 0; j < 8; j += 1) {
      out[i * 8 + j] = Number(value & 0xffn);
      value >>= 8n;
    }
  }
  return out;
}

export function blake2b512Hex(input: string | Uint8Array): string {
  return hex(blake2b512Bytes(toBytes(input)));
}

// ── SHA-512 / SHA-512/256 (FIPS 180-4) — the Algorand checksum hash ─────────

const SHA512_K: readonly bigint[] = [
  0x428a2f98d728ae22n, 0x7137449123ef65cdn, 0xb5c0fbcfec4d3b2fn, 0xe9b5dba58189dbbcn,
  0x3956c25bf348b538n, 0x59f111f1b605d019n, 0x923f82a4af194f9bn, 0xab1c5ed5da6d8118n,
  0xd807aa98a3030242n, 0x12835b0145706fben, 0x243185be4ee4b28cn, 0x550c7dc3d5ffb4e2n,
  0x72be5d74f27b896fn, 0x80deb1fe3b1696b1n, 0x9bdc06a725c71235n, 0xc19bf174cf692694n,
  0xe49b69c19ef14ad2n, 0xefbe4786384f25e3n, 0x0fc19dc68b8cd5b5n, 0x240ca1cc77ac9c65n,
  0x2de92c6f592b0275n, 0x4a7484aa6ea6e483n, 0x5cb0a9dcbd41fbd4n, 0x76f988da831153b5n,
  0x983e5152ee66dfabn, 0xa831c66d2db43210n, 0xb00327c898fb213fn, 0xbf597fc7beef0ee4n,
  0xc6e00bf33da88fc2n, 0xd5a79147930aa725n, 0x06ca6351e003826fn, 0x142929670a0e6e70n,
  0x27b70a8546d22ffcn, 0x2e1b21385c26c926n, 0x4d2c6dfc5ac42aedn, 0x53380d139d95b3dfn,
  0x650a73548baf63den, 0x766a0abb3c77b2a8n, 0x81c2c92e47edaee6n, 0x92722c851482353bn,
  0xa2bfe8a14cf10364n, 0xa81a664bbc423001n, 0xc24b8b70d0f89791n, 0xc76c51a30654be30n,
  0xd192e819d6ef5218n, 0xd69906245565a910n, 0xf40e35855771202an, 0x106aa07032bbd1b8n,
  0x19a4c116b8d2d0c8n, 0x1e376c085141ab53n, 0x2748774cdf8eeb99n, 0x34b0bcb5e19b48a8n,
  0x391c0cb3c5c95a63n, 0x4ed8aa4ae3418acbn, 0x5b9cca4f7763e373n, 0x682e6ff3d6b2b8a3n,
  0x748f82ee5defb2fcn, 0x78a5636f43172f60n, 0x84c87814a1f0ab72n, 0x8cc702081a6439ecn,
  0x90befffa23631e28n, 0xa4506cebde82bde9n, 0xbef9a3f7b2c67915n, 0xc67178f2e372532bn,
  0xca273eceea26619cn, 0xd186b8c721c0c207n, 0xeada7dd6cde0eb1en, 0xf57d4f7fee6ed178n,
  0x06f067aa72176fban, 0x0a637dc5a2c898a6n, 0x113f9804bef90daen, 0x1b710b35131c471bn,
  0x28db77f523047d84n, 0x32caab7b40c72493n, 0x3c9ebe0a15c9bebcn, 0x431d67c49c100d4cn,
  0x4cc5d4becb3e42b6n, 0x597f299cfc657e2an, 0x5fcb6fab3ad6faecn, 0x6c44198c4a475817n,
];
/** SHA-512/256's initial hash value (FIPS 180-4 §5.3.6.2). */
const SHA512_256_IV: readonly bigint[] = [
  0x22312194fc2bf72cn, 0x9f555fa3c84c64c2n, 0x2393b86b6f53b151n, 0x963877195940eabdn,
  0x96283ee2a88effe3n, 0xbe5e1e2553863992n, 0x2b0199fc2c85b8aan, 0x0eb72ddc81c52ca2n,
];

function sha512Core(input: Uint8Array, iv: readonly bigint[], outWords: number): Uint8Array {
  const length = input.length;
  // Padding: 0x80, zeros, 128-bit big-endian bit length; a multiple of 128.
  const padded = new Uint8Array(((length + 17 + 127) >> 7) << 7);
  padded.set(input);
  padded[length] = 0x80;
  let bits = BigInt(length) * 8n;
  for (let i = padded.length - 1; i >= padded.length - 16 && bits > 0n; i -= 1) {
    padded[i] = Number(bits & 0xffn);
    bits >>= 8n;
  }
  const h: bigint[] = iv.slice();
  const w: bigint[] = new Array<bigint>(80);
  for (let offset = 0; offset < padded.length; offset += 128) {
    for (let i = 0; i < 16; i += 1) {
      let value = 0n;
      for (let j = 0; j < 8; j += 1) value = (value << 8n) | BigInt(padded[offset + i * 8 + j]!);
      w[i] = value;
    }
    for (let i = 16; i < 80; i += 1) {
      const w15 = w[i - 15]!;
      const w2 = w[i - 2]!;
      const s0 = rotr64(w15, 1) ^ rotr64(w15, 8) ^ (w15 >> 7n);
      const s1 = rotr64(w2, 19) ^ rotr64(w2, 61) ^ (w2 >> 6n);
      w[i] = (w[i - 16]! + s0 + w[i - 7]! + s1) & MASK64;
    }
    let [a, b, c, d, e, f, g, hh] = h as [bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint];
    for (let i = 0; i < 80; i += 1) {
      const S1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
      const ch = (e & f) ^ (~e & MASK64 & g);
      const t1 = (hh + S1 + ch + SHA512_K[i]! + w[i]!) & MASK64;
      const S0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) & MASK64;
      hh = g;
      g = f;
      f = e;
      e = (d + t1) & MASK64;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) & MASK64;
    }
    h[0] = (h[0]! + a) & MASK64;
    h[1] = (h[1]! + b) & MASK64;
    h[2] = (h[2]! + c) & MASK64;
    h[3] = (h[3]! + d) & MASK64;
    h[4] = (h[4]! + e) & MASK64;
    h[5] = (h[5]! + f) & MASK64;
    h[6] = (h[6]! + g) & MASK64;
    h[7] = (h[7]! + hh) & MASK64;
  }
  const out = new Uint8Array(outWords * 8);
  for (let i = 0; i < outWords; i += 1) {
    let value = h[i]!;
    for (let j = 7; j >= 0; j -= 1) {
      out[i * 8 + j] = Number(value & 0xffn);
      value >>= 8n;
    }
  }
  return out;
}

function sha512_256Bytes(input: Uint8Array): Uint8Array {
  return sha512Core(input, SHA512_256_IV, 4);
}

export function sha512_256Hex(input: string | Uint8Array): string {
  return hex(sha512_256Bytes(toBytes(input)));
}

// ── Base58 / Base58Check (BIP-13 shape; Bitcoin and Ripple alphabets) ───────

const BASE58_BITCOIN = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE58_RIPPLE = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

function base58Map(alphabet: string): Int16Array {
  const map = new Int16Array(128).fill(-1);
  for (let i = 0; i < alphabet.length; i += 1) map[alphabet.charCodeAt(i)] = i;
  return map;
}
const BASE58_BITCOIN_MAP = base58Map(BASE58_BITCOIN);
const BASE58_RIPPLE_MAP = base58Map(BASE58_RIPPLE);

/** Decode a Base58 string to bytes (leading `1`s / `r`s become leading zero
 * bytes), or undefined on a character outside the alphabet. */
function base58Decode(text: string, map: Int16Array, zeroChar: string): Uint8Array | undefined {
  if (text === "") return undefined;
  const bytes: number[] = [];
  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i);
    const digit = code < 128 ? map[code]! : -1;
    if (digit < 0) return undefined;
    let carry = digit;
    for (let j = 0; j < bytes.length; j += 1) {
      carry += bytes[j]! * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  let leadingZeros = 0;
  while (leadingZeros < text.length && text[leadingZeros] === zeroChar) leadingZeros += 1;
  const out = new Uint8Array(leadingZeros + bytes.length);
  for (let i = 0; i < bytes.length; i += 1) out[leadingZeros + i] = bytes[bytes.length - 1 - i]!;
  return out;
}

/** Decode + verify the trailing four-byte double-SHA-256 checksum. Returns the
 * payload (version byte(s) included, checksum stripped) or undefined. */
function base58CheckDecode(text: string, ripple = false): Uint8Array | undefined {
  const decoded = ripple
    ? base58Decode(text, BASE58_RIPPLE_MAP, "r")
    : base58Decode(text, BASE58_BITCOIN_MAP, "1");
  if (!decoded || decoded.length < 5) return undefined;
  const payload = decoded.subarray(0, decoded.length - 4);
  const check = doubleSha256(payload);
  if (!bytesEqual(check, 0, decoded, decoded.length - 4, 4)) return undefined;
  return payload;
}

// ── bech32 / bech32m (BIP-173 / BIP-350) and CashAddr ───────────────────────

const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_MAP = (() => {
  const map = new Int16Array(128).fill(-1);
  for (let i = 0; i < BECH32_CHARSET.length; i += 1) map[BECH32_CHARSET.charCodeAt(i)] = i;
  return map;
})();
const BECH32_GENERATORS = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
const BECH32_CONST = 1;
const BECH32M_CONST = 0x2bc830a3;

function bech32Polymod(values: readonly number[]): number {
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i += 1) if ((top >>> i) & 1) chk ^= BECH32_GENERATORS[i]!;
  }
  return chk >>> 0;
}

function bech32HrpExpand(hrp: string): number[] {
  const out: number[] = [];
  for (let i = 0; i < hrp.length; i += 1) out.push(hrp.charCodeAt(i) >> 5);
  out.push(0);
  for (let i = 0; i < hrp.length; i += 1) out.push(hrp.charCodeAt(i) & 31);
  return out;
}

interface Bech32Decoded {
  hrp: string;
  /** 5-bit data values, checksum stripped. */
  data: number[];
  encoding: "bech32" | "bech32m";
}

/** Decode a bech32/bech32m string (mixed case rejected, per BIP-173). */
function bech32Decode(text: string): Bech32Decoded | undefined {
  if (text.length < 8 || text.length > 120) return undefined;
  if (text !== text.toLowerCase() && text !== text.toUpperCase()) return undefined;
  const lower = text.toLowerCase();
  const sep = lower.lastIndexOf("1");
  if (sep < 1 || sep + 7 > lower.length) return undefined;
  const hrp = lower.slice(0, sep);
  const values: number[] = [];
  for (let i = sep + 1; i < lower.length; i += 1) {
    const code = lower.charCodeAt(i);
    const v = code < 128 ? BECH32_MAP[code]! : -1;
    if (v < 0) return undefined;
    values.push(v);
  }
  const poly = bech32Polymod([...bech32HrpExpand(hrp), ...values]);
  const encoding = poly === BECH32_CONST ? "bech32" : poly === BECH32M_CONST ? "bech32m" : undefined;
  if (!encoding) return undefined;
  return { hrp, data: values.slice(0, values.length - 6), encoding };
}

/** 5-bit groups → 8-bit bytes (strict: no leftover bits ≥ 5, padding zero). */
function convertBits5to8(data: readonly number[]): Uint8Array | undefined {
  let acc = 0;
  let bits = 0;
  const out: number[] = [];
  for (const v of data) {
    acc = ((acc << 5) | v) & 0xffff_ffff;
    bits += 5;
    while (bits >= 8) {
      bits -= 8;
      out.push((acc >>> bits) & 0xff);
    }
  }
  if (bits >= 5 || (acc << (8 - bits)) & 0xff) return undefined;
  return Uint8Array.from(out);
}

/** A segwit address per BIP-173/350: witness version 0 must be bech32 with a
 * 20- or 32-byte program; versions 1–16 must be bech32m with 2–40 bytes. */
function isSegwitAddress(decoded: Bech32Decoded): boolean {
  if (decoded.data.length < 1) return false;
  const version = decoded.data[0]!;
  if (version > 16) return false;
  const program = convertBits5to8(decoded.data.slice(1));
  if (!program || program.length < 2 || program.length > 40) return false;
  if (version === 0) return decoded.encoding === "bech32" && (program.length === 20 || program.length === 32);
  return decoded.encoding === "bech32m";
}

// CashAddr (github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md):
// a 40-bit BCH-code checksum over the lower five bits of each prefix character,
// a zero separator, and the 5-bit payload. BigInt because the generator
// constants are 40 bits wide.
const CASHADDR_GENERATORS: readonly bigint[] = [0x98f2bc8e61n, 0x79b76d99e2n, 0xf33e5fb3c4n, 0xae2eabe2a8n, 0x1e4f43e470n];

function cashaddrPolymod(values: readonly number[]): bigint {
  let c = 1n;
  for (const d of values) {
    const c0 = c >> 35n;
    c = ((c & 0x07ffffffffn) << 5n) ^ BigInt(d);
    for (let i = 0; i < 5; i += 1) if ((c0 >> BigInt(i)) & 1n) c ^= CASHADDR_GENERATORS[i]!;
  }
  return c ^ 1n;
}

function isCashAddr(text: string): boolean {
  const lower = text.toLowerCase();
  if (text !== lower && text !== text.toUpperCase()) return false;
  const colon = lower.indexOf(":");
  if (colon < 1) return false;
  const prefix = lower.slice(0, colon);
  const payload = lower.slice(colon + 1);
  if (payload.length !== 42) return false;
  const values: number[] = [];
  for (let i = 0; i < prefix.length; i += 1) values.push(prefix.charCodeAt(i) & 0x1f);
  values.push(0);
  for (let i = 0; i < payload.length; i += 1) {
    const code = payload.charCodeAt(i);
    const v = code < 128 ? BECH32_MAP[code]! : -1;
    if (v < 0) return false;
    values.push(v);
  }
  if (cashaddrPolymod(values) !== 0n) return false;
  // Version byte: type in bits 3–6, size code in bits 0–2; 160-bit hash is 0.
  const bytes = convertBits5to8(values.slice(prefix.length + 1, values.length - 8));
  return bytes !== undefined && bytes.length === 21 && (bytes[0]! & 0x80) === 0;
}

// ── CRC16-XModem (Stellar strkeys, TON user-friendly addresses) ─────────────

function crc16Xmodem(bytes: Uint8Array, length: number): number {
  let crc = 0;
  for (let i = 0; i < length; i += 1) {
    crc ^= bytes[i]! << 8;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = crc & 0x8000 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
    }
  }
  return crc;
}

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** RFC 4648 base32, no padding, upper case only. */
function base32Decode(text: string): Uint8Array | undefined {
  let acc = 0;
  let bits = 0;
  const out: number[] = [];
  for (let i = 0; i < text.length; i += 1) {
    const v = BASE32_ALPHABET.indexOf(text[i]!);
    if (v < 0) return undefined;
    acc = ((acc << 5) | v) & 0xffff_ffff;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((acc >>> bits) & 0xff);
    }
  }
  return Uint8Array.from(out);
}

/** Stellar strkey (SEP-23): `G` + 55 base32 = 35 bytes: version 0x30 (6 << 3,
 * an ed25519 public key), 32 key bytes, CRC16-XModem little-endian. */
function isStellarAccount(text: string): boolean {
  if (text.length !== 56 || text[0] !== "G") return false;
  const bytes = base32Decode(text);
  if (!bytes || bytes.length !== 35 || bytes[0] !== 0x30) return false;
  const crc = crc16Xmodem(bytes, 33);
  return bytes[33] === (crc & 0xff) && bytes[34] === (crc >> 8);
}

const BASE64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/** base64 (either alphabet), no padding. */
function base64Decode(text: string): Uint8Array | undefined {
  let acc = 0;
  let bits = 0;
  const out: number[] = [];
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i]!;
    const v = BASE64URL_ALPHABET.indexOf(ch === "+" ? "-" : ch === "/" ? "_" : ch);
    if (v < 0) return undefined;
    acc = ((acc << 6) | v) & 0xffff_ffff;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((acc >>> bits) & 0xff);
    }
  }
  return Uint8Array.from(out);
}

/** TON user-friendly address: 48 base64(url) chars = 36 bytes: tag (0x11
 * bounceable / 0x51 non-bounceable, +0x80 for testnet), workchain, 32-byte
 * account id, CRC16-XModem big-endian over the first 34 bytes. */
function isTonAddress(text: string): boolean {
  if (text.length !== 48) return false;
  const bytes = base64Decode(text);
  if (!bytes || bytes.length !== 36) return false;
  const tag = bytes[0]! & 0x7f;
  if (tag !== 0x11 && tag !== 0x51) return false;
  const crc = crc16Xmodem(bytes, 34);
  return bytes[34] === crc >> 8 && bytes[35] === (crc & 0xff);
}

// ── EIP-55 ───────────────────────────────────────────────────────────────────

/** The mixed-case checksum form of a 40-hex address body. */
function eip55Checksum(body: string): string {
  const lower = body.toLowerCase();
  const digest = keccak256Hex(lower);
  let out = "";
  for (let i = 0; i < 40; i += 1) {
    const ch = lower[i]!;
    out += ch >= "a" && parseInt(digest[i]!, 16) >= 8 ? ch.toUpperCase() : ch;
  }
  return out;
}

// ── Address classification ───────────────────────────────────────────────────

type Classified = { chain: WalletChain; confidence: WalletConfidence };

const EVM_RE = /^0x[0-9a-fA-F]{40}$/;
const HEX64_RE = /^0x[0-9a-fA-F]{64}$/;
// Up to 110 data chars: BIP-173 caps segwit at 90, but a Cardano `addr1…`
// runs to 103 characters and the polymod does not care.
const BECH32_SHAPE_RE = /^(?:bc|tb|ltc|addr|stake|cosmos|osmo|juno|celestia|dydx|akash|kava|sei|inj|tia)1[02-9ac-hj-np-z]{6,110}$/i;
// ── SS58 (Polkadot / Kusama / Substrate) ────────────────────────────────────
//
// Base58 (Bitcoin alphabet) over: 1-byte network prefix (0–63) or a 2-byte one
// (64–16383), a 32-byte account id, and a 2-byte checksum = the first two
// bytes of blake2b-512("SS58PRE" || prefix || account). Any network prefix is
// accepted — a Kusama or a generic Substrate address is a Polkadot-family
// wallet for this module's purposes — and the label stays "Polkadot".

const SS58_PREFIX_BYTES = utf8Bytes("SS58PRE");

function isSs58Address(text: string): boolean {
  if (text.length < 46 || text.length > 49) return false;
  const raw = base58Decode(text, BASE58_BITCOIN_MAP, "1");
  if (!raw) return false;
  const first = raw[0]!;
  const prefixLength = first < 64 ? 1 : first < 128 ? 2 : 0;
  if (prefixLength === 0 || raw.length !== prefixLength + 32 + 2) return false;
  const body = raw.length - 2;
  const message = new Uint8Array(SS58_PREFIX_BYTES.length + body);
  message.set(SS58_PREFIX_BYTES);
  message.set(raw.subarray(0, body), SS58_PREFIX_BYTES.length);
  const digest = blake2b512Bytes(message);
  return digest[0] === raw[body] && digest[1] === raw[body + 1];
}

// ── Algorand ────────────────────────────────────────────────────────────────
//
// 58 base32 characters → 36 bytes: a 32-byte ed25519 public key and the LAST
// four bytes of SHA-512/256 over it.

function isAlgorandAddress(text: string): boolean {
  if (text.length !== 58) return false;
  const bytes = base32Decode(text);
  if (!bytes || bytes.length !== 36) return false;
  const digest = sha512_256Bytes(bytes.subarray(0, 32));
  return bytesEqual(digest, 28, bytes, 32, 4);
}

// ── Monero ──────────────────────────────────────────────────────────────────
//
// Monero's base58 is BLOCK-WISE: 11 encoded characters per 8 bytes, the last
// block shorter, each block big-endian. A standard address (95 chars, 69
// bytes) is a network tag, a 32-byte spend key, a 32-byte view key and a
// 4-byte checksum = the first four bytes of keccak-256 over the rest; an
// integrated address (106 chars, 77 bytes) carries an 8-byte payment id too.

/** Decoded size of a trailing block by its encoded length (index = chars). */
const MONERO_BLOCK_SIZES: readonly number[] = [0, -1, 1, 2, -1, 3, 4, 5, -1, 6, 7, 8];
/** Mainnet standard / integrated / subaddress, then testnet's three. */
const MONERO_TAGS: ReadonlySet<number> = new Set([0x12, 0x13, 0x2a, 0x35, 0x36, 0x3f]);

function moneroBase58Decode(text: string): Uint8Array | undefined {
  const out: number[] = [];
  for (let offset = 0; offset < text.length; offset += 11) {
    const block = text.slice(offset, offset + 11);
    const size = MONERO_BLOCK_SIZES[block.length] ?? -1;
    if (size <= 0) return undefined;
    let value = 0n;
    for (let i = 0; i < block.length; i += 1) {
      const code = block.charCodeAt(i);
      const digit = code < 128 ? BASE58_BITCOIN_MAP[code]! : -1;
      if (digit < 0) return undefined;
      value = value * 58n + BigInt(digit);
    }
    if (value >> BigInt(size * 8) !== 0n) return undefined;
    for (let i = size - 1; i >= 0; i -= 1) out.push(Number((value >> BigInt(i * 8)) & 0xffn));
  }
  return Uint8Array.from(out);
}

function isMoneroAddress(text: string): boolean {
  if (text.length !== 95 && text.length !== 106) return false;
  const bytes = moneroBase58Decode(text);
  if (!bytes || (bytes.length !== 69 && bytes.length !== 77) || !MONERO_TAGS.has(bytes[0]!)) return false;
  const digest = keccak256Bytes(bytes.subarray(0, bytes.length - 4));
  return bytesEqual(digest, 0, bytes, bytes.length - 4, 4);
}

const CASHADDR_RE = /^bitcoincash:[qp][02-9ac-hj-np-z]{41}$/i;
const BASE58_RUN_RE = /^[1-9A-HJ-NP-Za-km-z]{25,60}$/;
const STELLAR_RE = /^G[A-Z2-7]{55}$/;
const TON_RE = /^[EU]Q[A-Za-z0-9_+/-]{46}$/;
const ALGO_RE = /^[A-Z2-7]{58}$/;
const MONERO_RE = /^[48][1-9A-HJ-NP-Za-km-z]{94}(?:[1-9A-HJ-NP-Za-km-z]{11})?$/;

const COSMOS_HRPS: ReadonlySet<string> = new Set(["cosmos", "osmo", "juno", "celestia", "dydx", "akash", "kava", "sei", "inj", "tia"]);

function classifyBech32(candidate: string): Classified | undefined {
  const decoded = bech32Decode(candidate);
  if (!decoded) return undefined;
  switch (decoded.hrp) {
    case "bc":
    case "tb":
      return isSegwitAddress(decoded) ? { chain: "btc", confidence: "high" } : undefined;
    case "ltc":
    case "tltc":
      return isSegwitAddress(decoded) ? { chain: "ltc", confidence: "high" } : undefined;
    case "addr":
    case "stake":
      return { chain: "ada", confidence: "high" };
    default:
      return COSMOS_HRPS.has(decoded.hrp) ? { chain: "atom", confidence: "high" } : undefined;
  }
}

/** Tezos Base58Check prefixes (3 bytes) + a 20-byte hash. */
const TEZOS_PREFIXES: ReadonlyArray<readonly [number, number, number]> = [
  [6, 161, 159], // tz1
  [6, 161, 161], // tz2
  [6, 161, 164], // tz3
  [2, 90, 121], // KT1
];

function classifyBase58(candidate: string): Classified | undefined {
  const payload = base58CheckDecode(candidate);
  if (payload) {
    if (payload.length === 21) {
      switch (payload[0]) {
        case 0x00:
        case 0x05:
          return { chain: "btc", confidence: "high" };
        case 0x30:
        case 0x32:
          return { chain: "ltc", confidence: "high" };
        case 0x1e:
        case 0x16:
          return { chain: "doge", confidence: "high" };
        case 0x41:
          return { chain: "trx", confidence: "high" };
        default:
          return undefined;
      }
    }
    if (payload.length === 23) {
      for (const [a, b, c] of TEZOS_PREFIXES) {
        if (payload[0] === a && payload[1] === b && payload[2] === c) return { chain: "xtz", confidence: "high" };
      }
    }
    // A WIF (0x80/0xef + 32/33 bytes) or an extended key (78 bytes) is KEY
    // MATERIAL, never an address — findWalletKeyMaterial's business.
    return undefined;
  }
  if (candidate[0] === "r") {
    const ripple = base58CheckDecode(candidate, true);
    if (ripple && ripple.length === 21 && ripple[0] === 0x00) return { chain: "xrp", confidence: "high" };
  }
  // SS58 before the Solana fallback: a verified checksum outranks a shape.
  if (isSs58Address(candidate)) return { chain: "dot", confidence: "high" };
  // Solana: a raw ed25519 public key, 32 bytes, no checksum at all.
  if (candidate.length >= 32 && candidate.length <= 44) {
    const raw = base58Decode(candidate, BASE58_BITCOIN_MAP, "1");
    if (raw && raw.length === 32) return { chain: "sol", confidence: "low" };
  }
  return undefined;
}

/**
 * One candidate token → its chain and confidence, or undefined. Confidence is
 * the checksum's verdict: `high` where one verified, `medium` for an EVM
 * address with no case information, `low` for the shape-only chains (Solana,
 * Sui / Aptos).
 */
export function classifyWalletAddress(candidate: string): Classified | undefined {
  if (typeof candidate !== "string" || candidate.length < 25 || candidate.length > 120) return undefined;
  if (EVM_RE.test(candidate)) {
    const body = candidate.slice(2);
    if (body === body.toLowerCase() || body === body.toUpperCase()) return { chain: "evm", confidence: "medium" };
    // Mixed case that fails EIP-55 is a typo or a hash fragment, not an address.
    return eip55Checksum(body) === body ? { chain: "evm", confidence: "high" } : undefined;
  }
  if (HEX64_RE.test(candidate)) return { chain: "sui", confidence: "low" };
  if (BECH32_SHAPE_RE.test(candidate)) return classifyBech32(candidate);
  if (CASHADDR_RE.test(candidate)) return isCashAddr(candidate) ? { chain: "bch", confidence: "high" } : undefined;
  if (STELLAR_RE.test(candidate)) return isStellarAccount(candidate) ? { chain: "xlm", confidence: "high" } : undefined;
  if (TON_RE.test(candidate)) return isTonAddress(candidate) ? { chain: "ton", confidence: "high" } : undefined;
  if (BASE58_RUN_RE.test(candidate)) {
    const base58 = classifyBase58(candidate);
    // An Algorand address without an I or an O is also a Base58 run; let the
    // base32 checksum have its turn before giving up.
    if (base58 || !ALGO_RE.test(candidate)) return base58;
  }
  if (ALGO_RE.test(candidate)) return isAlgorandAddress(candidate) ? { chain: "algo", confidence: "high" } : undefined;
  if (MONERO_RE.test(candidate)) return isMoneroAddress(candidate) ? { chain: "xmr", confidence: "high" } : undefined;
  return undefined;
}

/**
 * Candidate tokenisation. Boundaries are explicit character classes rather
 * than `\b`, which treats `_` as a word character and so fails around
 * `wallet_0x…`. Each pattern's class is the alphabet of the shape it finds.
 */
const CANDIDATE_PATTERNS: ReadonlyArray<RegExp> = [
  /(?<![0-9A-Za-z])0x[0-9a-fA-F]{40}(?![0-9A-Za-z])/g,
  /(?<![0-9A-Za-z])0x[0-9a-fA-F]{64}(?![0-9A-Za-z])/g,
  /(?<![0-9A-Za-z])(?:bc|tb|ltc|addr|stake|cosmos|osmo|juno|celestia|dydx|akash|kava|sei|inj|tia)1[02-9ac-hj-np-z]{6,110}(?![0-9A-Za-z])/gi,
  /(?<![0-9A-Za-z])bitcoincash:[qp][02-9ac-hj-np-z]{41}(?![0-9A-Za-z])/gi,
  /(?<![0-9A-Za-z])[1-9A-HJ-NP-Za-km-z]{25,60}(?![0-9A-Za-z])/g,
  /(?<![0-9A-Za-z])G[A-Z2-7]{55}(?![0-9A-Za-z])/g,
  /(?<![0-9A-Za-z_+/-])[EU]Q[A-Za-z0-9_+/-]{46}(?![0-9A-Za-z_+/-])/g,
  /(?<![0-9A-Za-z])[A-Z2-7]{58}(?![0-9A-Za-z])/g,
  /(?<![0-9A-Za-z])[48][1-9A-HJ-NP-Za-km-z]{94}(?:[1-9A-HJ-NP-Za-km-z]{11})?(?![0-9A-Za-z])/g,
];

const CONFIDENCE_RANK: Record<WalletConfidence, number> = { high: 3, medium: 2, low: 1 };

/**
 * Every address-shaped token in `text` that validates for one of `chains`
 * (default DEFAULT_WALLET_CHAINS). Non-overlapping — the longer span wins, then
 * the higher confidence — and ordered by start. Scans at most 64 000 chars.
 *
 * `sui`/`apt` share a shape; a hit is reported under whichever of the two the
 * caller enabled (`sui` if both).
 */
export function findWalletAddresses(text: string, chains: readonly WalletChain[] = DEFAULT_WALLET_CHAINS): WalletAddressHit[] {
  if (typeof text !== "string" || text === "") return [];
  const haystack = text.length > SCAN_MAX_CHARS ? text.slice(0, SCAN_MAX_CHARS) : text;
  const enabled = new Set(chains);
  const hits: WalletAddressHit[] = [];
  for (const pattern of CANDIDATE_PATTERNS) {
    pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(haystack)) !== null) {
      const value = match[0];
      const classified = classifyWalletAddress(value);
      if (!classified) continue;
      let chain = classified.chain;
      if (chain === "sui" && !enabled.has("sui")) chain = "apt";
      if (!enabled.has(chain)) continue;
      hits.push({ chain, value, start: match.index, end: match.index + value.length, confidence: classified.confidence });
    }
  }
  hits.sort((a, b) => a.start - b.start || b.end - b.start - (a.end - a.start) || CONFIDENCE_RANK[b.confidence] - CONFIDENCE_RANK[a.confidence]);
  const out: WalletAddressHit[] = [];
  for (const hit of hits) {
    const last = out[out.length - 1];
    if (last && hit.start < last.end) {
      // Overlap: keep the longer span, then the more confident one.
      const lastLength = last.end - last.start;
      const hitLength = hit.end - hit.start;
      if (hitLength > lastLength || (hitLength === lastLength && CONFIDENCE_RANK[hit.confidence] > CONFIDENCE_RANK[last.confidence])) {
        out[out.length - 1] = hit;
      }
      continue;
    }
    out.push(hit);
  }
  return out;
}

/** Canonical form for hashing and equality: case is not information for an
 * EVM address (EIP-55 is a checksum over the same bytes) or a bech32 one. */
export function normalizeWalletAddress(chain: WalletChain, value: string): string {
  const trimmed = value.trim();
  switch (chain) {
    case "evm":
    case "sui":
    case "apt":
    case "ada":
    case "atom":
    case "bch":
      return trimmed.toLowerCase();
    case "btc":
    case "ltc":
      return /^(?:bc|tb|ltc|tltc)1/i.test(trimmed) ? trimmed.toLowerCase() : trimmed;
    default:
      return trimmed;
  }
}

/** Salted identity for the "My wallets" list — the list stores these, never
 * the addresses, so a prefs file cannot enumerate the person's wallets. */
export function walletAddressHash(salt: string, chain: WalletChain, value: string): string {
  return sha256Hex(`${salt}\n${chain}\n${normalizeWalletAddress(chain, value)}`);
}

/**
 * Famous, non-personal addresses a DeFi repository is full of — the zero
 * address, the big stablecoins and routers, the Solana system programs. Keyed
 * `${chain}:${normalized}`. A detector that flagged every WETH constant would
 * teach web3 developers to switch it off.
 */
export const KNOWN_CONTRACT_ADDRESSES: ReadonlySet<string> = new Set(
  (
    [
      ["evm", "0x0000000000000000000000000000000000000000"],
      ["evm", "0x000000000000000000000000000000000000dead"],
      ["evm", "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"], // WETH
      ["evm", "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"], // USDC
      ["evm", "0xdac17f958d2ee523a2206206994597c13d831ec7"], // USDT
      ["evm", "0x6b175474e89094c44da98b954eedeac495271d0f"], // DAI
      ["evm", "0x7a250d5630b4cf539739df2c5dacb4c659f2488d"], // Uniswap V2 router
      ["evm", "0xe592427a0aece92de3edee1f18e0157c02b8b0e0"], // Uniswap V3 router
      ["evm", "0x000000000022d473030f116ddee9f6b43ac78ba3"], // Permit2
      ["evm", "0x00000000000c2e074ec69a0dfb2997ba6c7d2e1e"], // ENS registry
      ["sol", "11111111111111111111111111111111"], // system program
      ["sol", "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"], // SPL token program
      ["sol", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"], // USDC mint
      ["sol", "So11111111111111111111111111111111111111112"], // wrapped SOL
      ["trx", "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"], // USDT (TRC-20)
      ["btc", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"], // genesis coinbase
    ] as ReadonlyArray<readonly [WalletChain, string]>
  ).map(([chain, value]) => `${chain}:${normalizeWalletAddress(chain, value)}`),
);

export function isKnownContractAddress(chain: WalletChain, value: string): boolean {
  return KNOWN_CONTRACT_ADDRESSES.has(`${chain}:${normalizeWalletAddress(chain, value)}`);
}

// ── Key material ─────────────────────────────────────────────────────────────

/**
 * The BIP-0039 English wordlist (bitcoin/bips, bip-0039/english.txt; sha256 of
 * the newline-separated file 2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8e
 * ff3a2ed3b24dbda), 2048 words in order — the index IS the 11-bit value.
 */
const BIP39_ENGLISH_TEXT =
  "abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act action actor actress actual adapt add addict address adjust admit adult advance advice aerobic affair afford afraid again age agent agree ahead aim air airport aisle alarm album alcohol alert alien all alley allow almost alone alpha already also alter always amateur amazing among amount amused analyst anchor ancient anger angle angry animal ankle announce annual another answer antenna antique anxiety any apart apology appear apple approve april arch arctic area arena argue arm armed armor army around arrange arrest arrive arrow art artefact artist artwork ask aspect assault asset assist assume asthma athlete atom attack attend attitude attract auction audit august aunt author auto autumn average avocado avoid awake aware away awesome awful awkward axis baby bachelor bacon badge bag balance balcony ball bamboo banana banner bar barely bargain barrel base basic basket battle beach bean beauty because become beef before begin behave behind believe below belt bench benefit best betray better between beyond bicycle bid bike bind biology bird birth bitter black blade blame blanket blast bleak bless blind blood blossom blouse blue blur blush board boat body boil bomb bone bonus book boost border boring borrow boss bottom bounce box boy bracket brain brand brass brave bread breeze brick bridge brief bright bring brisk broccoli broken bronze broom brother brown brush bubble buddy budget buffalo build bulb bulk bullet bundle bunker burden burger burst bus business busy butter buyer buzz cabbage cabin cable cactus cage cake call calm camera camp can canal cancel candy cannon canoe canvas canyon capable capital captain car carbon card cargo carpet carry cart case cash casino castle casual cat catalog catch category cattle caught cause caution cave ceiling celery cement census century cereal certain chair chalk champion change chaos chapter charge chase chat cheap check cheese chef cherry chest chicken chief child chimney choice choose chronic chuckle chunk churn cigar cinnamon circle citizen city civil claim clap clarify claw clay clean clerk clever click client cliff climb clinic clip clock clog close cloth cloud clown club clump cluster clutch coach coast coconut code coffee coil coin collect color column combine come comfort comic common company concert conduct confirm congress connect consider control convince cook cool copper copy coral core corn correct cost cotton couch country couple course cousin cover coyote crack cradle craft cram crane crash crater crawl crazy cream credit creek crew cricket crime crisp critic crop cross crouch crowd crucial cruel cruise crumble crunch crush cry crystal cube culture cup cupboard curious current curtain curve cushion custom cute cycle dad damage damp dance danger daring dash daughter dawn day deal debate debris decade december decide decline decorate decrease deer defense define defy degree delay deliver demand demise denial dentist deny depart depend deposit depth deputy derive describe desert design desk despair destroy detail detect develop device devote diagram dial diamond diary dice diesel diet differ digital dignity dilemma dinner dinosaur direct dirt disagree discover disease dish dismiss disorder display distance divert divide divorce dizzy doctor document dog doll dolphin domain donate donkey donor door dose double dove draft dragon drama drastic draw dream dress drift drill drink drip drive drop drum dry duck dumb dune during dust dutch duty dwarf dynamic eager eagle early earn earth easily east easy echo ecology economy edge edit educate effort egg eight either elbow elder electric elegant element elephant elevator elite else embark embody embrace emerge emotion employ empower empty enable enact end endless endorse enemy energy enforce engage engine enhance enjoy enlist enough enrich enroll ensure enter entire entry envelope episode equal equip era erase erode erosion error erupt escape essay essence estate eternal ethics evidence evil evoke evolve exact example excess exchange excite exclude excuse execute exercise exhaust exhibit exile exist exit exotic expand expect expire explain expose express extend extra eye eyebrow fabric face faculty fade faint faith fall false fame family famous fan fancy fantasy farm fashion fat fatal father fatigue fault favorite feature february federal fee feed feel female fence festival fetch fever few fiber fiction field figure file film filter final find fine finger finish fire firm first fiscal fish fit fitness fix flag flame flash flat flavor flee flight flip float flock floor flower fluid flush fly foam focus fog foil fold follow food foot force forest forget fork fortune forum forward fossil foster found fox fragile frame frequent fresh friend fringe frog front frost frown frozen fruit fuel fun funny furnace fury future gadget gain galaxy gallery game gap garage garbage garden garlic garment gas gasp gate gather gauge gaze general genius genre gentle genuine gesture ghost giant gift giggle ginger giraffe girl give glad glance glare glass glide glimpse globe gloom glory glove glow glue goat goddess gold good goose gorilla gospel gossip govern gown grab grace grain grant grape grass gravity great green grid grief grit grocery group grow grunt guard guess guide guilt guitar gun gym habit hair half hammer hamster hand happy harbor hard harsh harvest hat have hawk hazard head health heart heavy hedgehog height hello helmet help hen hero hidden high hill hint hip hire history hobby hockey hold hole holiday hollow home honey hood hope horn horror horse hospital host hotel hour hover hub huge human humble humor hundred hungry hunt hurdle hurry hurt husband hybrid ice icon idea identify idle ignore ill illegal illness image imitate immense immune impact impose improve impulse inch include income increase index indicate indoor industry infant inflict inform inhale inherit initial inject injury inmate inner innocent input inquiry insane insect inside inspire install intact interest into invest invite involve iron island isolate issue item ivory jacket jaguar jar jazz jealous jeans jelly jewel job join joke journey joy judge juice jump jungle junior junk just kangaroo keen keep ketchup key kick kid kidney kind kingdom kiss kit kitchen kite kitten kiwi knee knife knock know lab label labor ladder lady lake lamp language laptop large later latin laugh laundry lava law lawn lawsuit layer lazy leader leaf learn leave lecture left leg legal legend leisure lemon lend length lens leopard lesson letter level liar liberty library license life lift light like limb limit link lion liquid list little live lizard load loan lobster local lock logic lonely long loop lottery loud lounge love loyal lucky luggage lumber lunar lunch luxury lyrics machine mad magic magnet maid mail main major make mammal man manage mandate mango mansion manual maple marble march margin marine market marriage mask mass master match material math matrix matter maximum maze meadow mean measure meat mechanic medal media melody melt member memory mention menu mercy merge merit merry mesh message metal method middle midnight milk million mimic mind minimum minor minute miracle mirror misery miss mistake mix mixed mixture mobile model modify mom moment monitor monkey monster month moon moral more morning mosquito mother motion motor mountain mouse move movie much muffin mule multiply muscle museum mushroom music must mutual myself mystery myth naive name napkin narrow nasty nation nature near neck need negative neglect neither nephew nerve nest net network neutral never news next nice night noble noise nominee noodle normal north nose notable note nothing notice novel now nuclear number nurse nut oak obey object oblige obscure observe obtain obvious occur ocean october odor off offer office often oil okay old olive olympic omit once one onion online only open opera opinion oppose option orange orbit orchard order ordinary organ orient original orphan ostrich other outdoor outer output outside oval oven over own owner oxygen oyster ozone pact paddle page pair palace palm panda panel panic panther paper parade parent park parrot party pass patch path patient patrol pattern pause pave payment peace peanut pear peasant pelican pen penalty pencil people pepper perfect permit person pet phone photo phrase physical piano picnic picture piece pig pigeon pill pilot pink pioneer pipe pistol pitch pizza place planet plastic plate play please pledge pluck plug plunge poem poet point polar pole police pond pony pool popular portion position possible post potato pottery poverty powder power practice praise predict prefer prepare present pretty prevent price pride primary print priority prison private prize problem process produce profit program project promote proof property prosper protect proud provide public pudding pull pulp pulse pumpkin punch pupil puppy purchase purity purpose purse push put puzzle pyramid quality quantum quarter question quick quit quiz quote rabbit raccoon race rack radar radio rail rain raise rally ramp ranch random range rapid rare rate rather raven raw razor ready real reason rebel rebuild recall receive recipe record recycle reduce reflect reform refuse region regret regular reject relax release relief rely remain remember remind remove render renew rent reopen repair repeat replace report require rescue resemble resist resource response result retire retreat return reunion reveal review reward rhythm rib ribbon rice rich ride ridge rifle right rigid ring riot ripple risk ritual rival river road roast robot robust rocket romance roof rookie room rose rotate rough round route royal rubber rude rug rule run runway rural sad saddle sadness safe sail salad salmon salon salt salute same sample sand satisfy satoshi sauce sausage save say scale scan scare scatter scene scheme school science scissors scorpion scout scrap screen script scrub sea search season seat second secret section security seed seek segment select sell seminar senior sense sentence series service session settle setup seven shadow shaft shallow share shed shell sheriff shield shift shine ship shiver shock shoe shoot shop short shoulder shove shrimp shrug shuffle shy sibling sick side siege sight sign silent silk silly silver similar simple since sing siren sister situate six size skate sketch ski skill skin skirt skull slab slam sleep slender slice slide slight slim slogan slot slow slush small smart smile smoke smooth snack snake snap sniff snow soap soccer social sock soda soft solar soldier solid solution solve someone song soon sorry sort soul sound soup source south space spare spatial spawn speak special speed spell spend sphere spice spider spike spin spirit split spoil sponsor spoon sport spot spray spread spring spy square squeeze squirrel stable stadium staff stage stairs stamp stand start state stay steak steel stem step stereo stick still sting stock stomach stone stool story stove strategy street strike strong struggle student stuff stumble style subject submit subway success such sudden suffer sugar suggest suit summer sun sunny sunset super supply supreme sure surface surge surprise surround survey suspect sustain swallow swamp swap swarm swear sweet swift swim swing switch sword symbol symptom syrup system table tackle tag tail talent talk tank tape target task taste tattoo taxi teach team tell ten tenant tennis tent term test text thank that theme then theory there they thing this thought three thrive throw thumb thunder ticket tide tiger tilt timber time tiny tip tired tissue title toast tobacco today toddler toe together toilet token tomato tomorrow tone tongue tonight tool tooth top topic topple torch tornado tortoise toss total tourist toward tower town toy track trade traffic tragic train transfer trap trash travel tray treat tree trend trial tribe trick trigger trim trip trophy trouble truck true truly trumpet trust truth try tube tuition tumble tuna tunnel turkey turn turtle twelve twenty twice twin twist two type typical ugly umbrella unable unaware uncle uncover under undo unfair unfold unhappy uniform unique unit universe unknown unlock until unusual unveil update upgrade uphold upon upper upset urban urge usage use used useful useless usual utility vacant vacuum vague valid valley valve van vanish vapor various vast vault vehicle velvet vendor venture venue verb verify version very vessel veteran viable vibrant vicious victory video view village vintage violin virtual virus visa visit visual vital vivid vocal voice void volcano volume vote voyage wage wagon wait walk wall walnut want warfare warm warrior wash wasp waste water wave way wealth weapon wear weasel weather web wedding weekend weird welcome west wet whale what wheat wheel when where whip whisper wide width wife wild will win window wine wing wink winner winter wire wisdom wise wish witness wolf woman wonder wood wool word work world worry worth wrap wreck wrestle wrist write wrong yard year yellow you young youth zebra zero zone zoo";

export const BIP39_ENGLISH: readonly string[] = BIP39_ENGLISH_TEXT.split(" ");

const BIP39_INDEX: ReadonlyMap<string, number> = new Map(BIP39_ENGLISH.map((word, i) => [word, i]));

const MNEMONIC_LENGTHS: ReadonlySet<number> = new Set([12, 15, 18, 21, 24]);

/** 12/15/18/21/24 words, every one in the list, checksum valid (BIP-39: the
 * last ENT/32 bits are the first bits of SHA-256 over the entropy). */
export function isBip39Mnemonic(words: readonly string[]): boolean {
  if (!MNEMONIC_LENGTHS.has(words.length)) return false;
  let bits = "";
  for (const word of words) {
    const index = BIP39_INDEX.get(word.toLowerCase());
    if (index === undefined) return false;
    bits += index.toString(2).padStart(11, "0");
  }
  const checksumBits = words.length / 3;
  const entropyBits = bits.length - checksumBits;
  const entropy = new Uint8Array(entropyBits / 8);
  for (let i = 0; i < entropy.length; i += 1) entropy[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
  const digest = sha256Bytes(entropy);
  let expected = "";
  for (let i = 0; i < Math.ceil(checksumBits / 8); i += 1) expected += digest[i]!.toString(2).padStart(8, "0");
  return bits.slice(entropyBits) === expected.slice(0, checksumBits);
}

/** A run of 12–24 lowercase-ish words separated by spaces, commas or newlines;
 * a numbered list (`1. word`) is the other common backup layout. */
const WORD_RUN_RE = /(?<![A-Za-z])(?:(?:\d{1,2}[.):]\s*)?[A-Za-z]{3,8}(?:[ \t,;]+|\r?\n)){11,23}(?:\d{1,2}[.):]\s*)?[A-Za-z]{3,8}(?![A-Za-z])/g;
const WORD_RE = /[A-Za-z]{3,8}/g;

/** A Base58 run long enough to be a WIF (51/52) or an extended key (111). */
const KEY_BASE58_RE = /(?<![0-9A-Za-z])[1-9A-HJ-NP-Za-km-z]{50,112}(?![0-9A-Za-z])/g;
/** Solana's `id.json`: exactly 64 integers 0–255 in a JSON array. */
const SOLANA_KEYPAIR_RE = /\[\s*(?:\d{1,3}\s*,\s*){63}\d{1,3}\s*\]/g;
/** Web3 Secret Storage v3: a `crypto` object with `ciphertext` and `kdf`
 * within the next few hundred characters (nested `cipherparams` / `kdfparams`
 * objects sit in between, so the window is not brace-bounded). The reported
 * span is the object's opening — the keystore is one blob, not a token. */
const ETH_KEYSTORE_RE = /\\?"[cC]rypto\\?"\s*:\s*\{(?=[\s\S]{0,800}\\?"ciphertext\\?")(?=[\s\S]{0,800}\\?"kdf\\?")/g;

/** BIP-32 extended-key version bytes (big-endian) → private or public. */
const XKEY_VERSIONS: ReadonlyMap<number, "xprv" | "xpub"> = new Map<number, "xprv" | "xpub">([
  [0x0488ade4, "xprv"], [0x0488b21e, "xpub"], // x mainnet
  [0x049d7878, "xprv"], [0x049d7cb2, "xpub"], // y (BIP-49)
  [0x04b2430c, "xprv"], [0x04b24746, "xpub"], // z (BIP-84)
  [0x0295b005, "xprv"], [0x0295b43f, "xpub"], // Y (multisig P2WSH-P2SH)
  [0x02aa7a99, "xprv"], [0x02aa7ed3, "xpub"], // Z (multisig P2WSH)
  [0x04358394, "xprv"], [0x043587cf, "xpub"], // t testnet
  [0x044a4e28, "xprv"], [0x044a5262, "xpub"], // u testnet (BIP-49)
  [0x045f18bc, "xprv"], [0x045f1cf6, "xpub"], // v testnet (BIP-84)
]);

function classifyKeyBase58(candidate: string): WalletKeyKind | undefined {
  const payload = base58CheckDecode(candidate);
  if (!payload) return undefined;
  if ((payload[0] === 0x80 || payload[0] === 0xef) && (payload.length === 33 || (payload.length === 34 && payload[33] === 0x01))) {
    return "wif";
  }
  if (payload.length === 78) {
    const version = ((payload[0]! << 24) | (payload[1]! << 16) | (payload[2]! << 8) | payload[3]!) >>> 0;
    return XKEY_VERSIONS.get(version);
  }
  return undefined;
}

/**
 * Wallet KEY MATERIAL in `text`: mnemonics (checksum-verified → high; a run of
 * list words whose checksum fails is not reported at all — twelve dictionary
 * words are just prose), WIF and extended private keys (Base58Check-verified →
 * high), extended PUBLIC keys (verified → high; the caller decides how softly
 * to treat a privacy-grade shape), a Solana keypair array (high) and an
 * Ethereum keystore v3 object (medium — it is encrypted, but offline-guessable).
 * Non-overlapping, ordered by start.
 */
export function findWalletKeyMaterial(text: string): WalletKeyHit[] {
  if (typeof text !== "string" || text === "") return [];
  const haystack = text.length > SCAN_MAX_CHARS ? text.slice(0, SCAN_MAX_CHARS) : text;
  const hits: WalletKeyHit[] = [];

  KEY_BASE58_RE.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = KEY_BASE58_RE.exec(haystack)) !== null) {
    const kind = classifyKeyBase58(match[0]);
    if (kind) hits.push({ kind, start: match.index, end: match.index + match[0].length, confidence: "high" });
  }

  SOLANA_KEYPAIR_RE.lastIndex = 0;
  while ((match = SOLANA_KEYPAIR_RE.exec(haystack)) !== null) {
    const numbers = match[0].match(/\d{1,3}/g) ?? [];
    if (numbers.length === 64 && numbers.every((n) => Number(n) <= 255)) {
      hits.push({ kind: "solana_keypair", start: match.index, end: match.index + match[0].length, confidence: "high" });
    }
  }

  ETH_KEYSTORE_RE.lastIndex = 0;
  while ((match = ETH_KEYSTORE_RE.exec(haystack)) !== null) {
    hits.push({ kind: "eth_keystore", start: match.index, end: match.index + match[0].length, confidence: "medium" });
  }

  WORD_RUN_RE.lastIndex = 0;
  while ((match = WORD_RUN_RE.exec(haystack)) !== null) {
    const run = match[0];
    // Word positions inside the run. WORD_RUN_RE is greedy, so the run may
    // begin with ordinary prose ("seed phrase abandon …") and continue past
    // the phrase; every start offset and every valid length is tried, longest
    // first, so a 24-word phrase is never reported as its first 12 words.
    const positions: Array<{ word: string; at: number }> = [];
    WORD_RE.lastIndex = 0;
    let w: RegExpExecArray | null;
    while ((w = WORD_RE.exec(run)) !== null) positions.push({ word: w[0], at: w.index });
    let from = 0;
    while (positions.length - from >= 12) {
      let matched = false;
      for (const length of [24, 21, 18, 15, 12]) {
        if (positions.length - from < length) continue;
        const phrase = positions.slice(from, from + length);
        if (!isBip39Mnemonic(phrase.map((p) => p.word))) continue;
        const first = phrase[0]!;
        const last = phrase[length - 1]!;
        hits.push({
          kind: "bip39_mnemonic",
          start: match.index + first.at,
          end: match.index + last.at + last.word.length,
          confidence: "high",
          words: length,
        });
        from += length;
        matched = true;
        break;
      }
      if (!matched) from += 1;
    }
  }

  hits.sort((a, b) => a.start - b.start || b.end - a.end);
  const out: WalletKeyHit[] = [];
  for (const hit of hits) {
    const last = out[out.length - 1];
    if (last && hit.start < last.end) continue;
    out.push(hit);
  }
  return out;
}

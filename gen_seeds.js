#!/usr/bin/env node
"use strict";

/**
 * gen_seeds.js -- generate N BIP-39 seed phrases with Math.random() as the
 * entropy source, i.e. exactly the way an insecure crypto wallet does it.
 *
 * Usage:
 *   node gen_seeds.js [N] [--words 12|15|18|21|24] [--out seeds.txt] [--seed-hex]
 *
 *   N            number of mnemonics to generate            (default 10)
 *   --words W    mnemonic length, multiple of 3             (default 12)
 *   --out FILE   output .txt, one mnemonic per line         (default seeds.txt)
 *   --seed-hex   also append each mnemonic's 512-bit BIP-39 seed
 *                (PBKDF2-HMAC-SHA512, 2048 rounds, empty passphrase)
 *                as an indented hex line under the phrase
 *
 * The entropy itself is drawn the insecure way:
 *
 *     byte = Math.floor(Math.random() * 256)
 *
 * V8 implements Math.random() with xorshift128+ and a 64-bit seed, so every
 * phrase in the output file -- no matter how many -- comes from at most one
 * of 2^64 possible streams. 4-6 leaked doubles from the same browser context
 * pin that stream down completely (see poc.py / bip39_poc.py in this repo).
 *
 * Note: floor(Math.random()*256) is exactly uniform over 0..255 because
 * 2^53/256 = 2^45: each byte value corresponds to exactly 2^45 raw mantissa
 * values. The weakness here is the 64-bit seed and the generator's
 * linearity, not per-byte bias (contrast Math.random()*26 in the Qubic
 * wallet, which does have a small modulo bias on top of everything else).
 *
 * Everything after the entropy draw is standard BIP-39: SHA-256 checksum of
 * ENT/32 bits appended to the entropy, bit string sliced into 11-bit word
 * indices, wordlist = bip39_english.txt (official english.txt, SHA-256
 * 2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda).
 *
 * Deterministic runs (handy for tests / the PoCs in this repo):
 *   node --random-seed=42 gen_seeds.js 5 --out five.txt
 * writes the same five phrases on every invocation.
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const WORDLIST_PATH = path.join(__dirname, "bip39_english.txt");

function usage() {
  console.log(`usage: node gen_seeds.js [N] [--words 12|15|18|21|24] [--out FILE] [--seed-hex]

  N            number of mnemonics to generate            (default 10)
  --words W    mnemonic length, multiple of 3             (default 12)
  --out FILE   output .txt, one mnemonic per line         (default seeds.txt)
  --seed-hex   append each 512-bit BIP-39 seed (hex) under its phrase
`);
}

function die(msg) {
  console.error(`gen_seeds: ${msg}`);
  process.exit(1);
}

function parseArgs(argv) {
  const o = { n: 10, words: 12, out: "seeds.txt", seedHex: false, rest: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--words") o.words = Number(argv[++i]);
    else if (a === "--out") o.out = argv[++i];
    else if (a === "--seed-hex") o.seedHex = true;
    else if (a === "-h" || a === "--help") { usage(); process.exit(0); }
    else o.rest.push(a);
  }
  if (o.rest.length > 0) {
    const n = Number(o.rest[0]);
    if (!Number.isInteger(n) || n < 0) die(`N must be a non-negative integer, got "${o.rest[0]}"`);
    o.n = n;
  }
  if (!Number.isInteger(o.words) || o.words < 12 || o.words > 24 || o.words % 3 !== 0) {
    die(`--words must be one of 12, 15, 18, 21, 24 (got ${o.words})`);
  }
  if (typeof o.out !== "string" || o.out.length === 0) die("--out needs a file name");
  return o;
}

function loadWordlist() {
  let raw;
  try {
    raw = fs.readFileSync(WORDLIST_PATH, "utf8");
  } catch {
    die(`wordlist not found at ${WORDLIST_PATH} (run bip39_poc.py once, or download
https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt)`);
  }
  const words = raw.split(/\r?\n/).map((w) => w.trim()).filter(Boolean);
  if (words.length !== 2048) {
    die(`wordlist at ${WORDLIST_PATH} has ${words.length} words, expected 2048`);
  }
  return words;
}

// The insecure entropy source: one byte per Math.random() call.
function drawByte() {
  return Math.floor(Math.random() * 256);
}

// Standard BIP-39: entropy -> (entropy || SHA-256(entropy)[:CS bits])
// -> 11-bit indices -> words. CS = ENT/32, ENT = 32*W/3.
function generateMnemonic(wordlist, nWords) {
  const entBits = (32 * nWords) / 3;
  const csBits = entBits / 32;
  const entropy = Buffer.alloc(entBits / 8);
  for (let i = 0; i < entropy.length; i++) entropy[i] = drawByte();

  const hash = crypto.createHash("sha256").update(entropy).digest();
  const checksum = hash[0] >>> (8 - csBits); // csBits <= 8

  const bits = (BigInt("0x" + entropy.toString("hex")) << BigInt(csBits))
    | BigInt(checksum);

  const out = [];
  for (let i = 0; i < nWords; i++) {
    const idx = Number((bits >> BigInt((nWords - 1 - i) * 11)) & 2047n);
    out.push(wordlist[idx]);
  }
  return out.join(" ");
}

// BIP-39 seed: PBKDF2-HMAC-SHA512(NFKD(mnemonic), "mnemonic"+passphrase,
// 2048, 64 bytes). The english wordlist is ASCII, so NFKD is a no-op here.
function bip39Seed(mnemonic, passphrase = "") {
  return crypto.pbkdf2Sync(
    Buffer.from(mnemonic, "utf8"),
    Buffer.from("mnemonic" + passphrase, "utf8"),
    2048, 64, "sha512"
  );
}

function main() {
  const o = parseArgs(process.argv.slice(2));
  const wordlist = loadWordlist();

  const lines = [];
  for (let i = 0; i < o.n; i++) {
    const m = generateMnemonic(wordlist, o.words);
    if (o.seedHex) {
      lines.push(m, "    " + bip39Seed(m).toString("hex"));
    } else {
      lines.push(m);
    }
  }

  const body = o.n === 0 ? "" : lines.join("\n") + "\n";
  fs.writeFileSync(o.out, body);

  const entBits = (32 * o.words) / 3;
  console.error(`gen_seeds: wrote ${o.n} x ${o.words}-word BIP-39 mnemonic${o.n === 1 ? "" : "s"}` +
    ` (${entBits}-bit entropy, Math.random()-drawn) -> ${o.out}` +
    (o.seedHex ? " [+512-bit seeds]" : ""));
  console.error(`gen_seeds: every phrase above comes from one of at most 2^64` +
    ` V8 Math.random() streams -- treat this file as public knowledge.`);
}

main();

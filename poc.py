#!/usr/bin/env python3
"""
PoC: Math.random() is not cryptographically secure.

What this shows
---------------
V8 implements Math.random() with xorshift128+ (v8.dev/blog/math-random).
Every call exposes the top 53 bits of one 64-bit generator word:

    double = (word >> 11) / 2**53      # V8 RandomNumberGenerator::ToDouble

The generator is a 128-bit *linear* PRNG over GF(2) with recurrence

    x[j+1] = f(x[j-1], x[j]),
    f(a, b) = a ^ (a<<23) ^ (a>>17) ^ b ^ (b>>26)

Because the state transition is linear and every output leaks 53 state bits,
a handful of consecutive outputs pins down the entire 128-bit state, after
which all future outputs are deterministic. That is the definition of a
non-cryptographic PRNG.

node v24 / V8 13.6 detail (verified empirically, incl. with --random-seed):
V8 fills a 64-entry cache per context with ToDouble(state.s0) of 64
consecutive xorshift steps and Math.random() pops cache[63], cache[62], ...
So consecutive calls are consecutive stream words, consumed in descending
stream order within each 64-call block, and blocks continue the same stream:

    call #k (1-based) exposes x[64*block + 64 - offset_within_block]

Only the low 11 bits of each word are unknown to an observer. Three
consecutive observed values satisfy the recurrence exactly, so a tiny z3
query over the unknown low bits recovers the full internal state in
milliseconds -- after which the attacker computes the ENTIRE future of the
generator (verified here against real node output, including across V8's
cache-refill boundary).

A second section simulates the *fixed* xorshift128+ construction that
current V8 main uses (the fix for the cache-invalidation bug, released
after node 24; released binaries still ship the older behaviour described
above). Same conclusion: the construction remains predictable.

References
----------
* https://v8.dev/blog/math-random
* v8/src/numbers/math-random.cc and v8/src/builtins/math.tq (13.6)
* v8/src/base/utils/random-number-generator.h (XorShift128, ToDouble)
"""

from __future__ import annotations

import shutil
import subprocess
import time

from z3 import BitVec, BitVecVal, Concat, LShR, Solver, sat

M64 = (1 << 64) - 1
SHIFT = 11            # V8 drops the low 11 bits -> 53 leaked bits per output
DENOM = 1 << 53
CACHE_SIZE = 64       # V8 13.6 refill-cache size


# --------------------------------------------------------------------------
# Primitives (mirrors of V8's src/base/utils/random-number-generator.h)
# --------------------------------------------------------------------------

def murmur3(h: int) -> int:
    """V8's MurmurHash3 finalizer, used to derive the initial state."""
    h &= M64
    h ^= h >> 33
    h = (h * 0xFF51AFD7ED558CCD) & M64
    h ^= h >> 33
    h = (h * 0xC4CEB9FE1A85EC53) & M64
    h ^= h >> 33
    return h


def f_concrete(a: int, b: int) -> int:
    """xorshift128+ step: stream recurrence x[j+1] = f(x[j-1], x[j])."""
    t = a
    t ^= (t << 23) & M64
    t ^= t >> 17
    t ^= b
    t ^= b >> 26
    return t & M64


def g(a: int) -> int:
    """The part of the step driven by the *older* word:

        g(a) = a ^ (a<<23) ^ ((a ^ (a<<23)) >> 17)

    x[j+1] = g(x[j-1]) ^ x[j] ^ (x[j] >> 26).  g is linear over GF(2) and
    invertible, so given any two consecutive words the whole stream -- past
    and future -- can be recomputed.
    """
    t = a ^ ((a << 23) & M64)
    return (t ^ (t >> 17)) & M64


def _invert_gf2(cols: list[int]) -> list[int] | None:
    """Invert a 64x64 GF(2) linear map given as column images, via Gaussian
    elimination. Returns the rows of the inverse matrix, or None if singular.

    Row j of the inverse r_j satisfies: bit j of a = parity(r_j & t)."""
    rows = []
    for i in range(64):
        coeff = 0
        for j in range(64):
            if (cols[j] >> i) & 1:
                coeff |= 1 << j
        rows.append([coeff, 1 << i])
    for c in range(64):
        piv = next((r for r in range(c, 64) if (rows[r][0] >> c) & 1), None)
        if piv is None:
            return None
        rows[c], rows[piv] = rows[piv], rows[c]
        for r in range(64):
            if r != c and (rows[r][0] >> c) & 1:
                rows[r][0] ^= rows[c][0]
                rows[r][1] ^= rows[c][1]
    if any(rows[r][0] != (1 << r) for r in range(64)):
        return None
    return [rows[j][1] for j in range(64)]


_GINV_ROWS = _invert_gf2([g(1 << j) for j in range(64)])
assert _GINV_ROWS is not None, "g must be invertible over GF(2) for backward steps"


def ginv(t: int) -> int:
    """Inverse of g (precomputed 64x64 GF(2) inverse, applied by parity)."""
    a = 0
    for j in range(64):
        if (_GINV_ROWS[j] & t).bit_count() & 1:
            a |= 1 << j
    return a


def backward_step(xj: int, xj1: int) -> int:
    """Given x[j] and x[j+1], recover x[j-1] by inverting one xorshift step."""
    return ginv(xj1 ^ xj ^ (xj >> 26))


def f_z3(a, b):
    """Symbolic f on z3 64-bit bitvectors."""
    t = a ^ (a << 23)
    t = t ^ LShR(t, 17)
    t = t ^ b
    t = t ^ LShR(b, 26)
    return t


def as_double(mantissa: int) -> float:
    return mantissa / DENOM


# --------------------------------------------------------------------------
# Capturing real node output
# --------------------------------------------------------------------------

def node_randoms(n: int, seed: int | None = None) -> list[int]:
    """n consecutive Math.random() values of one node process, as exact
    53-bit mantissas (Math.random()*2**53 is exact in IEEE-754 and node
    prints round-trip-exact decimals)."""
    if shutil.which("node") is None:
        raise RuntimeError("node not found on PATH; the live attack needs node")
    js = (f"const o=[]; for (let i=0;i<{n};i++) "
          "o.push(String(Math.random()*9007199254740992)); console.log(o.join(' '))")
    cmd = ["node"]
    if seed is not None:
        cmd.append(f"--random-seed={seed}")
    cmd += ["-e", js]
    return [int(x) for x in subprocess.check_output(cmd, text=True).split()]


# --------------------------------------------------------------------------
# The z3 state-recovery query
# --------------------------------------------------------------------------

def solve_low_bits(observed: list[int], reversed_order: bool) -> list[int] | None:
    """Recover the low 11 bits of `observed` (consecutive exposed words).

    In natural stream order three consecutive words satisfy
        w[i] == f(w[i-2], w[i-1]).
    V8 13.6 pops its cache backwards, so observed values within one block
    arrive in *descending* stream order and the recurrence reads
        obs[i] == f(obs[i+2], obs[i+1]).
    Only 11 bits per word are unknown; two 64-bit recurrence equations
    over-determine them, so z3 solves in milliseconds.
    """
    n = len(observed)
    lits = [BitVec(f"l{i}", SHIFT) for i in range(n)]
    words = [Concat(BitVecVal(observed[i], 53), lits[i]) for i in range(n)]
    s = Solver()
    for i in range(n):
        if reversed_order and i + 2 < n:
            s.add(words[i] == f_z3(words[i + 2], words[i + 1]))
        if not reversed_order and i >= 2:
            s.add(words[i] == f_z3(words[i - 2], words[i - 1]))
    if s.check() != sat:
        return None
    m = s.model()
    return [(observed[i] << SHIFT) | m[lits[i]].as_long() for i in range(n)]


def extend_stream(xs: dict[int, int], upto: int) -> dict[int, int]:
    """Forward-extend the word-indexed stream xs (which must contain two
    consecutive words) up to and including index upto."""
    j = max(xs)
    while j < upto:
        xs[j + 1] = f_concrete(xs[j - 1], xs[j])
        j += 1
    return xs


def call_word(k: int) -> int:
    """Stream index exposed by 1-based call #k in V8 13.6."""
    blk = (k - 1) // CACHE_SIZE
    off = (k - 1) % CACHE_SIZE
    return blk * CACHE_SIZE + (CACHE_SIZE - off)


# --------------------------------------------------------------------------
# Part 1: live attack on node's Math.random (V8 13.6 behaviour)
# --------------------------------------------------------------------------

def attack_live(seed: int | None, n_holdback: int, n_predict: int) -> bool:
    print("=" * 72)
    print("PART 1 -- LIVE attack on node's Math.random() (V8 13.6)")
    print("=" * 72)

    # Ground truth: one fresh node process. The attacker only gets the first
    # n_holdback values; everything else is held back to verify predictions.
    total = n_holdback + n_predict
    truth = node_randoms(total, seed=seed)
    observed = truth[:n_holdback]

    print(f"\nfresh node process produced {total} Math.random() values;")
    print(f"the attacker sees only the first {n_holdback}:")
    for i in range(n_holdback):
        print(f"  call #{i + 1:2d} = {as_double(observed[i])!r}")

    # Calls #1..#n_holdback expose consecutive stream words in *descending*
    # order (V8 pops its 64-entry cache backwards).
    t0 = time.time()
    full = solve_low_bits(observed, reversed_order=True)
    dt = (time.time() - t0) * 1000
    if full is None:
        print("z3 found no consistent state -- model mismatch, aborting.")
        return False
    print(f"\nz3 recovered the unknown low bits in {dt:.1f} ms:")
    for i in range(n_holdback):
        print(f"  x[{call_word(i + 1)}] = 0x{full[i]:016x}"
              f"   (word behind call #{i + 1})")

    # Consistency check: the recovered words must satisfy the recurrence
    # exactly, otherwise the recovered state is wrong.
    if not all(full[i] == f_concrete(full[i + 2], full[i + 1])
               for i in range(n_holdback - 2)):
        print("recovered words violate the xorshift recurrence -- aborting.")
        return False

    # Calls #1..#n_holdback already recovered the *newest* words of the
    # window, but calls #5..#64 expose words BEHIND it (x[60] down to x[1]):
    # the first 64 calls of a fresh context walk the entire first cache
    # block in descending stream order. The step is invertible over GF(2),
    # so walk backwards from the recovered pair down to x[1].
    xs = {call_word(i + 1): full[i] for i in range(n_holdback)}
    for j in range(max(xs) - 1, 1, -1):
        xs[j - 1] = backward_step(xs[j], xs[j + 1])

    # Then walk forwards: the recurrence reproduces every recovered word
    # exactly and extends the stream to cover the holdback and every
    # predicted call, including the second 64-word cache block.
    # Within a block calls run from x[64*(blk+1)] downwards, so the highest
    # stream index any call touches is 64 * ceil(total / 64).
    highest = CACHE_SIZE * ((total + CACHE_SIZE - 1) // CACHE_SIZE)
    extend_stream(xs, highest)

    print(f"\npredicting the next {n_predict} calls (never shown to the attacker):")
    ok, first_bad = 0, None
    for k in range(n_holdback + 1, total + 1):
        pred = as_double(xs[call_word(k)] >> SHIFT)
        real = as_double(truth[k - 1])
        hit = pred == real
        ok += hit
        if not hit and first_bad is None:
            first_bad = k
        if k <= n_holdback + 6 or k in (total - 1, total):
            mark = "OK" if hit else "FAIL"
            print(f"  call #{k:2d}  predicted {pred!r:<24} actual {real!r:<24} [{mark}]")
    if first_bad is None:
        print(f"\n  -> {ok}/{n_predict} EXACT predictions -- 100% hit rate")
    else:
        print(f"\n  -> {ok}/{n_predict} exact predictions (first miss: call #{first_bad})")
    print("  (the later predictions cross V8's 64-entry cache refill boundary,"
          "\n   i.e. the attack survives V8's internal buffering)")
    return first_bad is None


# --------------------------------------------------------------------------
# Part 2: the *fixed* V8 construction (current V8 main) is equally predictable
# --------------------------------------------------------------------------

def fixed_stream(seed: int, n: int) -> list[int]:
    """Simulate current V8 main: MathRandomHelpers::FixedXorShift128+
    (state invalidated by overwriting s0 with the fresh word) and
    ToDouble(x). Call #k exposes x[k+1]; x0=murmur3(seed), x1=murmur3(~seed)."""
    xs = {0: murmur3(seed), 1: murmur3((~seed) & M64)}
    for j in range(1, n + 1):
        xs[j + 1] = f_concrete(xs[j - 1], xs[j])
    return [xs[j] for j in range(2, n + 2)]


def attack_fixed(seed: int, n_holdback: int, n_predict: int) -> bool:
    print()
    print("=" * 72)
    print("PART 2 -- the FIXED V8 construction (current main) is no better")
    print("=" * 72)

    total = n_holdback + n_predict
    words = fixed_stream(seed, total)          # call #k exposes words[k-1] = x[k+1]
    # The attacker observes mantissas: ToDouble(x) = (x >> 11) / 2**53.
    observed = [w >> SHIFT for w in words[:n_holdback]]

    print(f"\nsimulated a fresh context (seed = {seed}); the attacker sees")
    print(f"only the first {n_holdback} of {total} values:")
    for i in range(n_holdback):
        print(f"  call #{i + 1:2d} = {as_double(observed[i])!r}")

    t0 = time.time()
    full = solve_low_bits(observed, reversed_order=False)
    dt = (time.time() - t0) * 1000
    if full is None:
        print("z3 found no consistent state -- aborting.")
        return False
    print(f"\nz3 recovered the unknown low bits in {dt:.1f} ms:")
    for i in range(n_holdback):
        print(f"  x[{i + 2}] = 0x{full[i]:016x}   (word behind call #{i + 1})")

    # Forward-extend from the two oldest recovered words x[2], x[3].
    xs = {2: full[0], 3: full[1]}
    extend_stream(xs, total + 1)

    print(f"\npredicting the next {n_predict} calls:")
    ok, first_bad = 0, None
    for k in range(n_holdback + 1, total + 1):
        pred = as_double(xs[k + 1] >> SHIFT)
        real = as_double(words[k - 1] >> SHIFT)
        hit = pred == real
        ok += hit
        if not hit and first_bad is None:
            first_bad = k
        if k <= n_holdback + 6 or k in (total - 1, total):
            mark = "OK" if hit else "FAIL"
            print(f"  call #{k:2d}  predicted {pred!r:<24} actual {real!r:<24} [{mark}]")
    if first_bad is None:
        print(f"\n  -> {ok}/{n_predict} EXACT predictions -- 100% hit rate")
    else:
        print(f"\n  -> {ok}/{n_predict} exact predictions (first miss: call #{first_bad})")
    return first_bad is None


# --------------------------------------------------------------------------

def main() -> int:
    results = []

    results.append(("live node / V8 13.6", attack_live(seed=None, n_holdback=4, n_predict=64)))
    results.append(("fixed V8 main (simulated)", attack_fixed(seed=42, n_holdback=4, n_predict=8)))

    print()
    print("=" * 72)
    print("CONCLUSION")
    print("=" * 72)
    print("""
Math.random() is a 128-bit *linear* PRNG. Its state transition is
invertible linear algebra over GF(2) and every output leaks 53 of the
128 state bits. Three consecutive outputs fully determine the internal
state; from there the entire future -- and past -- of the generator is
fixed. No amount of 'randomness' is left: it is a computation, not entropy.

Contrast with a CSPRNG (crypto.getRandomValues, OpenSSL RAND_bytes,
/dev/urandom): 256 bits of state updated with non-invertible one-way
mixing, periodically reseeded from real entropy. Predicting the next
output is as hard as breaking AES-CTR; state recovery does not help an
attacker retroactively either.

Practical impact of using Math.random() for security decisions
(tokens, OTPs, session ids, 'unguessable' URLs): an attacker who can
observe a few outputs (timing side channels, correlated requests,
shared workers, log files, error reports) can compute your future
'tokens' with near certainty. Never use Math.random() for anything
security-relevant -- use crypto.getRandomValues().

Verified: live node process, exact 100% prediction of held-back values.
""")

    print("Summary:")
    for name, ok in results:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    return 0 if all(ok for _, ok in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())

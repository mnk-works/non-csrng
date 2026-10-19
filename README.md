# `Math.random()` is not a CSPRNG

A hands-on proof of concept, in Python, that JavaScript's `Math.random()`
is **not cryptographically secure**: from **4 observed outputs** of a real,
freshly-started `node` process, an attacker recovers the generator's full
128-bit internal state and predicts **every future output exactly**
(64/64 = 100% hit rate in this PoC), including across V8's internal
64-entry cache-refill boundary.

## TL;DR

```
$ uv run python poc.py

PART 1 -- LIVE attack on node's Math.random() (V8 13.6)
  attacker sees only the first 4 of 68 Math.random() values
  z3 recovered the unknown low bits in 5.8 ms
  -> 64/64 EXACT predictions -- 100% hit rate
```

`Math.random()` is a 128-bit *linear* PRNG (xorshift128+). Its state
transition is invertible linear algebra over GF(2) and every output leaks
53 of the 128 state bits. A few consecutive outputs fully determine the
internal state; from there the entire future -- and past -- of the
generator is fixed. It is a computation, not entropy.

**Never use `Math.random()` for tokens, OTPs, session ids, "unguessable"
URLs, or anything else security-relevant. Use `crypto.getRandomValues()`.**

## How the attack works

### 1. Every call leaks 53 state bits

V8 implements `Math.random()` with xorshift128+ over a 128-bit state.
Each call converts one 64-bit generator word to a double:

```
double = (word >> 11) / 2**53        # RandomNumberGenerator::ToDouble
```

i.e. each output *is* the top 53 bits of an internal state word. The low
11 bits are the only unknowns.

### 2. A tiny z3 query recovers the full state

The generator is linear over GF(2) with recurrence

```
x[j+1] = f(x[j-1], x[j])
f(a,b) = a ^ (a<<23) ^ ((a ^ (a<<23)) >> 17) ^ b ^ (b>>26)
```

Three consecutive observed words satisfy this recurrence exactly, so a
z3 query over just the 4 x 11 = 44 unknown low bits recovers them in
milliseconds (over-determined: 128 bits of equations, 44 unknowns).

### 3. The step is invertible -- so the whole stream falls

`g(a) = a ^ (a<<23) ^ ((a ^ (a<<23)) >> 17)` is an invertible GF(2)
linear map (proved constructively in the PoC by Gaussian elimination over
a 64x64 GF(2) matrix). Given two consecutive words the attacker therefore
walks the stream *backwards* to the beginning of the cache block, and
*forwards* forever:

```
x[j-1] = ginv(x[j+1] ^ x[j] ^ (x[j] >> 26))      # backward step
x[j+1] = f(x[j-1], x[j])                         # forward step
```

### 4. Surviving V8's internals (node v24 / V8 13.6)

V8 13.6 fills a 64-entry cache per context and pops it backwards, so
calls within a block arrive in *descending* stream order, and each block
continues the same stream:

```
call #k (1-based) exposes x[64*block + 64 - offset_within_block]
```

The PoC handles this ordering, crosses the refill boundary (calls #65+),
and still predicts every held-back value exactly.

### 5. The fixed construction is no better

Current V8 main fixes a cache-invalidation quirk of 13.6, but the
construction remains a linear PRNG leaking 53 bits per output. Part 2 of
the PoC simulates the fixed behaviour and recovers/predicts it with the
same ease. The problem is not a bug -- it is the design. `Math.random()`
is a *statistical* PRNG and cannot be made secure by tweaking it.

## Running it

Requirements: [`uv`](https://docs.astral.sh/uv/), `node` on `PATH` (for
the live attack; tested with node v24 / V8 13.6).

```
uv run python poc.py
```

The script

1. spawns a fresh `node` process, takes 68 `Math.random()` values, shows
   the attacker only the first 4, and z3-recovers the state from them
   (~10 ms),
2. predicts the remaining 64 held-back values and verifies them against
   the real node output -- including the 4 values that live beyond the
   cache-refill boundary,
3. simulates the fixed V8-main construction and repeats the attack,
4. prints the verdict:

```
Summary:
  [PASS] live node / V8 13.6
  [PASS] fixed V8 main (simulated)
```

`--random-seed` reproducibility note: the attack does not need to know
(or guess) the seed; it works purely from observed outputs.

## Repository layout

| file            | purpose                                        |
| --------------- | ---------------------------------------------- |
| `poc.py`        | the whole attack: model, z3 recovery, GF(2) inversion, verification |
| `pyproject.toml`| `uv` project; only dependency is `z3-solver`   |
| `uv.lock`       | locked dependency set (`uv` manages it)        |

## References

* v8.dev blog: [Math.random()](https://v8.dev/blog/math-random)
* V8 sources: `src/numbers/math-random.cc`, `src/builtins/math.tq` (13.6),
  `src/base/utils/random-number-generator.h` (XorShift128, ToDouble)
* V8 main fix for the 13.6 cache quirk: commit `99f60617`
* Lemire, O'Neill: *On the insecurity of xorshift128+* (the original
  prediction attack motivation)

## Disclaimer

This PoC is published for education and defensive engineering. It
demonstrates why `Math.random()` must never be used for security purposes.
Do not use it to attack systems you do not own.

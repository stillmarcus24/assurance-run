# Independent reproduction: `tersignhq/evidence-record-conformance` v0.5.3

**69 of 69 vectors agree, on verdict and on reject reason, from a verifier written here
with no shared code.**

Tersign published four criteria for any Phase 1 evidence-record corpus
([x402-foundation/tsc#4](https://github.com/x402-foundation/tsc/issues/4), 2026-09-28) and
named the one their suite does not yet meet:

> A corpus run only by implementations that share code or authors is not reproduced. No
> verifier, ours included, is the reference. […] to our knowledge no implementation we did
> not write has run the full set.

This is that run.

**Stated precisely, because the weaker claim is the true one:** this is not the first outside
verifier to touch the corpus. Their README at `0eda303` records that @Tetsurohhori's verifier
has run `p18`, `n25` and `n26`, and that outside parties have re-run *their* engine
byte-identically. What had not happened as of 2026-09-28 is a run of the **full set** by an
implementation sharing no code and no authors. That is what this is, and the distinction is
theirs, not a hedge added here.

| | |
|---|---|
| Corpus | `tersignhq/evidence-record-conformance` @ `0eda303`, MANIFEST version `0.5.3` |
| Vectors | 69 |
| Agreement | **69 / 69** — verdict **and** reject reason |
| Disagreements | 0 |
| Reject reasons exercised | 10 of 10 |
| Kinds two-sided in this run | 11 of 11 |
| Vectors where our verifier raised instead of returning a verdict | 0 |

```
node tersign-reproduction.cjs --self-test           # 24 structural + 8 crypto known answers
node tersign-reproduction.cjs <corpus-dir> --policy-matrix   # both undecided readings
node tersign-reproduction.cjs <corpus-dir>          # the run
node tersign-reproduction.cjs <corpus-dir> --json   # machine-readable
```

Runs on `node` + `viem` (for keccak256). No network. Reads the corpus only.

## What is independent about it, stated precisely

`verify.py` was **not read** while writing `tersign-reproduction.cjs`. Every criterion was
implemented from `MANIFEST.json`'s normative fields and `README.md`'s class table, plus the
vectors' own inputs. Theirs is Python; this is Node — a reader can check the separation
rather than take it.

What is **not** ours and is named so nobody has to guess: `keccak256` comes from `viem`,
`sha256` from `node:crypto`. The JSON parser and the RFC 8785 canonicalizer are written in
this file.

### Why a hand-written JSON parser, and not `JSON.parse`

Two vectors are unrepresentable after `JSON.parse`, by design, and a verifier built on it
passes them without ever evaluating the class they exist to catch:

- **n35 / n38** carry the wire tokens `2.0` and `3.0`. `JSON.parse` collapses both to the
  integers `2` and `3`, so the number-*token* boundary disappears.
- **n2** carries integer-like object keys. A JS engine hoists those into ascending numeric
  order on object rebuild, silently defeating sort-then-stringify — RFC 8785 §3.2.3 orders
  by UTF-16 code unit, so `"1" < "10" < "2"`.

So the parser keeps key insertion order, keeps numbers as their source token, and rejects
duplicate names.

## Controls

A green run by a verifier that cannot discriminate proves nothing. Three controls, all
reproducible from this repo.

### Control A — blind run

Every `expect` and `reason` deleted from the vector bytes by text surgery (**0** remaining),
then re-run.

- **69 / 69 verdicts identical** to the answered run.
- **0** rows carried an agreement score, i.e. nothing to peek at.

The first attempt at this control was wrong and is worth recording: stripping the
expectations with `JSON.parse` → `JSON.stringify` **rewrites the bytes**, collapsing `3.0`
to `3` — the exact token n38 exists to catch — and the run "diverged". The control was
broken, not the verifier. Text surgery is the correct form.

The runner also had to be fixed to *permit* a blind run at all: the first version crashed
without `expect` present. A verifier that cannot run without the answer key has not
demonstrated it isn't using one.

### Control B — targeted mutation of every accepting vector

One nibble changed inside the first 64-hex digest, one vector at a time. Of 29 accepting
vectors:

- **18 flipped** away from `valid`.
- **7** contain no 64-hex digest at all, so this control does not reach them
  (p2, p8, p9, p10, p11, p21, p25).
- **4 did not move**, and each is correct rather than insensitive:
  - **p7** — the mutated digest is `record.deliverable_digest`; the `phase_claim`
    criterion does not read it, and should not.
  - **p16, p17** — the mutated value is `settlement_result.transaction`. The derivation
    requires it to be a *non-empty string*, deliberately **not** that it resolves on-chain
    (MANIFEST `commitment_derivation`). A different non-empty transaction is still a
    settlement commitment.
  - **p22** — `claimed` is `"none"`. Silence is a valid state, so no digest is
    load-bearing.

For all 11 untouched-or-unmoved vectors, discrimination is demonstrated instead by the
corpus's own rejecting twin in the same kind, which this run gets right — see Control C.

### Control C — closure

- **10 of 10** reject reasons observed: `binding_reject`, `boundary_reject`,
  `canonicalization_reject`, `completeness_reject`, `continuity_reject`, `existence_reject`,
  `independence_reject`, `number_domain_reject`, `phase_reject`, `recompute_mismatch`.
- **11 of 11** kinds produced **both** verdicts in this run. None one-sided.

## A defect in this verifier, found by the run and reported rather than quietly fixed

The first complete run reported **64/69**, with all five `boundary_binding` vectors
disagreeing. The `boundary()` criterion was written but never wired into the dispatch
switch.

The part worth keeping: the unimplemented path threw a `Reject`, so it returned the verdict
`reject` — and that **agreed with the expected verdict on 3 of the 5** boundary vectors.
A criterion that did not exist scored as a pass on three vectors. Only comparing the reject
**reason** as well as the verdict exposed it.

An unimplemented criterion now raises `error`, never a reject, and `error` is never counted
as agreement.

## The crypto profile — implemented, and not exercisable by this corpus

`MANIFEST.json`'s `profile` field puts counter-signature recovery outside the stdlib core
and says exactly why it matters: *"a structurally complete set recomputed wholesale by one
forging party passes the structural predicate; the counter-signatures are what prevent that
in production."* So the structural run is necessary and not sufficient.

It is implemented here — `verifyLinkCounterSignatures()`, EIP-191 `personal_sign` recovery
over each recomputed link — and covered by **8 known-answer tests** (`--self-test`), because
the corpus cannot exercise it:

**Measured: the corpus carries no counter-signature over any link.** Every string of 64+
hex characters in all 69 vectors was enumerated by path. The only signature material in the
entire corpus is `.payload.signature` — 130 hex characters, 65 bytes — appearing **twice**,
in p1 and n1. No `records[].signature` exists. `cosignatures` in p24/n34's witness block is
an integer count (`7`), not material. `deliverable_signer` is an address, not a signature.

**And those two signatures are not verifiable from the vector bytes.** Both carry
`"format": "eip712"`, and neither vector carries an EIP-712 domain, the type definitions, or
an expected signer. Four candidate preimages were tried; each recovered a different, unrelated
address:

| preimage tried | recovered (p1) |
|---|---|
| `personal_sign(canonical(inner))` | `0x259E6521…` |
| `personal_sign(hex digest of inner)` | `0x058b792A…` |
| `personal_sign(raw digest bytes)` | `0x320579e9…` |
| raw `ecrecover(digest(inner))` | `0xee2124cc…` |

None is the counter-signing ledger address that appears throughout the corpus
(`0x9d38BA84…`) or the payload's own `payer`. **This is not evidence the signature is bad** —
it is the point: secp256k1 recovery returns *an* address for essentially any (hash,
signature) pair, so without a declared signing preimage and an expected signer there is
nothing to compare against. A verifier that recovers an address and reports success has
verified nothing.

That trap is designed out of the implementation here: `verifyLinkCounterSignatures()`
**requires** the expected signer as an argument, there is no recover-and-pass path, and an
unsigned link **rejects** rather than reading as "nothing wrong". Its 8 tests cover a
correct set, a link signed by a different key, a missing signature, an entirely unsigned
set, signatures swapped between links, a missing expected signer, and a structural failure
halting before the crypto check.

**Suggested vector, if it's wanted:** a `chain_set`-valid set whose links carry
`personal_sign` counter-signatures, with an accepting twin and a rejecting twin where one
link is signed by a second key. That is the pair that would make the forging case the
manifest describes executable rather than described. This repo's `--self-test` generates
exactly that shape in-process and can contribute it.

## The two undecided normalization calls, measured instead of chosen

Rather than pick a reading and report a green run, both are switchable and
`--policy-matrix` runs the full corpus under each:

```
stripTrailingSlash=true  percentDecode=false    agree 69/69   moved 0   <- default
stripTrailingSlash=false percentDecode=false    agree 68/69   moved 1: n31
stripTrailingSlash=true  percentDecode=true     agree 69/69   moved 0
stripTrailingSlash=false percentDecode=true     agree 68/69   moved 1: n31
```

**Trailing slash is not a judgement call — the corpus forces it.** Turning it off costs
exactly one vector, n31, the vector that exists for it. So this was never "a reader may
disagree"; n31 decides it.

**Percent-encoding changes nothing across all 69 vectors, either way — and that is the
finding.** The suite calls it a "stated open sibling", and no vector pins it, so two
conformant implementations can differ and the suite stays green on both. Constructed probe,
n31's sibling with the alias percent-encoded instead of slash-suffixed — party
`org:caldera-robotics`, attestor `org:caldera%2Drobotics`:

```
percentDecode=false -> valid
percentDecode=true  -> reject/independence_reject (attested only by parties)
```

The verdict **flips on the independence criterion**, which is an alias-bypass failing open
in one reading. This is the same shape as the per-kind two-sidedness hole @Rul1an reported:
a class the manifest names but no vector exercises. Either reading is defensible; the
absence of a vector is what lets the two diverge silently. The probe is
`--self-test`-adjacent and reproducible from this repo.

## Remaining scope, honestly

- `anchor_relation` is implemented as `sha256` over the subject digest's **raw 32 bytes**,
  the literal reading of the manifest.
- Agreement on a vector means the two implementations reach the same verdict for that
  input. It is not evidence that either reading is the one the working group should adopt.
- The crypto profile is implemented and self-tested but **has never been run against
  Tersign's material**, because none exists. That is a statement about the corpus, not a
  claim that their production ledger lacks counter-signatures — p1 is a live record and
  does carry one.

## Provenance

- Verifier: `tersign-reproduction.cjs` in this repo.
- Corpus: `tersignhq/evidence-record-conformance` @ `0eda303`, Apache-2.0, unmodified.
  Controls A and B operate on copies under `/tmp`; the corpus is never written to.

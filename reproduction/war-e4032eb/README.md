# work-acceptance record, profile 1.4.2 — independent Node run at `e4032eb`

Corpus: [`maximusrufus/work-acceptance-record`](https://github.com/maximusrufus/work-acceptance-record) at commit `e4032eb`.
The vectors are **byte-identical to `cb7e8f1`** (`git diff --stat cb7e8f1 HEAD -- vectors/` is empty; only Implementations rows changed since).
Verifier: [`war-verify.cjs`](../../war-verify.cjs) — Node.js, no dependencies outside `node:crypto`.

| | |
|---|---|
| vectors | 90 |
| agree on every field | **90** |
| expected fields compared | 831 |
| disagree on `tsa_signature` only | **0** |
| disagree on any other field | **0** |
| crashes | **0** |
| self-test | 32 passed, 0 failed |

Run files: [`run-e4032eb-90.txt`](run-e4032eb-90.txt) · [`discrimination-e4032eb.txt`](discrimination-e4032eb.txt)

## Correction to the previous run at `cb7e8f1`

The earlier run directory and the commit message of `87fd658` both state 90/90.
**That score was real but was not reachable through the entry point this repository ships.**
Driven through the CLI for the first time on 2026-10-29, the same file reported
**67/90 with 23 crashes**: `if (require.main === module) { ... }` sat *above* the step-9
declarations, so every TSA vector raised a TDZ `ReferenceError` on `const tlvOf` while the
hoisted `function cmsOf` resolved normally. The corpus had only ever been driven by
`require()`ing `runCorpus`, which completes module evaluation before the first call.

The block now sits last in the file. The 23 crashes were all in the `tsa_signature` path;
no rule or reading changed, and no outcome moved apart from those 23 going from a crash to
their expected value.

**The general lesson, stated for anyone else maintaining a checker:** run the instrument
through the entry point you ship, not through a harness that imports it. A green number
obtained by a different code path is a claim about the harness.

## Discrimination controls

A 90/90 is only evidence if the comparison can fail. Both controls are in
[`war-discrimination.cjs`](../../war-discrimination.cjs):

| control | result |
|---|---|
| **always-accept stub** — returns vector 01's expected outcome for all 90 | agreed on **3 of 90** |
| **mutation battery** — applicable input mutations, re-verified | **519 applied, 519 killed, 0 survived** |
| probes evaluated | **18,876** (every swept position, not stopped at the first kill) |

### Kill depth

Stopping at the first kill cannot distinguish a control noticed at one position out of 64
from one noticed at all of them, so every position is evaluated. `min/mutation` is the
number that matters: a 0 would be a survivor, and a 1 on a swept class would mean that
control rested on a single lucky byte.

| mutation class | applied | positions | kill | rate | min/mutation |
|---|---|---|---|---|---|
| signature-bit-flipped | 78 | 4992 | 4992 | 100.0% | 64 |
| signed-body-edited | 78 | 78 | 78 | 100.0% | 1 |
| required-result-flipped-to-fail | 87 | 87 | 87 | 100.0% | 1 |
| criteria-file-byte-flipped | 85 | 5440 | 5440 | 100.0% | 64 |
| criteria-token-byte-flipped | 72 | 4608 | 2761 | 59.9% | 2 |
| record-token-byte-flipped | 18 | 1152 | 455 | 39.5% | 2 |
| signing-key-bit-flipped | 78 | 2496 | 2496 | 100.0% | 32 |
| anchor-list-emptied | 23 | 23 | 23 | 100.0% | 1 |

The two token classes sit below 100% because much of a DER response — certificates, serials,
nonces — decides no outcome. That is the same fact that produced the false survivor below,
measured rather than assumed.

The battery mutates a deep copy of a vector's `inputs` and re-runs the verifier; a kill is
the outcome changing. Two false-positive classes were found in the battery itself and are
worth passing on, because both read exactly like verifier blind spots:

- **A mutation applied to a vector already in that failure state carries no information.**
  Flipping a bit in `signature.value` on 60-63 (already `SIGNATURE_INVALID`), corrupting
  the criteria file on 67 (already `CRITERIA_HASH_MISMATCH`), or touching anything on 77
  (already refused) cannot change the outcome. Each mutation now declares a precondition on
  the unmutated outcome and is **not applied** rather than counted as a survivor — 65 probes
  fall out this way.
- **Where the probe lands decides whether it can be noticed.** The first battery flipped the
  **last** byte of a timestamp token and recorded `01-valid / record-token-byte-flipped` as a
  survivor. The imprint sits in the middle of the signed TSTInfo, so the final byte of a DER
  response is frequently a field no outcome depends on. Byte-flip mutations now sweep up to
  64 evenly-spread positions and count a kill if **any** is noticed.

Uncorrected, those two classes reported **99 survivors** against a verifier that in fact
notices all 519.

## Scope

**Steps 1-9 are implemented**, `tsa_signature` included: CMS SignedData signature
verification (RSA PKCS#1 v1.5, RSASSA-PSS, ECDSA P-256/P-384, other curves reported
`unsupported`), the `contentType` and `messageDigest` signed attributes read under the
SignerInfo's **declared** digest algorithm, ESS signing-certificate binding,
`id-kp-timeStamping`, and a chain of CA issuers reaching an anchor matched by subject name
**and** public key, with the signer and every intermediate valid at `genTime`.

Two things that cost real verdicts:

- **The messageDigest algorithm is declared, not assumed.** FreeTSA's real token declares
  **SHA-512** (`2.16.840.1.101.3.4.2.3`, read from the SignerInfo of vector 31's token);
  DigiCert's declares SHA-256. Hardcoding SHA-256 was re-measured as a counterfactual rather
  than recalled: replacing the declared-algorithm lookup with the literal `"sha256"` moves
  **14 token verdicts across 8 vectors — 31, 33, 34, 35, 50, 51, 58 and 59.**
  *Correction:* the earlier run README of this verifier stated "six wrong `failed` verdicts
  (31, 50, 51, 58, 59, and the receipt half of 34)". That undercounted twice — it omitted
  **33** (`untrusted` → `failed`) and **35** (`no_signer` → `failed`) entirely, and it counted
  per vector where `tsa_signature` is reported per token, so 31/50/51/58/59 contribute two
  wrong values each, not one.
- **A name-matching anchor with another key is not a failed check.** Verifying against it and
  recording a signature failure turns "we do not know this authority" into "this token is
  broken" — the distinction 33 and 53 exist to preserve. A name-only anchor is never verified
  against; the chain simply stopped short, which is `untrusted`.

## Independence

`verifier/war_verify.py` and `verifier/check_payment.py` **have never been opened, run, or
grepped.** While the verifier was written, the fetch step pulled `README.md` and
`vectors/*.json` only. Re-verifying against upstream HEAD on 2026-10-29 used a full
`git clone`, so `verifier/` **is** present on disk — it was listed (`ls verifier/`) and
nothing in it was read. Stated this way because "not fetched to this machine" is no longer
true, and the narrower claim is the one that is.

Every rule is implemented from the profile README's *Properties*, *Verification procedure
(summary)* and *Profile 1.4.2 rules*, plus the vectors' own inputs.

**Disclosure — ANSWER-EXPOSED. This verifier was scored against the corpus, changed, and
re-scored.** Stated in full because an earlier draft of this file claimed the opposite, and
the commit history is public either way:

| commit | date | what it scored |
|---|---|---|
| `2579ffb` | 2026-10-28 | **67/90** — steps 1-8 only; `tsa_signature` not implemented |
| `87fd658` | 2026-10-28 | **90/90** — `tsa_signature` (CMS + X.509) implemented after seeing which vectors the 67 missed |
| `7ec4e67` | 2026-10-29 | **90/90** through the shipped CLI — the TDZ fix above |

So step 9 was built *after* the corpus identified it as the gap, with the `expected` values
visible. That is the same exposure `Tetsurohhori`, `babyblueviper1`, `robertolocatelli81-dev`
and `actaseal` each disclosed on their 1.4.2 rows, and it should be read the same way.

**What is NOT exposure here:** the 67/90 of `2579ffb` (step 9 absent) and the 67/90 of the
first CLI run (step 9 crashing) are the same number from unrelated causes — a coincidence,
not a repeated finding. And no per-vector *reading* was flipped to chase a score: where the
profile text left a reading open the vectors decided it, and each such case is a comment in
`war-verify.cjs` naming the vectors that forced it.

Each vector's `expected` object also sits in the same file as its inputs and was therefore
visible while the inputs were read.

## Why a second host language

As of `e4032eb` the Implementations table holds ten rows from five implementers and **every
one is Python**, the reference included. A second language cannot share a library, a datetime
parser, an ASN.1 decoder or a base64 edge case with the reference, so an agreement across it
is a stronger independence signal than another Python row.

Written here rather than borrowed:

- JCS (RFC 8785), including the ECMAScript number form and UTF-16 code-unit key order
- DER/ASN.1 walker for RFC 3161 `TSTInfo` extraction
- `GeneralizedTime` parsing to the profile's own grammar
- edwards25519 point arithmetic — step 2's key rule needs `[L]P == identity`, and
  `crypto.verify` cannot report prime-order failure as `KEY_REJECTED`

Ed25519 verification, SHA-256, RSA/ECDSA and X.509 parsing come from `node:crypto`.

## Run it

```
node war-verify.cjs --self-test                 # 32 primitive known-answer checks
node war-verify.cjs <corpus-dir>                # scores vectors/*.json
node war-discrimination.cjs <corpus-dir>        # both controls
```

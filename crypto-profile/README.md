# Crypto profile — independent second runner

Independent Node run of the crypto profile on
[tersignhq/evidence-record-conformance#11](https://github.com/tersignhq/evidence-record-conformance/pull/11)
(@babyblueviper1), who asked for a second independent runner.

```
node verify_crypto.cjs vectors     # 8/8 verdicts, 6/6 reject reasons
node confirm_cn3.cjs               # independent confirmation of the malleability finding
```

## Result

| | |
|---|---|
| vectors | 8 |
| verdict agreement | **8/8** |
| reject reasons exercised and matching | **6/6** |
| distinct outcomes | 4 (a constant-returning runner cannot pass) |

**Their live anchor reproduces.** The link recomputes from each vector's own
`artifact_digest`, `prev_digest` and `seq` to
`0x837c2d85db422b59f89527ef33bfe862af7230895635b63141b09cde169187a5`, and `cp1`'s
counter-signature recovers to the pinned `0x9d38BA84730271eb27Ac9bD4Bd2620c08dB4FDa6`.

**cn3 confirmed independently** — the finding that matters beyond this suite. The
malleated signature recovers to **the same** ledger signer, `s₁ + s₃ = n` exactly, and
`v` flips 28 → 27. One link therefore admits two distinct 65-byte strings, and an
address-only verifier accepts both. Ordering is normative: **low-s must be checked
before recovery**, because afterwards the two are indistinguishable by address.

## Independence, stated precisely

Implemented from `crypto/README.md`'s four normative rules and the vectors' own
fields. `crypto/verify_crypto.py` and `crypto/secp256k1_recover.py` were **never
fetched and never read**.

It is **not** stdlib-pure the way theirs is — `keccak256` and the secp256k1 recovery
come from viem. So this is a second implementation in a second language, not a second
stdlib-only proof, and it should not be counted as one.

## The pre-commitment, and why a runner rather than a result

`precommitment.json` + `precommitment.sig.json` are produced by the **same**
`seal()` and canonical-JSON code already running the dated two-party MCP registry
series with MCPShip ([spec and four sealed
windows](https://github.com/Heaviside479/mcpship-registry-attestations/pull/1)) — not
a second implementation of the commitment scheme.

```
commitment_sha256  0c6a0ba1455f3e18fa24d97f7fae1568d2466626bb50ddcc404f03c53736db16
record_sha256      d72c45c20f7a75534354209ad0404311a7a6e30808a0b044ce2bdba783d4f585
scheme             sha256(nonce_hex || canonical_json(record_body))
key_fingerprint    21de066900082465   (resolves in the public keyring, status active)
```

The open scope items — EIP-712 payload signatures and signer-set rotation — have **no
vectors yet**, so there is no result to commit to. What can be committed now is the
**verifier's own bytes**, which makes "the runner was not tuned to the vectors after
seeing them" checkable rather than asserted. Same reason the MCP sweep collects
execution provenance *before* its walk rather than after.

The body names what the runner has already seen and what it has not. `nonce` and the
record body are withheld; publishing them now would defeat the commitment.

**Why this exists at all.** Independence in this suite is currently *declared*, not
demonstrated. Roberto's own clean-room run states the limit exactly — *a transcript
shows which files were opened, not what was already known* — and @TKCollective scoped
his R1 credit down because the agreement arrived after a rule change. Tersign put it
plainly: *agreement makes neither verifier a reference, ours included.* My 8/8 above
has the same defect: I read their README first. A commitment published before the
vectors exist is the only version of this claim a stranger can check.

## Ed25519 non-canonical-S test

```
node ed25519_malleability.cjs      # 4/4, public inputs only, no local files or keys
```

Runs against four **published** commitment files, their detached signatures, and the
public keyring resolved by fingerprint — so a stranger reproduces it without anything
from this box. All four: digest matches, **original verifies** (positive control),
`S` canonical, malleated `S + L` rejected.

**Scope, because it bounds the claim:** the `S + L` non-canonical encoding form only.
Not a statement about every Ed25519 malleability class — small-order `R` and
cofactor/mixed-order points are not covered.

The positive control runs first for a reason: an earlier version of this test reported
"safe" while the *original* signature also failed to verify, which proved nothing. The
preimage is domain-separated as `domain || 0x00 || ascii(sha256_hex(file))` and I had
signed the wrong bytes. A rejection only means something once the genuine signature is
shown to verify.

## Signer-set rotation

```
node build_rotation_vectors.cjs    # author from live material
node signer_rotation.cjs           # 9 vectors + 5 mutants, 14/14, no network
```

Second open item in the crypto profile's scope list: *which key was authoritative at
which seq*. No vectors existed, so these are authored from a **live two-key rotation** —
`921e3af51250a1f5` retired naming its successor, `21de066900082465` active, **5,581 real
receipts across both**, Ed25519 over `ascii(receipt_hash)`, keys resolved from the public
keyring by fingerprint.

**Rule:** authoritative iff the key verifies the signature **and**
`effective_from <= t < effective_until` (null = open-ended).

**Half-open is normative, not stylistic.** In this live registry
`retired.effective_until` and `active.effective_from` are the same instant to the
millisecond — inclusive/inclusive makes two keys authoritative there, so one record
admits two authoritative signers. `rn3`/`rn6`/`rn7` pin `[from, until)` from both sides.

**Rotation must not invalidate history.** `rp1` is a real receipt under the now-retired
key and must stay valid forever. "Accepts only the currently-active key" is the likeliest
wrong implementation and dies on it.

`rn4` is a disclosure: a real production receipt whose signer is **absent from our own
published keyring** (`fp_test`, 2 rows, `authoritative: false`). A rotation-aware
verifier must reject it, so it is a negative vector rather than something quietly
cleaned up.

Five mutants ship — accepts-only-active, ignores-time, inclusive-interval,
trusts-the-claimant-on-succession, policy-before-crypto — each killed by the vector built
for it. An earlier pass had `inclusive-interval` dying to an unrelated vector because the
mutant sweep skipped the boundary case; a suite whose mutants die to the wrong vector
gives false assurance.

## EIP-712: p1 is fully verifiable, and the canonical form was not published

```
node verify_p1_digest.cjs      # live recompute from /v1/genesis
node derive_canonical.cjs      # how the canonical form was recovered
node derive_signer.cjs         # 18 preimage forms, 16 distinct addresses, 0 published
node derive_eip712.cjs         # 5,184 typed-data constructions, 0 recover
```

p1's `kind` is `digest_recompute`, so its target had to be reachable from published
bytes. Using the digest as an oracle rather than guessing: the canonical form is
**`keccak256` over JCS of the whole artifact, signature included** — recomputed live,
395 canonical bytes, exact match.

Two discrimination checks show what the content address does: drop the signature and it
differs (`0x09b78689…`); drop the `format` label and it differs (`0xf112d84a…`). Both are
committed **as bytes**, neither is interpreted. **A conformant verifier validates p1
completely while never checking the payload signature.**

So `format: "eip712"` is an uninterpreted assertion. Four things unblock the vectors —
**domain fields, `primaryType`, field order with solidity types, and the signer's
address**. Without the last, recovery has nothing to compare against, and the signer may
not be `payer`: no address for `sellerId: tersign-first` is published.

## Verify the signature yourself

Detached Ed25519 over `domain || 0x00 || ascii(sha256_hex(file))`. The zero byte stops
two domains colliding by concatenation; a signature under the joint-window domain does
**not** verify under this one (tested). Resolve the key by fingerprint at
`https://stillosdigitalholdings.com/notary/keyring` — never "the current key".

The signature proves the holder of that key produced these exact bytes. It does **not**
prove the claim inside is true.

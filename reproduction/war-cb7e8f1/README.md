# work-acceptance record, profile 1.4.2 — independent Node run

Corpus: [`maximusrufus/work-acceptance-record`](https://github.com/maximusrufus/work-acceptance-record) at commit `cb7e8f1`.
Verifier: [`war-verify.cjs`](../../war-verify.cjs) — Node.js, no dependencies outside `node:crypto`.

| | |
|---|---|
| vectors | 90 |
| agree on every field | **90** |
| disagree on `tsa_signature` only | **0** |
| disagree on any other field | **0** |
| crashes | **0** |

## Scope

**Steps 1-9 are implemented**, `tsa_signature` included: CMS SignedData signature
verification (RSA PKCS#1 v1.5, RSASSA-PSS, ECDSA P-256/P-384, with other curves
reported `unsupported`), the `contentType` and `messageDigest` signed attributes read
under the SignerInfo's **declared** digest algorithm, ESS signing-certificate binding,
`id-kp-timeStamping`, and a chain of CA issuers reaching an anchor matched by subject
name **and** public key, with the signer and every intermediate valid at `genTime`.

Two things that cost real verdicts and are worth passing on:

- **The messageDigest algorithm is declared, not assumed.** FreeTSA's real token
  declares SHA-512. Hardcoding SHA-256 produced six wrong `failed` verdicts on tokens
  that are entirely valid (31, 50, 51, 58, 59, and the receipt half of 34).
- **A name-matching anchor with another key is not a failed check.** Verifying against
  it and recording a signature failure turns "we do not know this authority" into
  "this token is broken" — the distinction 33 and 53 exist to preserve. A name-only
  anchor is never verified against; the chain simply stopped short, which is
  `untrusted`.

## Independence

`verifier/war_verify.py` and `verifier/check_payment.py` were **not fetched to this
machine**, let alone read. The fetch step pulled `README.md` and `vectors/*.json`
only; `verifier/` was listed in the tree and deliberately skipped. Every rule is
implemented from the profile README's *Properties*, *Verification procedure (summary)*
and *Profile 1.4.2 rules*, plus the vectors' own inputs.

**Disclosure:** each vector's `expected` object sits in the same file as its inputs
and was therefore visible while the inputs were read. Where the text left a reading
open, the vectors decided it, and each such case is recorded as a comment in
`war-verify.cjs` naming the vectors that forced it.

## Written here rather than borrowed

- JCS (RFC 8785)
- DER/ASN.1 walker for RFC 3161 `TSTInfo` extraction
- `GeneralizedTime` parsing to the profile's own grammar
- edwards25519 point arithmetic — step 2's key rule needs `[L]P == identity`, and
  `crypto.verify` cannot report prime-order failure as `KEY_REJECTED`

Ed25519 verification and SHA-256 come from `node:crypto`.

## Run it

```
node war-verify.cjs --self-test      # 25 primitive known-answer checks
node war-verify.cjs <corpus-dir>     # scores vectors/*.json
```

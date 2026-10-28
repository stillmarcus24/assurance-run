# work-acceptance record, profile 1.4.2 — independent Node run

Corpus: [`maximusrufus/work-acceptance-record`](https://github.com/maximusrufus/work-acceptance-record) at commit `cb7e8f1`.
Verifier: [`war-verify.cjs`](../../war-verify.cjs) — Node.js, no dependencies outside `node:crypto`.

| | |
|---|---|
| vectors | 90 |
| agree on every field | **67** |
| disagree on `tsa_signature` only | 23 |
| disagree on any other field | **0** |
| crashes | **0** |

## Scope, stated rather than implied

Steps 1-8 of the verification procedure are implemented.

**Step 9 (`tsa_signature`) is implemented only for the no-anchor case**, where the
profile states the value is `not_evaluated` and that an absent field reads the same.
When `tsa_roots_base64` is supplied, a real value requires CMS and X.509 work that is
**not implemented here**: SignedData signature verification over RSA PKCS#1 v1.5 and
ECDSA P-256/P-384, the `contentType` signed attribute, ESS signing-certificate
binding, `id-kp-timeStamping`, and a chain of CA issuers reaching an anchor matched by
subject name and public key with every certificate valid at `genTime`.

In that case the field is **omitted rather than asserted**. A wrong `verified` would
claim a time had been validated against a trust anchor when nothing of the kind
happened, which is worse than an absent field. The 23 disagreements are exactly those
vectors, and no other outcome field disagrees on any vector.

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

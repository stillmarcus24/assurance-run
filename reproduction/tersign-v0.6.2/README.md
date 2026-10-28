# evidence-record-conformance v0.6.2 — independent run

Corpus: [`tersignhq/evidence-record-conformance`](https://github.com/tersignhq/evidence-record-conformance) at tag `v0.6.2` (`2e9a63b`).

| file | suite | vectors | agreement |
|---|---|---|---|
| `structural-v0.6.2.json` | `MANIFEST.json` | 284 | 284/284 |
| `crypto-v0.6.2.json` | `crypto/MANIFEST.json` | 50 | 50/50 |
| `eip712-v0.6.2.json` | `crypto/EIP712_MANIFEST.json` | 46 | 46/46 |

`python3 tools/compare_run.py structural-v0.6.2.json` at the tag prints
`agrees on 284/284 verdicts and reasons at v0.6.2 (MANIFEST.json sha256 7f6bfb69…)` and exits 0.

`compare_run.py` cannot check the two crypto outputs: no entry of either crypto manifest names a
reject reason (each reject vector carries its own `reject_reason`), so `--manifest crypto/MANIFEST.json`
is refused. Those were compared against each vector's own `expect` and `reject_reason`.

Manifest digests this run was measured against:

```
7f6bfb696522b184a7fd749eda1882f6b78251fc99e5d26841fb670196e68ac6  MANIFEST.json
061046e67115756fcd3c...                                            crypto/MANIFEST.json
f4a28015a721a224bf1f...                                            crypto/EIP712_MANIFEST.json
```

Runners: `tersign-reproduction.cjs` (structural), `tersign-crypto-profile.cjs` (counter-signature),
`tersign-eip712-profile.cjs` (EIP-712). `verify.py`, `crypto/verify_crypto.py` and
`crypto/verify_eip712.py` were not read.

# Capability-expansion detector — blind validation set

The contingency tables and blind answer key behind
[snyk/agent-scan#482](https://github.com/snyk/agent-scan/issues/482), published so the
57.1% precision figure in that issue is re-derived rather than taken on trust.

```
node rederive.cjs
```

Node 18+, standard library only. No network, no install.

## What is here

`answer-key.json` — the blind assignment. 90 release transitions drawn from a frame of
7,711 (1,752 expanded / 1,158 changed-not-expanded / 4,801 identical), fixed by seed
`20260920` **before any case was examined**, carrying the package name, the from/to
versions, the stratum, and what the detector said.

`adjudications.jsonl` — the 90 labels, each adjudicated against source, with the reasoning
note that produced it. Without the notes the labels would be unfalsifiable.

`rederive.cjs` — recomputes precision from those two files and prints it.

## What is deliberately not here

The per-case observation vectors the detector computes are **not** in this pack. The
package and version pairs are, so every adjudication is re-runnable from the npm tarballs
directly — which is a stronger check than reading our observations, because it verifies
the labels against the artifacts rather than against our notes.

Said out loud rather than quietly omitted, since an undisclosed omission is the same class
of defect as an invisible pin input.

## The denominator rule, stated

Two of the 30 flagged cases adjudicated `unclear`. Excluding them gives **16/28 = 57.1%**,
which is the figure quoted in the issue. Counting them as false positives gives
**16/30 = 53.3%**, moving the corrected alert rate from 13.0% to 12.1% and the attack rate
required for 10% PPV from 1.30% to 1.21%. The script prints both. A precision figure whose
denominator rule is invisible has the same defect as a pin whose inputs are invisible.

## The guard

If `adjudications.jsonl` were swapped for a file agreeing with the detector everywhere,
precision would read 100% and nothing would complain. The script refuses to report at all
when the adjudications never contradict the detector. That case is run as a known-answer
test: force every label to `yes` and it exits 1.

MIT.

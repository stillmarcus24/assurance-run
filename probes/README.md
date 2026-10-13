# Unpinned-reading probes — evidence-record-conformance v0.5.6

`MANIFEST.json` and `README.md` name six readings no vector pins. A reading no
vector pins is a place two conforming engines can disagree without either being
wrong, and — as `u1` shows — a place a real engine defect can survive a full green
run.

One probe per reading we can express structurally, each run through BOTH engines
(tersignhq `verify.py`, stdlib Python; this repo's `tersign-reproduction.cjs`, Node):

| probe | reading | python | node |
|---|---|---|---|
| `u1` | a surrogate pair written half raw, half escaped, where it repeats no name | valid | valid |
| `u2` | the RFC 8785 §3.2.2.2 escapes for U+0000–U+001F | valid | valid |
| `u3` | whether a null `prev_digest` constrains `seq` | continuity_reject | continuity_reject |
| `u4` | a phase word padded with whitespace | phase_reject | phase_reject |
| `u5` | settlement presented as funding (one of the 17 unpinned ordered pairs) | phase_reject | phase_reject |

**`u1` is why this directory exists.** On first run the two engines DISAGREED:
Python accepted, this Node engine rejected. The Node engine was wrong — it scanned
the RAW `payload_text` for unpaired surrogates, and a pair written half raw is
unpaired in the raw text while being a valid pair after unescaping. Every corpus
vector in that class (`n41`, `n42`, `n93`) also REPEATS a name, so it rejects on the
duplicate first and never reaches the surrogate decision. **The defect survived a
162/162 run.** Fixed; both engines now agree.

Not probed here: scheme equivalences beyond rule (5) (default port, ENS, `did:web`),
which need a full `independence_claim` construction rather than a one-field change.

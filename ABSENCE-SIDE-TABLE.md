# Absence-side handling across reachable implementations

Built 2026-09-23 to correct a table I posted to `x402-foundation/tsc#4` on 2026-09-20.
That version said `x402-measure` carried "no verdict enum at all" and placed it with the
implementations that separate the absence side in a *sibling field rather than the verdict*.
@meloliva14 corrected both points. They are right, and the correction removes the
load-bearing part of an argument I made to the TSC.

Every row below is sourced to a file and line, or marked `NOT_EVALUATED`. A row I have not
re-read is not a finding — that is the same rule this table is about.

## The question

Does the implementation separate *absence of a check* from *a check that ran and failed*,
and is that separation carried **in the verdict value** or **beside it**?

## Table

| implementation | absence carried in | states | source |
|---|---|---|---|
| `assurance-run` (mine) | **verdict value** | `AGREE` / `DISAGREE` / `INDETERMINATE` / `NOT_EVALUATED`, with `reason` as a sibling | `kernel.cjs:43-46` defines them; `kernel.cjs:306,312,317,328,335` return `{verdict: NOT_EVALUATED, reason: ...}`; `kernel.cjs:340,345` return `{verdict: INDETERMINATE, reason: ...}` |
| `x402-measure` (@meloliva14) | **verdict value** | 10-value enum: `OK`, `WARN`, `BLOCKED`, `V1`, `NON_EVM`, `NO_402`, `RATE_LIMITED`, `UNPARSEABLE`, `UNREACHABLE`, `UNKNOWN_NETWORK`; `notes` carries the reason | enum published in every signed manifest at `snapshot.py:393` as `dict(sorted(preflight.VERDICT_NOTE.items()))`, generated from the module not hand-written; values in `preflight.py` |
| `api.babyblueviper.com/verify-proof` (@babyblueviper1) | **beside the verdict** | top-level `valid: bool`, with a sibling `checks` object of named booleans | live response 2026-09-23: top-level keys include `valid` (bool), `checks`, `preimage_fields_authorized`, `trust_basis` |
| `agentoracle-receipt-verify` (@TKCollective) | collapses the absence side | `valid` / `invalid` / `indeterminate` — three, not four | stated by its author in `wg-identity#21`, 2026-09-20, including its own AC-11 bug. **Not independently re-read by me.** |
| `elara-verify` | `NOT_EVALUATED` | — | I characterised it as `Verified / Partial / Failed` on 2026-09-20 and have **not re-verified that claim**. It is withdrawn pending a re-read, not restated. |

## What the correction changes

My 2026-09-20 comment argued that `assurance-run` was the only reachable implementation
emitting the absence states as verdict values, and used that to warn the TSC that Phase 1
as scoped would ratify my implementation by default.

That uniqueness claim does not hold. `x402-measure` carries `NO_402`, `UNREACHABLE`,
`RATE_LIMITED` and `NON_EVM` as enum values with the reason text in a sibling `notes`
field — which is **structurally the same shape as mine**, where `NOT_EVALUATED` and
`INDETERMINATE` are verdict values and `reason` is the sibling. I described a peer's
design as weaker than mine when it is the same design.

The count in that column is two, not one. My warning was therefore weaker than I stated
it, and it was weaker in the direction that flattered my own implementation.

## What survives

More than one independent implementation separates the absence side inside the verdict,
both built that way in production before this thread named the shape. That is an argument
for lifting existing vocabulary rather than inventing it — and it is a better argument
than the one I made, because it does not depend on my code being special.

## NOT_ASSESSED

My 2026-09-20 comment attributed `NOT_ASSESSED` to `x402-measure` as a verdict. It is not
one. It appears only as a local set `NOT_ASSESSED = {"RATE_LIMITED"}` at
`compare_controls_nohumans.py:86` and `compare_perday_nohumans.py:29`, used to neutralise
429 rows when diffing against another party's file. No row carries it.

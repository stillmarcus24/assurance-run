# assurance-run

An executable corpus for the four evidence semantics that
[`x402-foundation/tsc#4`](https://github.com/x402-foundation/tsc/issues/4)
identified as having no attachment point in the proposed Phase 1 baseline.

Not a competing schema. Not an `x402ev/2`. There is no wire format proposed
here. This is the **semantics** underneath whatever byte form the working
group settles on, written as prohibitions a conforming implementation must
refuse to violate, with a control that proves the suite can actually fail.

```
git clone https://github.com/stillmarcus24/assurance-run && cd assurance-run
node selftest.cjs            # the four-state evaluator          (10 cases)
node selftest-semantics.cjs  # the three missing semantics       (17 cases)
node cross-rail.cjs          # same evaluator, unrelated rails   (6 cases, 2 live)
```

No dependencies, no install step, no network calls except the two live
Starknet reads in `cross-rail.cjs`, and no callback to us in any of them.

---

## The four gaps, and where each is implemented

Taken verbatim from [@magentixai's 15 September
comment](https://github.com/x402-foundation/tsc/issues/4#issuecomment-5680248416).

| # | Gap | Implemented in | Cases |
|---|---|---|---|
| 1 | Verdict vocabulary: `verified / contradicted / indeterminate / not-evaluated` | `kernel.cjs` | AC-01 … AC-10 |
| 2 | The capture relationship — who observed vs who executed | `semantics.cjs` | SC-01 … SC-05 |
| 3 | An evidence anchor per state | `semantics.cjs` | SC-06 … SC-10 |
| 4 | The `ref=` slot — pre-action verification reference | `semantics.cjs` | SC-11 … SC-17 |

### 1. Four states, never two

`AGREE` · `DISAGREE` · `INDETERMINATE` · `NOT_EVALUATED`

The fourth is the one that gets dropped as redundant when it is only ever
written down. It is the difference between *"we checked and could not tell"*
and *"no check ran"*. Collapse them and a gate that never executed reads as a
gate that passed. We have shipped that bug ourselves — a conformance harness
that silently ignored unknown flags and reported PASS for code it never
loaded.

**The core invariant:** self-reported evidence that *matches* can never
produce `AGREE` (AC-05). Attesting to a party's report of a source is not
attesting to the source. The verdict is
`INDETERMINATE / INSUFFICIENT_INDEPENDENCE` — weaker, and honest.

### 2. The capture relationship

Four separable roles: `issuer`, `executor`, `observer`, `verifier`. They
commonly collapse onto one party. That is allowed, and it must be **stated**
rather than assumed.

Independence is **derived from the role identities**, not read from a
self-declared label. A record that declares `independent_retrieval` while
naming the same party as observer and executor is contradicted by its own
contents (SC-05 → `DISAGREE`). A record that names neither is
`NOT_EVALUATED` — absence of a stated relationship is not independence
(SC-01, SC-02).

### 3. An evidence anchor per state

`"state": "settled"` is a bare string. One anchor at the top of a record
covers one fact; it does not cover every state the record asserts.

Each asserted state names the evidence supporting *that* state. A record with
three states and one anchor reads as one supported and two unevaluated —
never as three settled (SC-10). Evidence that is referenced but absent is
`INDETERMINATE`, not `DISAGREE`: absent is not contradicted (SC-07). Evidence
present that does not hash to its stated digest is `DISAGREE` (SC-08).

### 4. Typed references

One overloaded pointer cannot distinguish *"this checked a precondition
before acting"* from *"this replaces an earlier record"*. Typed instead:

`verifies-precondition` · `derives-from` · `settles` · `corrects` · `supersedes`

The last two are what let history stay append-only. A later record changes
the **interpretation** of an earlier one without editing it; the earlier
record remains exactly as issued and independently verifiable.
`currentInterpretation()` resolves which record is authoritative and returns
`INDETERMINATE` — never a silent pick — when the chain does not determine one
(SC-16, SC-17).

An unknown reference type is `NOT_EVALUATED`, same rule as an unknown schema:
never a pass, never a failure (SC-12).

---

## Rail neutrality, tested rather than asserted

A set of rules derived from one settlement rail is a house style. The same
evaluator, **unmodified**, runs against evidence systems with nothing in
common:

| Rail | Validity means | Status |
|---|---|---|
| State proof (Starknet Sepolia) | a fact registered by a STARK verifier | live RPC read |
| Transparency log | a record's position in a hash chain | structural, offline |
| Account chain (EVM/x402) | a balance or transfer at an address | adapter in `adapters.cjs` |

**Kernel changes required to support them: none.** Adapters normalise into
`observed`; the evaluator was not modified for either rail. Had it needed a
new verdict or a new provenance field, the semantics would have been
rail-specific — and that is worth knowing *before* a group adopts them.

## What this run found in its own adapter

The first draft of the Starknet adapter passed a raw 256-bit SHA-256 digest
to the chain as a `felt252`. A felt is strictly below 2²⁵², so the chain
answered `-32602 invalid fp.Element encoding` — which logs exactly like a
lookup miss. **Only the known-answer control separated the two.** It is now
pinned as XR-02: out of range is `NOT_EVALUATED`, never an absence of fact.

That endpoint also intermittently answers `-32601 "the method starknet_call
does not exist"` for a method it demonstrably supports seconds earlier. The
adapter retries a bounded number of times — not for persistence's own sake,
but to refuse to let one flaky response become a permanent fact about a rail.
A persistently unreachable source is `INDETERMINATE / SOURCE_UNREACHABLE`,
never "not anchored".

## Known limits, stated rather than omitted

- Reading the fact registry answers whether a fact is **registered**. It does
  not prove a specific leaf sits under a given batch root — that root is a
  flat Poseidon over all leaves, so single-leaf inclusion requires disclosing
  every other party's entry. **Anchored is not the same as provably
  included**, and nothing here claims the stronger thing.
- `cross-rail.cjs` exercises two rails live. The account-chain adapter is
  present but not exercised in that run.
- The state vocabulary is deliberately **open**. This validates the
  *binding*, not which state names a profile may use. Constraining names is a
  profile's job.

## Scope boundary

Nothing here knows about bonds, collateral, escrow, challenge windows or
slashing. Those are settlement mechanics and belong downstream. This
describes evidence only. A record that validates here says nothing about who
owes whom — that is the point, and it is the boundary
[@whawk46 asked Phase 1 to hold](https://github.com/x402-foundation/tsc/issues/4#issuecomment-5673343148).

## Ownership

Offered to the Phase 1 working group on open terms as reference material and
negative vectors, whoever chairs. If Phase 1 is chartered, this moves under
the group. The record shape belongs to the group, not to a contributor.

MIT.

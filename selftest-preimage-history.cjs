#!/usr/bin/env node
'use strict';
/**
 * Assurance Run — preimage-field history, executable.
 *
 * `fixtures-invinoveritas-preimage-history.json` ASSERTS a monotonic invariant:
 * across the policy_versions that shipped a live proof, no version drops a
 * preimage field present in an earlier one. An assertion in a data file is a
 * claim; this suite is what makes it a check.
 *
 * Written for wg-identity#21, whose whole subject is that `not evaluated` must
 * never collapse into `verified`. This fixture contains a case that is exactly
 * that: babyblueviper1 reported (2026-09-22) that v13's single
 * `action_binding_hash` was split into three narrower fields at v14. We cannot
 * confirm it. v13 never shipped a live proof, so a ledger walk is structurally
 * blind to it, and the registry that would settle it is producer-side.
 *
 * MEASURED, not assumed: the authorized-fields registry appears in NONE of the
 * six published releases of their own offline verifier (0.1.0, 0.2.0, 0.3.0,
 * 0.4.0, 0.4.1, 0.4.2 — each downloaded and grepped 2026-09-22). So
 * `preimage_fields_authorized` is the one check in that verifier a third party
 * cannot recompute from any published artifact. Their own response says as much
 * (`independently_verified_by_this_response: false`,
 * `registered_set_completeness_status: "cannot_establish"`); this suite records
 * that the same holds across every artifact they ship, not just the API reply.
 *
 * So PH-02 asserts NOT_EVALUATED. A suite that reported the exception as
 * confirmed would be committing the defect the issue exists to forbid.
 *
 * Same discipline as selftest-semantics.cjs: every case is a PROHIBITION, and a
 * deliberately permissive implementation is run against the same cases and must
 * be caught.
 */

const fs = require('fs');
const path = require('path');

const AGREE = 'AGREE';
const NOT_EVALUATED = 'NOT_EVALUATED';

const FIXTURE = path.join(__dirname, 'fixtures-invinoveritas-preimage-history.json');

// ---------------------------------------------------------------- the checker
const strict = {
  /** Monotonic over the OBSERVED population only. Never over all versions. */
  monotonic(fx) {
    const order = Object.keys(fx.versions).sort(
      (a, b) => Number(a.split('.v')[1]) - Number(b.split('.v')[1]),
    );
    let prev = null;
    for (const pv of order) {
      const cur = new Set(fx.versions[pv].fields);
      if (prev) for (const f of prev) if (!cur.has(f)) {
        return { state: 'DISAGREE', reason: `FIELD_DROPPED:${pv}:${f}` };
      }
      prev = cur;
    }
    return { state: AGREE, reason: 'MONOTONIC_OVER_OBSERVED', n: order.length };
  },

  /** A reported exception we cannot reach is NOT_EVALUATED, never a pass. */
  reportedException(fx) {
    const k = fx.known_exception;
    if (!k) return { state: NOT_EVALUATED, reason: 'NO_EXCEPTION_RECORDED' };
    if (k.independently_verified_by_us === true) {
      return { state: AGREE, reason: 'EXCEPTION_INDEPENDENTLY_VERIFIED' };
    }
    return { state: NOT_EVALUATED, reason: 'REGISTRY_NOT_PUBLISHED' };
  },

  /** A coverage claim must name what it could not see. */
  coverageHonest(fx) {
    const c = fx.coverage || {};
    if (!Array.isArray(c.unobserved) || c.unobserved.length === 0) {
      return { state: 'DISAGREE', reason: 'COVERAGE_CLAIMS_TOTALITY' };
    }
    if (c.policy_versions_observed >= c.policy_versions_known_to_exist) {
      return { state: 'DISAGREE', reason: 'OBSERVED_CLAIMS_ALL_VERSIONS' };
    }
    return { state: AGREE, reason: 'BLIND_SPOT_NAMED', unobserved: c.unobserved.length };
  },
};

// A permissive twin: reports success without looking. If the cases below cannot
// catch it, the cases are decorative.
const permissive = {
  monotonic: () => ({ state: AGREE, reason: 'MONOTONIC_OVER_OBSERVED' }),
  reportedException: () => ({ state: AGREE, reason: 'EXCEPTION_INDEPENDENTLY_VERIFIED' }),
  coverageHonest: () => ({ state: AGREE, reason: 'BLIND_SPOT_NAMED' }),
};

// ---------------------------------------------------------------- the cases
const CASES = [
  { id: 'PH-01', name: 'observed population is monotonic — no version drops an earlier field',
    want: AGREE, run: (m, fx) => m.monotonic(fx) },

  { id: 'PH-02', name: 'v13->v14 split is reported, unreachable, and therefore NOT_EVALUATED',
    want: NOT_EVALUATED, wantReason: 'REGISTRY_NOT_PUBLISHED',
    run: (m, fx) => m.reportedException(fx) },

  { id: 'PH-03', name: 'coverage names its blind spot rather than claiming totality',
    want: AGREE, run: (m, fx) => m.coverageHonest(fx) },

  { id: 'PH-04', name: 'a fixture claiming all versions observed is refused',
    want: 'DISAGREE', wantReason: 'OBSERVED_CLAIMS_ALL_VERSIONS',
    mutate: (fx) => ({ ...fx, coverage: { ...fx.coverage, policy_versions_observed: 19 } }),
    run: (m, fx) => m.coverageHonest(fx) },

  { id: 'PH-05', name: 'a fixture with an unnamed blind spot is refused',
    want: 'DISAGREE', wantReason: 'COVERAGE_CLAIMS_TOTALITY',
    mutate: (fx) => ({ ...fx, coverage: { ...fx.coverage, unobserved: [] } }),
    run: (m, fx) => m.coverageHonest(fx) },

  { id: 'PH-06', name: 'a real dropped field is caught, not smoothed over',
    want: 'DISAGREE',
    mutate: (fx) => {
      const c = JSON.parse(JSON.stringify(fx));
      c.versions['invinoveritas.review.v18'].fields =
        c.versions['invinoveritas.review.v18'].fields.filter((f) => f !== 'verdict');
      return c;
    },
    run: (m, fx) => m.monotonic(fx) },
];

// ---------------------------------------------------------------- run
function run(model, label) {
  const base = JSON.parse(fs.readFileSync(FIXTURE, 'utf8'));
  const out = [];
  for (const c of CASES) {
    const fx = c.mutate ? c.mutate(JSON.parse(JSON.stringify(base))) : base;
    let got;
    try { got = c.run(model, fx); } catch (e) { got = { state: 'THREW', reason: e.message }; }
    const ok = got.state === c.want && (!c.wantReason || got.reason === c.wantReason);
    out.push({ ...c, got, ok });
  }
  return out;
}

const strictRes = run(strict, 'strict');
for (const r of strictRes) {
  console.log(`${r.ok ? 'PASS' : 'FAIL'}  ${r.id}  ${r.name}`);
  if (!r.ok) console.log(`        want ${r.want}${r.wantReason ? '/' + r.wantReason : ''}, got ${r.got.state}/${r.got.reason}`);
}
const failed = strictRes.filter((r) => !r.ok).length;

// The control: the permissive twin must be caught by at least the prohibitions.
const permRes = run(permissive, 'permissive');
const permCaught = permRes.filter((r) => !r.ok).length;
console.log(`\nCONTROL  permissive twin caught by ${permCaught}/${CASES.length} cases`);
if (permCaught === 0) {
  console.log('CONTROL FAILED — a checker that looks at nothing passes every case; the cases prove nothing.');
  process.exit(1);
}

console.log(`\n${CASES.length - failed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);

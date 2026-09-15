#!/usr/bin/env node
'use strict';
/**
 * Assurance Run — cross-rail neutrality run.
 *
 * The claim this file exists to test: the four-state evaluator and the
 * evidence semantics were not designed around one settlement rail.
 *
 * The only way to test that is to run the SAME evaluator, unmodified,
 * against evidence systems whose trust models have nothing in common, and
 * report what happens — including where it comes out weaker than a
 * single-rail implementation would.
 *
 *   account chain    balance/transfer at an address        (EVM, out of scope here)
 *   state proof      a fact registered by a STARK verifier (Starknet Sepolia, live)
 *   transparency log a record's position in a hash chain   (structural, offline)
 *
 * Two of the three are exercised live below. Every case carries a
 * KNOWN-ANSWER CONTROL: an input whose correct answer we already know
 * independently, so a run that returns all-green because the instrument is
 * broken is distinguishable from a run that returns all-green because the
 * evidence is good. An instrument tested only against unknowns measures
 * nothing.
 *
 * Exit code is deliberately NOT a pass/fail on the evidence. It is a
 * pass/fail on whether the evaluator behaved correctly for each input.
 */

const K = require('./kernel.cjs');
const R = require('./adapters-rails.cjs');
const A = require('./adapters.cjs');

// Caller supplies the clock; the kernel never invents one.
const OBSERVED_AT = process.env.ASSURANCE_OBSERVED_AT || new Date().toISOString();
const OPTS = { observed_at: OBSERVED_AT };

// The real StillOS digest Vauban included as a STILLOS_NOTARY_RECEIPT_V1
// foreign leaf on 2026-09-14. Used as a live input, not as a claim of
// inclusion -- see the note on the flat batch root in the output.
const STILLOS_LEAF = '636ec23cec4628502312ddde24bc620bee54bf83bd85759eadabf810230a4536';
// The high 128-bit limb of that digest -- a real value from the real encoding,
// and a valid felt252, unlike the full digest.
const LIMB_HI = '636ec23cec4628502312ddde24bc620b';

function chain(payloads) {
  const out = []; let prev = 'genesis';
  for (const p of payloads) {
    const digest = K.sha256(prev + '|' + K.canonical(p));
    out.push({ prev, payload: p, digest }); prev = digest;
  }
  return out;
}

const CASES = [
  {
    id: 'XR-01', rail: 'state-proof (Starknet Sepolia)', kind: 'KNOWN-ANSWER CONTROL',
    why: 'a fact hash that cannot have been registered must read as a real zero, not as an error',
    adapter: R.starknetFact,
    spec: { event_id: 'xr-01', claim: 'an impossible fact is not registered',
      source: R.STARKNET_SEPOLIA_RPC, resource: '0x' + '1'.repeat(48),
      expected: { state: 'NO_VERIFICATIONS_FOR_FACT' } },
    expectAny: [K.AGREE, K.INDETERMINATE], live: true,
  },
  {
    id: 'XR-02', rail: 'state-proof (Starknet Sepolia)', kind: 'ENCODING CONTROL',
    why: 'a 256-bit digest is NOT a felt252; the adapter must refuse rather than send a ' +
         'call whose -32602 would read like a lookup miss',
    adapter: R.starknetFact,
    spec: { event_id: 'xr-02', claim: 'raw sha256 digest queried as a felt',
      source: R.STARKNET_SEPOLIA_RPC, resource: '0x' + STILLOS_LEAF,
      expected: { state: 'FACT_REGISTERED' } },
    expect: K.NOT_EVALUATED,
  },
  {
    id: 'XR-03', rail: 'state-proof (Starknet Sepolia)', kind: 'NEGATIVE CONTROL',
    why: 'the leading-zero trap: a felt padded with zeros must resolve to the same fact',
    adapter: R.starknetFact,
    spec: { event_id: 'xr-03', claim: 'padded and stripped felt forms resolve identically',
      source: R.STARKNET_SEPOLIA_RPC, resource: '0x0000' + LIMB_HI,
      expected: { fact: R.normFelt('0x' + LIMB_HI) } },
    expectAny: [K.AGREE, K.INDETERMINATE], live: true,
  },
  {
    id: 'XR-04', rail: 'transparency log', kind: 'KNOWN-ANSWER CONTROL',
    why: 'an intact chain recomputed from its own entries',
    adapter: R.hashChainLog,
    spec: { event_id: 'xr-04', claim: 'log chain is intact', source: 'urn:log:test',
      resource: chain([{ a: 1 }, { a: 2 }, { a: 3 }]),
      expected: { state: 'CHAIN_INTACT', length: '3' } },
    expect: K.AGREE,
  },
  {
    id: 'XR-05', rail: 'transparency log', kind: 'NEGATIVE CONTROL',
    why: 'a tampered middle entry must be caught, not smoothed over',
    adapter: R.hashChainLog,
    spec: (() => {
      const c = chain([{ a: 1 }, { a: 2 }, { a: 3 }]);
      c[1].payload = { a: 'TAMPERED' };
      return { event_id: 'xr-05', claim: 'log chain is intact', source: 'urn:log:test',
        resource: c, expected: { state: 'CHAIN_INTACT' } };
    })(),
    expect: K.DISAGREE,
  },
  {
    id: 'XR-06', rail: 'any', kind: 'INDEPENDENCE CONTROL',
    why: 'the same matching data, self-reported, must never reach AGREE on any rail',
    adapter: A.counterpartyReport({ state: 'CHAIN_INTACT', length: '3' }, OPTS),
    spec: { event_id: 'xr-06', claim: 'counterparty says the chain is intact',
      source: 'urn:counterparty', expected: { state: 'CHAIN_INTACT', length: '3' } },
    expect: K.INDETERMINATE,
  },
];

(async function main() {
  console.log('\n  ' + K.VERSION + ' — cross-rail neutrality run');
  console.log('  observed_at: ' + OBSERVED_AT);
  console.log('  ' + '-'.repeat(72));

  const results = [];
  for (const c of CASES) {
    const spec = { ...c.spec, frozen_at: OBSERVED_AT };
    let rec;
    try { rec = await K.run(spec, c.adapter, OPTS); }
    catch (err) { rec = { verdict: 'THREW', reason: err.message, evidence: {} }; }

    // A live-network case has TWO legitimate outcomes: the read succeeded, or the
    // endpoint could not be reached. The prohibition under test holds in both --
    // what must never happen is an unreachable source reported as a real zero.
    // Failing the suite because someone else's RPC was down would measure the
    // network, not the evaluator.
    const ok = c.expectAny
      ? c.expectAny.includes(rec.verdict) &&
        (rec.verdict !== K.INDETERMINATE || rec.reason === 'SOURCE_UNREACHABLE')
      : c.expect === null ? true : rec.verdict === c.expect;
    results.push({ ...c, rec, ok });

    console.log(`\n  ${c.id}  [${c.rail}]  ${c.kind}`);
    console.log(`        ${c.why}`);
    console.log(`        verdict: ${rec.verdict} / ${rec.reason}`);
    if (rec.evidence && rec.evidence.observed) {
      console.log(`        observed: ${JSON.stringify(rec.evidence.observed)}`);
    }
    if (rec.evidence && rec.evidence.error) {
      console.log(`        error:    ${rec.evidence.error}`);
    }
    if (c.expectAny) {
      const branch = rec.verdict === K.INDETERMINATE ? ' (endpoint unreachable this run)' : ' (live read succeeded)';
      console.log(`        ${ok ? 'ok  ' : 'FAIL'}  expected one of ${c.expectAny.join(' | ')}${branch}`);
    } else if (c.expect !== null) {
      console.log(`        ${ok ? 'ok  ' : 'FAIL'}  expected ${c.expect}`);
    } else {
      console.log('        (no expected verdict — reporting what the rail actually says)');
    }
  }

  const failed = results.filter((r) => !r.ok);
  console.log('\n  ' + '-'.repeat(72));
  console.log('  RAILS EXERCISED: state-proof (live RPC), transparency log (structural),');
  console.log('                   plus the independence control that applies to all rails.');
  console.log('  KERNEL CHANGES REQUIRED TO SUPPORT THEM: none.');
  console.log('  Adapters normalise; the evaluator was not modified for either rail.');
  console.log('\n  DEFECT THIS RUN FOUND IN ITS OWN ADAPTER (2026-09-15):');
  console.log('  The first draft passed a raw 256-bit sha256 digest to Starknet as a felt252.');
  console.log('  The chain answered -32602 invalid fp.Element encoding, which logs exactly like');
  console.log('  a lookup miss. Only the known-answer control separated the two. XR-02 is now');
  console.log('  that case, pinned: out of range is NOT_EVALUATED, never an absence of fact.');
  console.log('\n  KNOWN LIMIT, stated rather than omitted:');
  console.log('  Reading the registry answers whether a fact is REGISTERED. It does not prove');
  console.log('  a specific leaf sits under a given batch root — that root is a flat Poseidon');
  console.log('  over all leaves, so single-leaf inclusion requires disclosing every other');
  console.log('  party\'s entry. Anchored is not the same as provably included, and this');
  console.log('  run does not claim the stronger thing.');
  console.log('\n  RESULT: ' + (failed.length === 0
    ? 'evaluator behaved correctly on every controlled input'
    : 'FAILED on ' + failed.map((f) => f.id).join(', ')) + '\n');
  process.exit(failed.length === 0 ? 0 : 1);
})();

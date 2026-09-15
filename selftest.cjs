#!/usr/bin/env node
'use strict';
/**
 * Assurance Run v0.1 — acceptance contract, executable.
 *
 * Every case below is a PROHIBITION: a thing the kernel must refuse to do.
 * The suite also runs a discrimination control — a deliberately permissive
 * evaluator that MUST fail these cases. A suite that cannot fail is as
 * uninformative as one that never passes.
 */

const K = require('./kernel.cjs');
const A = require('./adapters.cjs');

const P = { source: 'https://example.test/x', observer: 'test', capture_method: 'unit',
  observed_at: '2026-09-15T00:00:00Z', raw_digest: 'd', adapter_version: 'test/0.1' };

const SPEC = {
  event_id: 'evt-1', claim: 'order filled 10 @ 1.25', source: 'https://example.test/x',
  expected: { symbol: 'AAPL', qty: '10', price: '1.25' }, frozen_at: '2026-09-15T00:00:00Z',
};

const CASES = [
  { id: 'AC-01', name: 'no check attempted -> NOT_EVALUATED',
    spec: SPEC, ev: { attempted: false }, want: K.NOT_EVALUATED },

  { id: 'AC-02', name: 'real attempt, source unreachable -> INDETERMINATE',
    spec: SPEC, want: K.INDETERMINATE,
    ev: { attempted: true, reachable: false, independence_class: K.INDEPENDENT, ...P } },

  { id: 'AC-03', name: 'independent retrieval, fields match -> AGREE',
    spec: SPEC, want: K.AGREE,
    ev: { attempted: true, reachable: true, independence_class: K.INDEPENDENT, ...P,
      observed: { symbol: 'AAPL', qty: '10', price: '1.25' } } },

  { id: 'AC-04', name: 'independent retrieval, field contradicts -> DISAGREE',
    spec: SPEC, want: K.DISAGREE,
    ev: { attempted: true, reachable: true, independence_class: K.INDEPENDENT, ...P,
      observed: { symbol: 'AAPL', qty: '10', price: '1.31' } } },

  { id: 'AC-05', name: 'SELF-REPORTED evidence that MATCHES -> never AGREE',
    spec: SPEC, want: K.INDETERMINATE, wantReason: 'INSUFFICIENT_INDEPENDENCE',
    ev: { attempted: true, reachable: true, independence_class: K.SELF_REPORTED, ...P,
      observed: { symbol: 'AAPL', qty: '10', price: '1.25' } } },

  { id: 'AC-06', name: 'unknown schema -> NOT_EVALUATED, never pass or false',
    spec: SPEC, want: K.NOT_EVALUATED,
    ev: { attempted: true, reachable: true, schema_supported: false,
      independence_class: K.INDEPENDENT, ...P } },

  { id: 'AC-07', name: 'evidence without provenance is not evidence -> NOT_EVALUATED',
    spec: SPEC, want: K.NOT_EVALUATED,
    ev: { attempted: true, reachable: true, observed: { symbol: 'AAPL', qty: '10', price: '1.25' } } },

  { id: 'AC-08', name: 'zero under a non-exact scheme -> INDETERMINATE, never "nobody paid"',
    want: K.INDETERMINATE, wantReason: 'ZERO_UNDER_NONEXACT_SCHEME',
    spec: { ...SPEC, scheme: 'escrow', expected: { state: 'PAID' } },
    ev: { attempted: true, reachable: true, independence_class: K.INDEPENDENT, ...P,
      observed: { state: 'ZERO_OBSERVED' } } },

  { id: 'AC-09', name: 'third-party attested match is still not independent -> INDETERMINATE',
    spec: SPEC, want: K.INDETERMINATE, wantReason: 'INSUFFICIENT_INDEPENDENCE',
    ev: { attempted: true, reachable: true, independence_class: K.THIRD_PARTY, ...P,
      observed: { symbol: 'AAPL', qty: '10', price: '1.25' } } },
];

// A deliberately permissive evaluator: matches -> AGREE, everything else pass.
function brokenEvaluate(frozen, ev) {
  if (!ev || !ev.observed) return { verdict: K.AGREE, reason: 'BROKEN_DEFAULT_PASS' };
  for (const [k, v] of Object.entries(frozen.expected)) {
    if (ev.observed[k] !== v) return { verdict: K.DISAGREE, reason: 'BROKEN' };
  }
  return { verdict: K.AGREE, reason: 'BROKEN' };
}

function runSuite(evaluator) {
  const out = [];
  for (const c of CASES) {
    const frozen = K.freeze(c.spec);
    let got;
    try { got = evaluator(frozen, c.ev); }
    catch (err) { got = { verdict: 'THREW:' + err.message, reason: '' }; }
    const okVerdict = got.verdict === c.want;
    const okReason = !c.wantReason || got.reason === c.wantReason;
    out.push({ ...c, got, pass: okVerdict && okReason });
  }
  return out;
}

(async function main() {
  console.log('\n  ' + K.VERSION + ' — acceptance contract\n  ' + '-'.repeat(68));

  const real = runSuite(K.evaluate);
  for (const r of real) {
    console.log(`  ${r.pass ? 'ok  ' : 'FAIL'}  ${r.id}  ${r.name}`);
    if (!r.pass) console.log(`        wanted ${r.want}${r.wantReason ? '/' + r.wantReason : ''}, got ${r.got.verdict}/${r.got.reason}`);
  }
  const failed = real.filter((r) => !r.pass);

  // Discrimination control: the broken evaluator MUST fail several of these.
  const broken = runSuite(brokenEvaluate);
  const brokenCaught = broken.filter((r) => !r.pass).map((r) => r.id);
  console.log('\n  DISCRIMINATION CONTROL — a permissive evaluator must be caught');
  console.log('        caught on: ' + (brokenCaught.join(', ') || 'NOTHING — the suite cannot fail'));

  // Replay determinism on a real signed receipt.
  console.log('\n  REPLAY');
  const rec = await K.run(
    { ...SPEC, source: 'about:blank' },
    A.counterpartyReport({ symbol: 'AAPL', qty: '10', price: '1.25' }, { observed_at: '2026-09-15T00:00:00Z' })
  );
  const rp = K.replay(rec);
  const replayOk = rp.verdict_matches && rp.digest_matches && rp.signature_valid;
  console.log(`  ${replayOk ? 'ok  ' : 'FAIL'}  AC-10  replay reproduces verdict, digest and signature`);
  console.log(`        verdict=${rec.verdict}/${rec.reason}  digest_match=${rp.digest_matches}  sig_valid=${rp.signature_valid}`);

  const allOk = failed.length === 0 && brokenCaught.length >= 3 && replayOk;
  console.log('\n  ' + '-'.repeat(68));
  console.log('  RESULT: ' + (allOk ? 'all prohibitions held' : 'CONTRACT VIOLATED') + '\n');
  process.exit(allOk ? 0 : 1);
})();

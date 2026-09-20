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

const FIXED = '2026-09-15T00:00:00Z';
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

  { id: 'AC-11', name: 'OUR adapter threw -> NOT_EVALUATED, never "source unreachable"',
    spec: SPEC, want: K.NOT_EVALUATED, wantReason: 'ADAPTER_FAILED',
    ev: { attempted: true, adapter_failed: true, error: 'ReferenceError: now is not defined',
      independence_class: K.INDEPENDENT, ...P } },

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

  // ADAPTER SMOKE: every exported adapter must survive one real invocation.
  // All three suites passed for hours while httpPublic threw on every call,
  // because nothing ever invoked it. A suite that never runs a component is not
  // evidence that the component works.
  console.log('\n  ADAPTER SMOKE — every adapter must produce a verdict that is not ADAPTER_FAILED');
  const smokeAdapters = [
    ['httpPublic', A.httpPublic, { source: 'https://example.com/', expected: { unused: '1' } }],
    ['counterpartyReport', A.counterpartyReport({ unused: '1' }, { observed_at: FIXED }), { source: 'about:blank', expected: { unused: '1' } }],
  ];
  let smokeOk = true;
  for (const [nm, ad, extra] of smokeAdapters) {
    const r = await K.run({ ...SPEC, ...extra }, ad, { observed_at: FIXED });
    const bad = r.reason === 'ADAPTER_FAILED';
    if (bad) smokeOk = false;
    console.log(`  ${bad ? 'FAIL' : 'ok  '}  ${nm.padEnd(20)} ${r.verdict}/${r.reason}${bad ? '  ' + (r.detail || r.evidence.error) : ''}`);
  }

  // ADAPTER FAULT BOUNDARY — AC-11 was pinned at the wrong layer.
  //
  // AC-11 hands the evaluator `adapter_failed: true` and checks it answers
  // NOT_EVALUATED. It passed from the day it was written. What it never checked
  // is whether any adapter SETS that flag — and none did: every one caught its
  // own exceptions into `reachable: false` before the kernel's guard could see
  // them. Proved 2026-09-19 against the shipped 0.1.1: a `require()` of a
  // missing module and a URL we malformed ourselves BOTH reported the source as
  // unreachable. A conformance case that cannot reach the code path it names is
  // the false-green this corpus exists to prohibit, committed by the corpus.
  //
  // These cases run the REAL adapters against real faults. AC-14 is the control:
  // if the classifier simply charged everything to the instrument, the split
  // would be worthless, so a genuinely dead host must still read as the source.
  console.log('\n  ADAPTER FAULT BOUNDARY — our fault vs theirs, decided at the adapter');
  const savedTruth = process.env.ASSURANCE_X402_TRUTH;
  process.env.ASSURANCE_X402_TRUTH = require('path').join(__dirname, 'no-such-module.cjs');
  const faultCases = [
    ['AC-12', 'require() of a missing reader -> NOT_EVALUATED/ADAPTER_FAILED',
      A.baseX402, { source: 'https://example.test/x', resource: '0xdead', expected: { state: 'PAID' } },
      K.NOT_EVALUATED, 'ADAPTER_FAILED'],
    ['AC-13', 'a URL WE malformed -> NOT_EVALUATED, never "source unreachable"',
      A.httpPublic, { source: 'htp:/not a url', expected: { unused: '1' } },
      K.NOT_EVALUATED, 'ADAPTER_FAILED'],
    ['AC-14', 'CONTROL: a genuinely dead host -> INDETERMINATE/SOURCE_UNREACHABLE',
      A.httpPublic, { source: 'https://host-that-cannot-resolve-xyzzy.invalid/x', expected: { unused: '1' } },
      K.INDETERMINATE, 'SOURCE_UNREACHABLE'],
  ];
  let faultOk = true;
  for (const [id, name, ad, extra, wantV, wantR] of faultCases) {
    const r = await K.run({ ...SPEC, ...extra }, ad, { observed_at: FIXED });
    const pass = r.verdict === wantV && r.reason === wantR;
    if (!pass) faultOk = false;
    console.log(`  ${pass ? 'ok  ' : 'FAIL'}  ${id}  ${name}`);
    if (!pass) console.log(`        wanted ${wantV}/${wantR}, got ${r.verdict}/${r.reason}`);
  }
  // Not wired at all is a fourth thing: nobody was asked anything.
  delete process.env.ASSURANCE_X402_TRUTH;
  const nw = await K.run({ ...SPEC, source: 'https://example.test/x', resource: '0xdead',
    expected: { state: 'PAID' } }, A.baseX402, { observed_at: FIXED });
  const nwPass = nw.verdict === K.NOT_EVALUATED && nw.reason === 'ADAPTER_NOT_CONFIGURED';
  if (!nwPass) faultOk = false;
  console.log(`  ${nwPass ? 'ok  ' : 'FAIL'}  AC-15  an unwired adapter -> NOT_EVALUATED/ADAPTER_NOT_CONFIGURED`);
  if (!nwPass) console.log(`        wanted NOT_EVALUATED/ADAPTER_NOT_CONFIGURED, got ${nw.verdict}/${nw.reason}`);
  if (savedTruth !== undefined) process.env.ASSURANCE_X402_TRUTH = savedTruth;

  // ---- AC-16..19: the derivation gate. A gate with no test is a gate we are
  // asserting works, which is the defect it exists to stop, applied to itself.
  let gateOk = true;
  const gate = (id, name, fn) => {
    let pass = false, why = '';
    try { pass = fn() === true; } catch (e) { why = e.message.split('\n')[0]; }
    if (!pass) gateOk = false;
    console.log(`  ${pass ? 'ok  ' : 'FAIL'}  ${id}  ${name}`);
    if (!pass && why) console.log(`        threw: ${why}`);
  };

  gate('AC-16', 'a hardcoded literal at a load-bearing path is REFUSED, not published', () => {
    const obj = { rows: [{ id: 'a', col: K.derived(true, 'computed here') }, { id: 'b', col: false }] };
    try { K.sealDerived(obj, ['rows[].col']); return false; } // must not reach
    catch (e) {
      return e.code === 'DERIVATION_GATE' && e.undeclared.length === 1 &&
        e.undeclared[0].path === 'rows.1.col';
    }
  });

  gate('AC-17', 'a derived value publishes, unwrapped, with its source recorded', () => {
    const obj = { rows: [{ id: 'a', col: K.derived(true, 'classifier over 10 declared values') }] };
    const prov = K.sealDerived(obj, ['rows[].col']);
    return obj.rows[0].col === true && prov['rows.0.col'] === 'classifier over 10 declared values';
  });

  gate('AC-18', 'derived() with no named source is rejected at the mint, not at publication', () => {
    try { K.derived(true); return false; } catch (e) { return /DERIVED_REQUIRES_SOURCE/.test(e.message); }
  });

  gate('AC-19', 'a MISSING load-bearing field is refused too, not silently skipped', () => {
    const obj = { rows: [{ id: 'a' }] };
    try { K.sealDerived(obj, ['rows[].col']); return false; }
    catch (e) { return e.code === 'DERIVATION_GATE' && e.undeclared[0].value_typed_in === '(missing)'; }
  });

  const allOk = failed.length === 0 && brokenCaught.length >= 3 && replayOk && smokeOk && faultOk && gateOk;
  console.log('\n  ' + '-'.repeat(68));
  console.log('  RESULT: ' + (allOk ? 'all prohibitions held' : 'CONTRACT VIOLATED') + '\n');
  process.exit(allOk ? 0 : 1);
})();

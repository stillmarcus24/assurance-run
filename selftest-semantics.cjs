#!/usr/bin/env node
'use strict';
/**
 * Assurance Run — evidence-semantics acceptance contract, executable.
 *
 * Companion to selftest.cjs. That suite proves the four-state evaluator
 * cannot be talked into a false pass. This one proves the three semantics
 * a bare evidence record cannot express — capture relationship, per-state
 * evidence binding, typed references — hold the same prohibitions.
 *
 * Same discipline as the kernel suite: every case is a PROHIBITION, and a
 * deliberately permissive implementation is run against the same cases and
 * must be caught. A control that rejects nothing and a control that rejects
 * everything are equally uninformative.
 */

const K = require('./kernel.cjs');
const S = require('./semantics.cjs');

// ---------------------------------------------------------------- fixtures
const EV_A = { kind: 'settlement', rail: 'eip155:8453', tx: '0xabc' };
const EV_B = { kind: 'delivery', url: 'https://example.test/receipt' };
const DIG_A = K.sha256(K.canonical(EV_A));
const DIG_B = K.sha256(K.canonical(EV_B));

const CASES = [
  // ------------------------------------------------ capture relationship
  { id: 'SC-01', name: 'no parties asserted -> NOT_EVALUATED, never independent',
    want: K.NOT_EVALUATED,
    run: (m) => m.captureRelationship(undefined) },

  { id: 'SC-02', name: 'observer named but executor absent -> NOT_EVALUATED',
    want: K.NOT_EVALUATED, wantReason: 'CAPTURE_RELATIONSHIP_UNSTATED',
    run: (m) => m.captureRelationship({ observer: 'auditor.example' }) },

  { id: 'SC-03', name: 'observer IS executor -> never AGREE (self-report)',
    want: K.INDETERMINATE, wantReason: 'OBSERVER_IS_EXECUTOR',
    run: (m) => m.captureRelationship({ observer: 'acme.example', executor: 'acme.example' }) },

  { id: 'SC-04', name: 'observer distinct from executor -> AGREE',
    want: K.AGREE,
    run: (m) => m.captureRelationship({ observer: 'auditor.example', executor: 'acme.example' }) },

  { id: 'SC-05', name: 'record claims independence its own parties contradict -> DISAGREE',
    want: K.DISAGREE, wantReason: 'DECLARED_INDEPENDENCE_CONTRADICTED_BY_PARTIES',
    run: (m) => m.checkDeclaredIndependence(
      { observer: 'acme.example', executor: 'acme.example' }, K.INDEPENDENT) },

  // -------------------------------------------- per-state evidence binding
  { id: 'SC-06', name: 'state asserted with no evidence -> NOT_EVALUATED, never settled',
    want: K.NOT_EVALUATED, wantReason: 'STATE_ASSERTED_WITHOUT_EVIDENCE',
    run: (m) => { const r = m.bindStates([{ state: 'settled' }], {}); return r.bindings[0]; } },

  { id: 'SC-07', name: 'state names evidence absent from the bundle -> INDETERMINATE',
    want: K.INDETERMINATE, wantReason: 'EVIDENCE_REFERENCED_BUT_ABSENT',
    run: (m) => { const r = m.bindStates([{ state: 'settled', evidence_digest: DIG_A }], {}); return r.bindings[0]; } },

  { id: 'SC-08', name: 'evidence present but does not hash to its digest -> DISAGREE',
    want: K.DISAGREE, wantReason: 'EVIDENCE_DIGEST_MISMATCH',
    run: (m) => { const r = m.bindStates([{ state: 'settled', evidence_digest: DIG_A }],
      { [DIG_A]: { kind: 'settlement', rail: 'eip155:8453', tx: '0xTAMPERED' } }); return r.bindings[0]; } },

  { id: 'SC-09', name: 'each state binds its own evidence -> AGREE per state',
    want: K.AGREE,
    run: (m) => m.bindStates(
      [{ state: 'settled', evidence_digest: DIG_A }, { state: 'delivered', evidence_digest: DIG_B }],
      { [DIG_A]: EV_A, [DIG_B]: EV_B }) },

  { id: 'SC-10', name: 'one anchor does NOT cover a second unbacked state',
    want: K.NOT_EVALUATED,
    run: (m) => m.bindStates(
      [{ state: 'settled', evidence_digest: DIG_A }, { state: 'delivered' }],
      { [DIG_A]: EV_A }) },

  // ------------------------------------------------------- typed references
  { id: 'SC-11', name: 'untyped ref -> NOT_EVALUATED, never authoritative',
    want: K.NOT_EVALUATED, wantReason: 'REF_UNTYPED',
    run: (m) => { const r = m.checkRefs([{ target: 'urn:x' }]); return r.refs[0]; } },

  { id: 'SC-12', name: 'unknown ref type -> NOT_EVALUATED, never pass or false',
    want: K.NOT_EVALUATED, wantReason: 'REF_TYPE_UNSUPPORTED',
    run: (m) => { const r = m.checkRefs([{ type: 'invented-2031', target: 'urn:x' }]); return r.refs[0]; } },

  { id: 'SC-13', name: 'typed ref with no target -> DISAGREE',
    want: K.DISAGREE, wantReason: 'REF_TYPE_WITHOUT_TARGET',
    run: (m) => { const r = m.checkRefs([{ type: 'supersedes' }]); return r.refs[0]; } },

  { id: 'SC-14', name: 'pre-action verification reference is well formed -> AGREE',
    want: K.AGREE,
    run: (m) => m.checkRefs([{ type: 'verifies-precondition', target: 'urn:evidence:pre-1' }]) },

  // ------------------------------------------- correction without mutation
  { id: 'SC-15', name: 'a correction replaces interpretation, not history -> AGREE',
    want: K.AGREE, wantReason: 'SINGLE_CURRENT_INTERPRETATION',
    run: (m) => m.currentInterpretation([
      { id: 'rec-1', refs: [] },
      { id: 'rec-2', refs: [{ type: 'corrects', target: 'rec-1' }] },
    ]) },

  { id: 'SC-16', name: 'two unreplaced records -> INDETERMINATE, never pick one silently',
    want: K.INDETERMINATE, wantReason: 'MULTIPLE_LIVE_RECORDS',
    run: (m) => m.currentInterpretation([{ id: 'rec-1', refs: [] }, { id: 'rec-2', refs: [] }]) },

  { id: 'SC-17', name: 'a supersession cycle resolves to nothing -> INDETERMINATE',
    want: K.INDETERMINATE, wantReason: 'ALL_RECORDS_REPLACED_CYCLE',
    run: (m) => m.currentInterpretation([
      { id: 'rec-1', refs: [{ type: 'supersedes', target: 'rec-2' }] },
      { id: 'rec-2', refs: [{ type: 'supersedes', target: 'rec-1' }] },
    ]) },
];

// A deliberately permissive implementation: everything is fine, everything
// is independent, every state is supported, every reference is authoritative.
const permissive = {
  captureRelationship: () => ({ verdict: K.AGREE, reason: 'PERMISSIVE' }),
  checkDeclaredIndependence: () => ({ verdict: K.AGREE, reason: 'PERMISSIVE' }),
  bindStates: (states) => ({ verdict: K.AGREE, reason: 'PERMISSIVE',
    bindings: (states || []).map((s) => ({ state: s && s.state, verdict: K.AGREE, reason: 'PERMISSIVE' })) }),
  checkRefs: (refs) => ({ verdict: K.AGREE, reason: 'PERMISSIVE',
    refs: (refs || []).map(() => ({ verdict: K.AGREE, reason: 'PERMISSIVE' })) }),
  currentInterpretation: () => ({ verdict: K.AGREE, reason: 'PERMISSIVE' }),
};

function runSuite(mod) {
  return CASES.map((c) => {
    let got;
    try { got = c.run(mod); }
    catch (err) { got = { verdict: 'THREW:' + err.message, reason: '' }; }
    got = got || { verdict: 'UNDEFINED', reason: '' };
    const pass = got.verdict === c.want && (!c.wantReason || got.reason === c.wantReason);
    return { ...c, got, pass };
  });
}

(function main() {
  console.log('\n  ' + K.VERSION + ' — evidence-semantics acceptance contract\n  ' + '-'.repeat(68));

  const real = runSuite(S);
  let section = '';
  for (const r of real) {
    const head = r.id <= 'SC-05' ? 'capture relationship'
      : r.id <= 'SC-10' ? 'per-state evidence binding'
        : r.id <= 'SC-14' ? 'typed references' : 'correction without mutation';
    if (head !== section) { console.log('\n  [' + head + ']'); section = head; }
    console.log(`  ${r.pass ? 'ok  ' : 'FAIL'}  ${r.id}  ${r.name}`);
    if (!r.pass) console.log(`        wanted ${r.want}${r.wantReason ? '/' + r.wantReason : ''}, got ${r.got.verdict}/${r.got.reason}`);
  }
  const failed = real.filter((r) => !r.pass);

  const caught = runSuite(permissive).filter((r) => !r.pass).map((r) => r.id);
  console.log('\n  DISCRIMINATION CONTROL — a permissive implementation must be caught');
  console.log('        caught on: ' + (caught.join(', ') || 'NOTHING — the suite cannot fail'));

  const allOk = failed.length === 0 && caught.length >= 10;
  console.log('\n  ' + '-'.repeat(68));
  console.log('  RESULT: ' + (allOk ? 'all prohibitions held' : 'CONTRACT VIOLATED') + '\n');
  process.exit(allOk ? 0 : 1);
})();

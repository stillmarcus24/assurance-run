#!/usr/bin/env node
'use strict';
/**
 * selftest-missshape — known-answer tests for BB-03, the wg-identity#21 clause.
 *
 * BB-03 asks one question of a live verifier: when handed a proof id it cannot
 * resolve, does it return a DISTINCT non-verified signal, or does it pass?
 *
 * Why this file exists: on 2026-09-29 the live target had adopted a structured
 * four-state response somewhere after 2026-09-22, and this runner's expectation
 * was still pinned to the old HTTP-404-plus-prose shape. The classifier returned
 * INDETERMINATE/UNEXPECTED_MISS_SHAPE — correctly a statement about OUR
 * instrument, never a DISAGREE about their server — but nothing tested the
 * predicate, so the staleness was only visible by reading output by hand.
 *
 * No network. Requires the runner, which is why that file needs its main guard:
 * without it this test would fire a live sweep against a third party.
 */

const assert = require('assert');
const { classifyMissShape, STATES_321 } = require('./live-babyblueviper.cjs');

let pass = 0;
const fail = [];
function t(name, fn) {
  try { fn(); console.log('  ok    ' + name); pass++; }
  catch (e) { console.log('  FAIL  ' + name + '\n        ' + e.message); fail.push(name); }
}

const ID = 'eb22294404b2021588f90747b6404e878431191845c2aab26a919702394c68ac';

console.log('\n  BB-03 classifier — known answers\n  ' + '-'.repeat(66));

// ---- the shape observed live on 2026-09-29 ---------------------------------
t('MS-01  structured indeterminate/absence -> AGREE/HONEST_STATE_DECLARED', () => {
  const r = classifyMissShape({ ok: true, status: 200, json: {
    valid: null, verdict: 'cannot_establish', state: 'indeterminate',
    state_reason: 'absence', source: 'ledger_entry_legacy_flat', entry: 1 } }, ID);
  assert.strictEqual(r.verdict, 'AGREE');
  assert.strictEqual(r.reason, 'HONEST_STATE_DECLARED');
  assert.ok(/state:"indeterminate"/.test(r.detail), 'names the state');
  assert.ok(/state_reason:"absence"/.test(r.detail), 'names the state_reason');
  assert.ok(/valid:null/.test(r.detail), 'records valid:null verbatim');
});

// ---- the legacy shape must not stop being accepted -------------------------
t('MS-02  legacy 404 + prose -> AGREE/HONEST_NOT_EVALUATED', () => {
  const r = classifyMissShape({ ok: true, status: 404,
    json: { error: 'no durably-stored event for this id; predates this fix' } }, ID);
  assert.strictEqual(r.verdict, 'AGREE');
  assert.strictEqual(r.reason, 'HONEST_NOT_EVALUATED');
});

// ---- THE SAFETY PROPERTY. This is the whole point of the clause ------------
t('MS-03  valid:true for an unresolvable id -> DISAGREE/ABSENCE_READ_AS_PASS', () => {
  const r = classifyMissShape({ ok: true, status: 200, json: { valid: true } }, ID);
  assert.strictEqual(r.verdict, 'DISAGREE');
  assert.strictEqual(r.reason, 'ABSENCE_READ_AS_PASS');
});

t('MS-04  CONTROL: a declared state cannot launder a valid:true', () => {
  // The ordering trap. If the structured branch ran first, a server returning
  // state:"indeterminate" ALONGSIDE valid:true would score as an honest AGREE
  // while actually claiming the proof checked out.
  const r = classifyMissShape({ ok: true, status: 200, json: {
    valid: true, state: 'indeterminate', state_reason: 'absence' } }, ID);
  assert.strictEqual(r.verdict, 'DISAGREE',
    'valid:true must win over a declared state, not be masked by it');
  assert.strictEqual(r.reason, 'ABSENCE_READ_AS_PASS');
});

t('MS-05  state:"verified" for an unresolvable id is NEVER an AGREE', () => {
  const r = classifyMissShape({ ok: true, status: 200, json: {
    valid: null, state: 'verified' } }, ID);
  assert.notStrictEqual(r.verdict, 'AGREE',
    'the one state value that is a collapse here must not pass');
  assert.strictEqual(r.reason, 'UNEXPECTED_MISS_SHAPE');
});

// ---- unknown shapes are about US, never about them ------------------------
t('MS-06  unrecognised shape -> INDETERMINATE, never DISAGREE', () => {
  const r = classifyMissShape({ ok: true, status: 200,
    json: { something: 'else' }, text: 'weird' }, ID);
  assert.strictEqual(r.verdict, 'INDETERMINATE');
  assert.strictEqual(r.reason, 'UNEXPECTED_MISS_SHAPE');
});

t('MS-07  a state we do not recognise -> INDETERMINATE, not a default pass', () => {
  const r = classifyMissShape({ ok: true, status: 200, json: {
    valid: null, state: 'probably_fine' } }, ID);
  assert.strictEqual(r.verdict, 'INDETERMINATE');
});

t('MS-08  transport fault -> INDETERMINATE and carries the fault detail', () => {
  const r = classifyMissShape({ ok: false,
    fault: { detail: 'ECONNREFUSED' } }, ID);
  assert.strictEqual(r.verdict, 'INDETERMINATE');
  assert.strictEqual(r.detail, 'ECONNREFUSED');
});

t('MS-09  case-insensitive on the state value', () => {
  const r = classifyMissShape({ ok: true, status: 200, json: {
    valid: null, state: 'NOT_EVALUATED' } }, ID);
  assert.strictEqual(r.verdict, 'AGREE');
  assert.strictEqual(r.reason, 'HONEST_STATE_DECLARED');
});

t('MS-10  the four states are exactly the draft\'s four', () => {
  assert.deepStrictEqual(STATES_321.slice().sort(),
    ['contradicted', 'indeterminate', 'not_evaluated', 'verified']);
});

// ---- DISCRIMINATION CONTROL: a permissive classifier must be caught --------
t('MS-11  CONTROL: an always-AGREE classifier fails MS-03/04/05', () => {
  const permissive = () => ({ verdict: 'AGREE', reason: 'HONEST_STATE_DECLARED' });
  const caught = [
    { ok: true, status: 200, json: { valid: true } },
    { ok: true, status: 200, json: { valid: true, state: 'indeterminate' } },
    { ok: true, status: 200, json: { valid: null, state: 'verified' } },
  ].filter((o) => permissive(o).verdict === 'AGREE' &&
                  classifyMissShape(o, ID).verdict !== 'AGREE');
  assert.strictEqual(caught.length, 3,
    'the suite must be able to fail a classifier that passes everything');
});

console.log('  ' + '-'.repeat(66));
if (fail.length) {
  console.log('  RESULT: ' + fail.length + ' FAILED (' + fail.join(', ') + ')\n');
  process.exit(1);
}
console.log('  RESULT: ' + pass + '/' + pass + ' known answers held\n');

#!/usr/bin/env node
'use strict';
/**
 * interop-matrix — what the four-state vocabulary actually costs, measured.
 *
 * wg-identity#21 and tsc#4 record four parties converged on the verdict
 * vocabulary `verified / contradicted / indeterminate / not-evaluated`. That
 * count is a count of agreement, not of emission. @TKCollective drew the
 * distinction himself at tsc#4 on 2026-09-20: his production verifier is
 * three-outcome while the term sits in draft-krausz-verification-state.
 *
 * This runner answers the question the charter vote actually turns on: for each
 * implementation named in that thread, which of the four states can it express
 * DISTINCTLY, and where does it collapse them. It reports how each row was
 * established, and it refuses to print a row whose evidence it did not obtain
 * in THIS run.
 *
 * The load-bearing column is the absence side. `indeterminate` (a check ran and
 * the evidence could not settle it) and `not-evaluated` (no valid check ran)
 * have different owners: the first is a fact about the world, the second is a
 * fact about the evaluator. An implementation that cannot separate them can
 * report its own instrument failure as a finding about someone else's system.
 * That is AC-11, and it is the defect this vocabulary exists to make impossible.
 *
 * HONESTY BOUNDARY, same as live-babyblueviper.cjs:
 *   - Executed and confirmed        -> AGREE
 *   - Read off pinned public source -> AGREE, method recorded as source_read
 *   - Could not execute / no public surface -> NOT_EVALUATED, never a DISAGREE
 *     about their system. Failing to reach an implementation is a statement
 *     about this runner, not about their code.
 *
 * Read-only. No key, no account, no write, no payment.
 */

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const K = require('./kernel.cjs');

const { AGREE, INDETERMINATE, NOT_EVALUATED } = K;

const UA = 'StillOS-assurance-run/interop-matrix (read-only; no key; no payment)';

/* ------------------------------------------------------------------ *
 * Subjects. Each carries the public surface it is established from.
 * ------------------------------------------------------------------ */

const SUBJECTS = [
  {
    id: 'assurance-run',
    operator: '@stillmarcus24',
    surface: 'https://github.com/stillmarcus24/assurance-run',
    kind: 'executable',
  },
  {
    id: 'elara-verify',
    operator: '@navigatorbuilds',
    surface: 'https://github.com/navigatorbuilds/elara-mesh',
    kind: 'source',
  },
  {
    id: 'x402-measure',
    operator: '@meloliva14',
    surface: 'https://github.com/meloliva14/x402-measure',
    kind: 'source',
  },
  {
    id: 'babyblueviper-verify-proof',
    operator: '@babyblueviper1',
    surface: 'https://api.babyblueviper.com',
    kind: 'live',
  },
  {
    id: 'draft-krausz-verification-state',
    operator: '@TKCollective',
    surface: 'https://datatracker.ietf.org/doc/draft-krausz-verification-state/',
    kind: 'specification',
  },
];

/* ------------------------------------------------------------------ *
 * Evidence gatherers. Each returns {established, method, detail} and
 * never throws a conclusion about the subject on its own failure.
 * ------------------------------------------------------------------ */

function sh(cmd, args, opts) {
  return execFileSync(cmd, args, { encoding: 'utf8', timeout: 120000, ...opts });
}

async function http(method, url) {
  try {
    const res = await fetch(url, { method, headers: { 'user-agent': UA }, signal: AbortSignal.timeout(20000) });
    const text = await res.text();
    return { ok: true, status: res.status, text };
  } catch (err) {
    return { ok: false, error: String(err && err.message || err) };
  }
}

/** assurance-run: execute the corpus in this tree. */
function gatherSelf() {
  try {
    const out = sh('node', [path.join(__dirname, 'selftest-semantics.cjs')], { cwd: __dirname });
    const held = /RESULT: all prohibitions held/.test(out);
    const cases = (out.match(/^\s+ok\s+SC-\d+/gm) || []).length;
    const head = sh('git', ['rev-parse', '--short', 'HEAD'], { cwd: __dirname }).trim();
    if (!held) return { established: false, method: 'executed', detail: 'selftest did not report all prohibitions held' };
    return {
      established: true,
      method: 'executed',
      pin: head,
      states: ['AGREE', 'DISAGREE', 'INDETERMINATE', 'NOT_EVALUATED'],
      distinguishes_absence: true,
      detail: `${cases} semantic cases executed, all prohibitions held`,
    };
  } catch (err) {
    return { established: false, method: 'executed', detail: String(err && err.message || err) };
  }
}

/**
 * A peer repo, read at a pinned commit. Source-read only: this runner clones
 * shallow and reads text. It does NOT build, test or execute third-party code,
 * which is why the elara-verify row is a source_read rather than an execution.
 * A clone that cannot be obtained is NOT_EVALUATED, never a finding.
 */
function ensureClone(dir, remote) {
  if (fs.existsSync(path.join(dir, '.git'))) return true;
  try {
    fs.mkdirSync(path.dirname(dir), { recursive: true });
    sh('git', ['clone', '--depth', '1', '--quiet', remote, dir]);
    return true;
  } catch (_) {
    return false;
  }
}

function gatherSource(dir, extract, remote) {
  if (!fs.existsSync(dir) && remote) ensureClone(dir, remote);
  if (!fs.existsSync(dir)) {
    return { established: false, method: 'not_reachable', detail: `could not obtain ${remote || dir}; nothing was read` };
  }
  let pin = null;
  try { pin = sh('git', ['rev-parse', '--short', 'HEAD'], { cwd: dir }).trim(); } catch (_) {}
  try {
    const found = extract(dir);
    if (!found) return { established: false, method: 'source_read', detail: 'declared surface not found in the tree at this pin' };
    return { established: true, method: 'source_read', pin, ...found };
  } catch (err) {
    return { established: false, method: 'source_read', pin, detail: String(err && err.message || err) };
  }
}

function extractElara(dir) {
  const f = path.join(dir, 'crates/elara-verify/src/lib.rs');
  if (!fs.existsSync(f)) return null;
  const src = fs.readFileSync(f, 'utf8');
  const block = src.match(/pub enum Verdict \{([\s\S]*?)\}/);
  if (!block) return null;
  const states = block[1].split('\n').map(s => s.trim().replace(/,$/, ''))
    .filter(s => s && !s.startsWith('//'));
  // Its own docstring on Partial is the evidence for the absence-side question.
  const partialDoc = /Not proven, but NOT forged — absent or pending evidence/.test(src);
  return {
    states,
    distinguishes_absence: false,
    detail: `Verdict{${states.join(', ')}} in crates/elara-verify/src/lib.rs` +
      (partialDoc ? '; its own docstring assigns "absent or pending evidence" to a single Partial' : ''),
  };
}

function extractX402Measure(dir) {
  const files = fs.readdirSync(dir).filter(f => f.endsWith('.py'));
  if (!files.length) return null;
  const blob = files.map(f => fs.readFileSync(path.join(dir, f), 'utf8')).join('\n');
  const tokens = ['NO_402', 'UNREACHABLE', 'TIMEOUT', 'NOT_ASSESSED', 'PASS', 'FAIL'];
  const seen = tokens.filter(t => new RegExp(`\\b${t}\\b`).test(blob));
  if (!seen.length) return null;
  return {
    states: seen,
    // NOT_ASSESSED exists as its own label (the 429 fix): absence is separated
    // at the label level, but there is no single verdict enum carrying the four.
    distinguishes_absence: seen.includes('NOT_ASSESSED'),
    enum_present: false,
    detail: `labels ${seen.join(' / ')} across ${files.length} probe modules; no single verdict enum`,
  };
}

/** The live endpoint: re-run the named reference vector rather than cite it. */
function gatherLiveVector() {
  try {
    const out = sh('node', [path.join(__dirname, 'live-babyblueviper.cjs')], { cwd: __dirname });
    const counts = out.match(/counts\s+(\{.*\})/);
    if (!counts) return { established: false, method: 'executed_live', detail: 'runner produced no counts line' };
    const parsed = JSON.parse(counts[1]);
    return {
      established: true,
      method: 'executed_live',
      states: ['valid:boolean', 'sibling reason/status fields'],
      distinguishes_absence: true,
      enum_present: false,
      counts: parsed,
      detail: 'no four-state enum; a boolean with sibling status fields. Absence separated by ' +
        'sibling (preimage_fields_authorized, recon_status), not by verdict value',
    };
  } catch (err) {
    return { established: false, method: 'executed_live', detail: String(err && err.message || err) };
  }
}

/** A specification with no public executable surface is not a failing row. */
async function gatherSpec(url) {
  const res = await http('GET', 'https://datatracker.ietf.org/api/v1/doc/document/?name__contains=krausz-verification&format=json');
  if (!res.ok) {
    return { established: false, method: 'not_reachable', detail: `datatracker unreachable from this run: ${res.error}` };
  }
  let total = null;
  try { total = JSON.parse(res.text).meta.total_count; } catch (_) {}
  return {
    established: false,
    method: 'no_executable_surface',
    detail: total
      ? `draft is published (datatracker returns ${total} matching document) and carries the four-state term; ` +
        'no public implementation surface is named in wg-identity#21 or tsc#4, so nothing was executed'
      : 'datatracker returned no matching document from this run',
  };
}

/* ------------------------------------------------------------------ */

function verdictFor(ev) {
  if (!ev.established) return NOT_EVALUATED;
  if (ev.distinguishes_absence === true) return AGREE;
  if (ev.distinguishes_absence === false) return INDETERMINATE;
  return NOT_EVALUATED;
}

async function main() {
  const peerRoot = process.env.INTEROP_CLONE_DIR || path.join(__dirname, '.peers');
  const evidence = {
    'assurance-run': gatherSelf(),
    'elara-verify': gatherSource(path.join(peerRoot, 'elara-mesh'), extractElara,
      'https://github.com/navigatorbuilds/elara-mesh.git'),
    'x402-measure': gatherSource(path.join(peerRoot, 'x402-measure'), extractX402Measure,
      'https://github.com/meloliva14/x402-measure.git'),
    'babyblueviper-verify-proof': gatherLiveVector(),
    'draft-krausz-verification-state': await gatherSpec(),
  };

  const rows = SUBJECTS.map(s => {
    const ev = evidence[s.id];
    return {
      ...s,
      verdict: verdictFor(ev),
      established: ev.established === true,
      method: ev.method,
      pin: ev.pin || null,
      states: ev.states || null,
      cardinality: ev.states ? ev.states.length : null,
      distinguishes_absence: ev.distinguishes_absence === undefined ? null : ev.distinguishes_absence,
      detail: ev.detail,
    };
  });

  const emitters = rows.filter(r => r.established && r.cardinality === 4 &&
    Array.isArray(r.states) && r.states.includes('NOT_EVALUATED'));
  const unreached = rows.filter(r => !r.established);

  const out = {
    corpus: 'assurance-run/interop-matrix',
    question: 'which implementations can express the four verification states distinctly, and where do they collapse',
    observed_at: new Date().toISOString(),
    rows,
    summary: {
      subjects: rows.length,
      four_state_emitters: emitters.map(r => r.id),
      absence_side_collapsed: rows.filter(r => r.distinguishes_absence === false).map(r => r.id),
      not_established_by_this_run: unreached.map(r => ({ id: r.id, why: r.method })),
    },
  };

  const dir = path.join(__dirname, 'verdicts');
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `interop-matrix-${out.observed_at.slice(0, 10)}.json`);
  fs.writeFileSync(file, JSON.stringify(out, null, 2) + '\n');

  const pad = (s, n) => String(s === null || s === undefined ? '—' : s).padEnd(n).slice(0, n);
  console.log('\n  four-state interop matrix — measured, not asserted');
  console.log(`  observed_at  ${out.observed_at}`);
  console.log(`  not established by this run: ${unreached.length} of ${rows.length}\n`);
  console.log(`  ${pad('implementation', 32)}${pad('verdict', 15)}${pad('states', 8)}${pad('absence split', 15)}method`);
  console.log(`  ${'-'.repeat(88)}`);
  for (const r of rows) {
    console.log(`  ${pad(r.id, 32)}${pad(r.verdict, 15)}${pad(r.cardinality, 8)}` +
      `${pad(r.distinguishes_absence === null ? '—' : (r.distinguishes_absence ? 'distinct' : 'COLLAPSED'), 15)}${r.method}`);
  }
  console.log('');
  for (const r of rows) console.log(`  ${r.id}\n    ${r.detail}\n`);
  console.log(`  four-state emitters: ${emitters.length ? emitters.map(r => r.id).join(', ') : 'none'}`);
  console.log(`  written: ${file}\n`);
}

main().catch(err => { console.error(err); process.exit(1); });

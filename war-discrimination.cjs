#!/usr/bin/env node
'use strict';
/*
 * war-discrimination.cjs — the control for war-verify.cjs.
 *
 * WHY. "A corpus that cannot fail proves nothing." A 90/90 run is only evidence
 * if the comparison has killing power, and the first full CLI run of war-verify
 * proved that is not a formality: the shipped entry point crashed on all 23 TSA
 * vectors (a TDZ ReferenceError) while the committed message read "90/90",
 * because the corpus had only ever been driven by require()ing runCorpus.
 *
 * TWO CONTROLS, both reported:
 *   1. ALWAYS-ACCEPT. A stub that returns vector 01's expected outcome for every
 *      vector. If the comparison is sound this scores near 1/90. A harness this
 *      passes is measuring nothing.
 *   2. MUTATION BATTERY. Each applicable mutation is applied to a vector's
 *      INPUTS and the real verifier is re-run. A mutation the verifier does not
 *      notice is a SURVIVOR: either a blind spot in the verifier or a rule no
 *      vector pins. Survivors are listed, never summarised away.
 *
 * Mutations are applied to a deep copy; the upstream corpus is never written.
 *
 *   node war-discrimination.cjs <corpus-dir>
 *   node war-discrimination.cjs <corpus-dir> --json
 */
const fs = require('fs');
const path = require('path');
const { verify } = require('./war-verify.cjs');

const clone = (o) => JSON.parse(JSON.stringify(o));
const outcomeKey = (o) => JSON.stringify(o, Object.keys(o).sort());

/** Flip the lowest bit of the last decoded byte, re-encoded canonically. */
function flipLastBit(b64) {
  let raw;
  try { raw = Buffer.from(b64, 'base64'); } catch { return null; }
  if (!raw.length) return null;
  const m = Buffer.from(raw);
  m[m.length - 1] ^= 0x01;
  return m.toString('base64');
}

/* Flip the lowest bit at byte `pos`, re-encoded canonically.
 *
 * ⚠️ WHY A SWEEP AND NOT ONE FLIP. The first version of this battery flipped the
 * LAST byte of a timestamp token and recorded 99 survivors, including
 * `01-valid / record-token-byte-flipped`. That was the control's defect, not the
 * verifier's: the imprint sits in the middle of the signed TSTInfo, so the final
 * byte of a DER response is often a field no outcome depends on. A survivor that
 * is an artefact of where the probe landed reads exactly like a blind spot.
 * A byte-flip mutation therefore sweeps positions and counts a kill if ANY of
 * them is noticed. */
function flipBitAt(b64, pos) {
  let raw;
  try { raw = Buffer.from(b64, 'base64'); } catch { return null; }
  if (pos >= raw.length) return null;
  const m = Buffer.from(raw);
  m[pos] ^= 0x01;
  return m.toString('base64');
}

const SWEEP_MAX = 64;
/** Evenly spread up to SWEEP_MAX byte positions over a decoded base64 value. */
function sweepPositions(b64) {
  let n;
  try { n = Buffer.from(b64, 'base64').length; } catch { return []; }
  if (!n) return [];
  if (n <= SWEEP_MAX) return Array.from({ length: n }, (_, i) => i);
  return Array.from({ length: SWEEP_MAX }, (_, i) => Math.floor((i * n) / SWEEP_MAX));
}

/* Each mutation declares:
 *   precondition(base) — is the vector's UNMUTATED outcome still clean for the
 *       rule this mutation attacks? A vector already reporting that failure
 *       cannot be pushed into it, so the probe carries no information and is
 *       NOT APPLIED rather than counted as a survivor. This is the second
 *       false-positive class the first run of this battery produced: 60-63
 *       (already SIGNATURE_INVALID), 67 (already CRITERIA_HASH_MISMATCH),
 *       70-74 (already an unusable genTime) and 77 (already refused) accounted
 *       for most of the 99.
 *   variants(inputs) — one or more mutated copies; a kill is ANY of them being
 *       noticed (see flipBitAt).
 */
const refused = (b) => b.refused === true || b.error !== undefined;
const has = (b, c) => Array.isArray(b.problem_codes) && b.problem_codes.includes(c);
const warned = (b, c) => Array.isArray(b.warning_codes) && b.warning_codes.includes(c);

const MUTATIONS = [
  {
    id: 'signature-bit-flipped',
    why: 'step 2 — a one-bit change in the Ed25519 signature must not verify',
    precondition: (b) => !refused(b) && b.signature_valid === true,
    variants: (i) => {
      const v = i.receipt && i.receipt.signature && i.receipt.signature.value;
      if (!v) return [];
      return sweepPositions(v).map((p) => {
        const m = flipBitAt(v, p);
        if (!m || m === v) return null;
        const o = clone(i); o.receipt.signature.value = m; return o;
      }).filter(Boolean);
    },
  },
  {
    id: 'signed-body-edited',
    why: 'step 2 — editing the signed receipt after signing must break the signature',
    precondition: (b) => !refused(b) && b.signature_valid === true,
    variants: (i) => {
      const r = i.receipt && i.receipt.receipt;
      if (!r || typeof r.receipt_id !== 'string') return [];
      const o = clone(i); o.receipt.receipt.receipt_id = r.receipt_id + '-EDITED'; return [o];
    },
  },
  {
    id: 'required-result-flipped-to-fail',
    why: 'property 4 — a required fail must make the recomputed verdict fail',
    precondition: (b) => !refused(b) && b.verdict_recomputed !== 'fail',
    variants: (i) => {
      const rs = i.receipt && i.receipt.receipt && i.receipt.receipt.results;
      if (!Array.isArray(rs)) return [];
      const n = rs.findIndex((x) => x && x.required === true && x.result !== 'fail');
      if (n < 0) return [];
      const o = clone(i); o.receipt.receipt.results[n].result = 'fail'; return [o];
    },
  },
  {
    id: 'criteria-file-byte-flipped',
    why: 'step 4 — another criteria document must not match criteria.sha256',
    precondition: (b) => !refused(b) && b.criteria_hash === 'match',
    variants: (i) => {
      const v = i.criteria_file_base64;
      if (typeof v !== 'string') return [];
      return sweepPositions(v).map((p) => {
        const m = flipBitAt(v, p);
        if (!m || m === v) return null;
        const o = clone(i); o.criteria_file_base64 = m; return o;
      }).filter(Boolean);
    },
  },
  {
    id: 'criteria-token-byte-flipped',
    why: 'step 5 — a token whose imprint moved must not establish commitment time',
    precondition: (b) => !refused(b)
      && !has(b, 'CRITERIA_TIMESTAMP_MISMATCH')
      && !warned(b, 'CRITERIA_COMMITMENT_UNVERIFIED'),
    variants: (i) => {
      const v = i.criteria_tsr_base64;
      if (typeof v !== 'string') return [];
      return sweepPositions(v).map((p) => {
        const m = flipBitAt(v, p);
        if (!m || m === v) return null;
        const o = clone(i); o.criteria_tsr_base64 = m; return o;
      }).filter(Boolean);
    },
  },
  {
    id: 'record-token-byte-flipped',
    why: 'step 6 — the record token must stop matching the canonical receipt',
    precondition: (b) => !refused(b) && b.receipt_timestamp === 'imprint_match',
    variants: (i) => {
      const v = i.receipt_tsr_base64;
      if (typeof v !== 'string') return [];
      return sweepPositions(v).map((p) => {
        const m = flipBitAt(v, p);
        if (!m || m === v) return null;
        const o = clone(i); o.receipt_tsr_base64 = m; return o;
      }).filter(Boolean);
    },
  },
  {
    id: 'signing-key-bit-flipped',
    why: 'step 2 — the signature must not verify under a different public key',
    precondition: (b) => !refused(b) && b.signature_valid === true,
    variants: (i) => {
      const ks = i.keys && i.keys.keys;
      const signed = i.receipt && i.receipt.receipt && i.receipt.receipt.key_id;
      if (!Array.isArray(ks) || !signed) return [];
      const n = ks.findIndex((k) => k && k.key_id === signed);
      if (n < 0 || typeof ks[n].public_key_base64 !== 'string') return [];
      const v = ks[n].public_key_base64;
      return sweepPositions(v).map((p) => {
        const m = flipBitAt(v, p);
        if (!m || m === v) return null;
        const o = clone(i); o.keys.keys[n].public_key_base64 = m; return o;
      }).filter(Boolean);
    },
  },
  {
    id: 'anchor-list-emptied',
    why: 'step 9 — removing relying-party anchors must change tsa_signature',
    precondition: (b) => !refused(b) && !!b.tsa_signature
      && Object.values(b.tsa_signature).some((x) => x !== 'not_evaluated'),
    variants: (i) => {
      if (!Array.isArray(i.tsa_roots_base64) || !i.tsa_roots_base64.length) return [];
      const o = clone(i); o.tsa_roots_base64 = []; return [o];
    },
  },
];

function run(vdir) {
  const dir = path.join(vdir, 'vectors');
  const files = fs.readdirSync(dir).filter((f) => f.endsWith('.json')).sort();
  const vectors = files.map((f) => ({ f, v: JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8')) }));

  // CONTROL 1 — always-accept stub.
  const stub = vectors.find((x) => x.f.startsWith('01-')).v.expected;
  let stubAgree = 0;
  for (const { v } of vectors) {
    const keys = [...new Set([...Object.keys(v.expected), ...Object.keys(stub)])];
    const ok = keys.every((k) => JSON.stringify(v.expected[k]) === JSON.stringify(stub[k]));
    if (ok) stubAgree++;
  }

  // CONTROL 2 — mutation battery.
  let applied = 0, killed = 0, skipped = 0, probes = 0;
  const survivors = [];
  const depth = {};
  for (const { f, v } of vectors) {
    let base;
    try { base = verify(v.inputs); } catch (e) { base = { error: String(e && e.message) }; }
    const baseKey = outcomeKey(base);
    for (const m of MUTATIONS) {
      let vars = [];
      try { vars = m.variants(v.inputs) || []; } catch { vars = []; }
      if (!vars.length) continue;                       // does not apply to this vector
      if (!m.precondition(base)) { skipped++; continue; } // carries no information
      applied++;
      // Every swept position is evaluated — NOT stopped at the first kill. A
      // mutation class that is noticed only at one position out of 64 is a far
      // weaker control than one noticed at all of them, and stopping early
      // cannot tell those apart. `min_positions_killing` below is the number
      // that matters: if any applied mutation depended on a single lucky byte,
      // it would read 1.
      let kills = 0;
      for (const mutated of vars) {
        probes++;
        let got;
        try { got = verify(mutated); } catch (e) { got = { error: String(e && e.message) }; }
        if (outcomeKey(got) !== baseKey) kills++;
      }
      const cls = depth[m.id] || (depth[m.id] = { applied: 0, positions: 0, killing: 0, min_positions_killing: Infinity });
      cls.applied++; cls.positions += vars.length; cls.killing += kills;
      cls.min_positions_killing = Math.min(cls.min_positions_killing, kills);
      if (kills > 0) killed++;
      else survivors.push({ vector: f.replace('.json', ''), mutation: m.id, why: m.why, probes: vars.length });
    }
  }
  return {
    vectors: vectors.length,
    always_accept_control: { agreed: stubAgree, of: vectors.length },
    mutation_battery: { applied, killed, survived: survivors.length, skipped_no_information: skipped, probes_evaluated: probes },
    depth_by_mutation_class: depth,
    survivors,
  };
}

module.exports = { run, MUTATIONS };

/* CLI entry point. MUST BE LAST — see the note at the foot of war-verify.cjs. */
if (require.main === module) {
  const dir = process.argv[2];
  if (!dir) { console.error('usage: node war-discrimination.cjs <corpus-dir> [--json]'); process.exit(2); }
  const r = run(dir);
  if (process.argv.includes('--json')) { console.log(JSON.stringify(r, null, 1)); process.exit(0); }
  console.log(`\n  CONTROL 1 — always-accept stub : agreed on ${r.always_accept_control.agreed} of ${r.always_accept_control.of} vectors`);
  const mb = r.mutation_battery;
  console.log(`  CONTROL 2 — mutation battery   : ${mb.applied} applied, ${mb.killed} killed, ${mb.survived} survived`);
  console.log(`                                   ${mb.probes_evaluated} probes evaluated; ${mb.skipped_no_information} not applied (vector already in that failure state)`);
  console.log('\n  KILL DEPTH — every swept position evaluated, not stopped at the first kill:');
  console.log(`    ${'mutation class'.padEnd(34)}${'applied'.padStart(8)}${'positions'.padStart(11)}${'kill'.padStart(9)}${'rate'.padStart(8)}${'min/mutation'.padStart(14)}`);
  for (const [k, d] of Object.entries(r.depth_by_mutation_class)) {
    console.log(`    ${k.padEnd(34)}${String(d.applied).padStart(8)}${String(d.positions).padStart(11)}${String(d.killing).padStart(9)}${(100 * d.killing / d.positions).toFixed(1).padStart(7)}%${String(d.min_positions_killing).padStart(14)}`);
  }
  console.log('    A min/mutation of 0 would be a survivor; a min of 1 on a swept class would mean');
  console.log('    that control rested on a single lucky byte. Token classes sit below 100% because');
  console.log('    much of a DER response (certificates, serials, nonces) decides no outcome.');
  if (r.survivors.length) {
    console.log('\n  SURVIVORS (a mutation the verifier did not notice):');
    for (const s of r.survivors) console.log(`    ${s.vector.padEnd(46)} ${s.mutation.padEnd(32)} ${s.probes} probes · ${s.why}`);
  } else {
    console.log('\n  SURVIVORS: none — every applicable mutation was noticed.');
  }
  console.log('');
  process.exit(0);
}

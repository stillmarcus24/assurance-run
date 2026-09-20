#!/usr/bin/env node
'use strict';
/**
 * recompute — the multi-rail settlement number, OFFLINE from the published
 * corpus. No network, no keys, no callback. This is the "recomputable from a
 * clean clone" claim made literal: clone, run this, get the signed number.
 *
 *   node settlement/recompute.cjs
 *
 * Door state = the scanner's roll-up, reproduced here: PAID if any read rail
 * shows inbound; UNKNOWN if any advertised rail is unread or a payTo is
 * unparsed; ZERO_OBSERVED only if every advertised rail was read and empty.
 */
const fs = require('fs');
const path = require('path');
const K = require('../kernel.cjs');
const A = require('./impl_a.cjs');
const B = require('./impl_b.cjs');
const rails = require('./rails.cjs');

const corpusFile = process.argv[2] || path.join(__dirname, 'corpus-2026-09-20.jsonl');
const recs = fs.readFileSync(corpusFile, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));

function doorState(rec) {
  const va = A.verdict(rec), vb = B.verdict(rec);
  const live = (rec.paytos || []).filter((p) => !(p.sink && p.sink.is_sink));
  const xrpl = live.filter((p) => p.form === 'xrpl').map((p) => rails.xrplSummary((rec.evidence || {})[p.value]).state);
  const sol = live.filter((p) => p.form === 'solana').map((p) => rails.solanaSummary((rec.evidence || {})[p.value]).state);
  const states = [va.state, ...xrpl, ...sol];
  let state;
  if (states.includes('PAID')) state = 'PAID';
  else if (states.includes('UNKNOWN') || (rec.payto_unparsed || []).length || (rec.out_of_scope_rails || []).length) state = 'UNKNOWN';
  else if (states.length && states.every((x) => x === 'ZERO_OBSERVED')) state = 'ZERO_OBSERVED';
  else state = 'UNKNOWN';
  return { state, base_agree: va.state === vb.state, base_state: va.state };
}

let PAID = 0, UNKNOWN = 0, ZERO = 0, pr_flag = 0, gap = 0, base_paid = 0, nonbase_paid = 0;
for (const rec of recs) {
  const d = doorState(rec);
  if (d.state === 'PAID') { PAID++; if (d.base_state === 'PAID') base_paid++; else nonbase_paid++; }
  else if (d.state === 'UNKNOWN') UNKNOWN++;
  else if (d.state === 'ZERO_OBSERVED') ZERO++;
  if (rec.payment_ready) { pr_flag++; if (d.state !== 'PAID') gap++; }
}

const payload = {
  tool: 'settlement-recompute/0.1', kernel: K.VERSION,
  observed_at: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
  corpus: path.basename(corpusFile),
  method: 'offline multi-rail roll-up (Base impl_a/impl_b + XRPL/Solana rails) recomputed from published corpus; no network',
  source: 'x402-list.com directory (CC-BY-4.0)',
  doors: recs.length,
  states: { PAID, UNKNOWN, ZERO_OBSERVED: ZERO },
  paid_base_visible: base_paid,
  paid_nonbase_only: nonbase_paid,
  payment_ready_flagged: pr_flag,
  claim_vs_chain_gap: gap,
  claim_vs_chain_gap_pct_of_payment_ready: pr_flag ? +(100 * gap / pr_flag).toFixed(1) : null,
  caveats: [
    'PAID = inbound to the advertised payTo, not proof of customers; payment_ready is the directory flag (distinct from its `verified` and `status` fields), not a revenue claim.',
    'a facilitator settling for many buyers reads as one sender; distinct-payer is a floor.',
    'Base-rail counts exact; XRPL by inbound Payments, Solana by current USDC balance (a swept account reads UNKNOWN, not ZERO).',
  ],
};
const digest = K.sha256(K.canonical(payload));
fs.writeFileSync(path.join(__dirname, '..', 'verdicts', 'x402-settlement-multirail-2026-09-20.json'),
  JSON.stringify({ payload, digest, signature: K.sign(digest), algorithm: 'ed25519' }, null, 2) + '\n');

console.log(`\n  MULTI-RAIL SETTLEMENT (offline recompute, n=${recs.length})`);
console.log(`  PAID ${PAID} (base ${base_paid} + non-base ${nonbase_paid}) · UNKNOWN ${UNKNOWN} · ZERO ${ZERO}`);
console.log(`  payment_ready flagged: ${pr_flag}`);
console.log(`  claim-vs-chain gap: ${gap}/${pr_flag} = ${payload.claim_vs_chain_gap_pct_of_payment_ready}% of payment_ready doors`);
console.log(`  signed: verdicts/x402-settlement-multirail-2026-09-20.json\n`);

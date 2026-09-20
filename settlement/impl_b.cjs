'use strict';
/*
 * x402_settlement_impl_b.cjs — derivation B: never read the transfer list.
 *
 * PURE, same contract as impl A. Written to reach the same tri-state by a route
 * that shares none of A's logic: A counts rows out of /token-transfers; B rules
 * from /addresses/{a} metadata and /addresses/{a}/token-balances and does not
 * look at a single transfer row. A parse, filter or pagination bug in A cannot
 * reproduce itself here, which is the only reason running both is worth anything.
 *
 * THE SIGNALS, AND WHICH ONES ARE ACTUALLY TRUSTWORTHY -- measured 2026-09-14,
 * not assumed:
 *
 *   /addresses/{a}/counters        token_transfers_count
 *       BROKEN. RETURNS "0" FOR EVERY ADDRESS TESTED, INCLUDING ALL EIGHT DOORS
 *       KNOWN TO HAVE RECEIVED MONEY -- agentpay reads "0" while holding 50
 *       transfers and 8.07 USDC. 8 of 8 false zeros. This field is never read by
 *       this file and must never be read by any other. It is the same
 *       confident-false-zero shape as the `address_hash` rename, in a different
 *       endpoint, and an earlier draft of today's finding was built on it.
 *
 *   /addresses/{a}  has_token_transfers
 *       TRUSTWORTHY on the known-answer test: true for all 8 known-paid doors,
 *       false for the 3 addresses with no history. This is the load-bearing
 *       signal here.
 *
 *   /addresses/{a}/token-balances  USDC entry
 *       ONE-WAY ONLY. A positive balance proves money arrived. A zero or absent
 *       balance proves NOTHING -- humanmirror received 0.01 USDC and swept it,
 *       so it reads has_token_transfers:true with no USDC balance at all. Using
 *       an empty balance as evidence of non-payment would be precisely the
 *       inference this instrument exists to refuse.
 */

const USDC_BASE = '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913';

const NAME = 'B: address metadata + token balances (no transfer rows read)';

function usdcBalance(ev) {
  const bal = ev && ev.token_balances;
  if (!Array.isArray(bal)) return null;
  const hit = bal.find((x) => String(((x || {}).token || {}).address_hash || '').toLowerCase() === USDC_BASE);
  if (!hit) return 0;
  const v = Number(hit.value || 0);
  return Number.isFinite(v) ? v : null;
}

function verdictForAddress(ev) {
  if (!ev) return { state: 'UNKNOWN', reason: 'no_evidence_captured' };
  if (ev.rail && ev.rail !== 'eip155:8453') return { state: 'UNKNOWN', reason: 'rail_out_of_scope:' + ev.rail };
  if (ev.fetch_errors && ev.fetch_errors.length) return { state: 'UNKNOWN', reason: 'fetch_error:' + ev.fetch_errors[0] };

  const meta = ev.address_meta;
  if (!meta || typeof meta !== 'object') return { state: 'UNKNOWN', reason: 'address_meta_missing' };

  const bal = usdcBalance(ev);
  // A positive USDC balance is proof money arrived, regardless of anything else.
  if (bal !== null && bal > 0) return { state: 'PAID', usdc_balance_raw: String(bal) };

  const htt = meta.has_token_transfers;
  if (htt === false) {
    // No token transfers of any kind ever. USDC is a token, so no USDC either.
    return { state: 'ZERO_OBSERVED' };
  }
  if (htt === true) {
    // Token transfers happened but no USDC is held now. Could be a swept USDC
    // payment (humanmirror, exactly this) or could be unrelated tokens. B cannot
    // separate those without reading rows, which is the one thing it must not do.
    return { state: 'UNKNOWN', reason: 'token_transfers_exist_but_usdc_balance_zero_cannot_attribute' };
  }
  return { state: 'UNKNOWN', reason: 'has_token_transfers_absent' };
}

function verdict(rec) {
  const paytos = (rec && rec.paytos) || [];
  const evidence = (rec && rec.evidence) || {};
  const live = paytos.filter((p) => !(p.sink && p.sink.is_sink));
  if (!live.length) return { state: 'UNKNOWN', reason: 'no_live_payto_resolved' };

  const per = live.map((p) => verdictForAddress(evidence[p.value]));
  if (per.some((v) => v.state === 'PAID')) return { state: 'PAID' };
  const unk = per.find((v) => v.state === 'UNKNOWN');
  // Carry the reason up. A roll-up that flattens WHY it could not rule turns a
  // useful coverage map into an opaque shrug, which is most of the value lost.
  if (unk) return { state: 'UNKNOWN', reason: unk.reason || null };
  return { state: 'ZERO_OBSERVED' };
}

module.exports = { NAME, verdict, verdictForAddress, usdcBalance, USDC_BASE };

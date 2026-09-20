'use strict';
/*
 * x402_settlement_impl_a.cjs — derivation A: count the transfer rows.
 *
 * PURE. Takes a corpus record carrying pre-fetched raw evidence and returns a
 * verdict. No network, no clock, no filesystem. That is deliberate: it makes this
 * a real implementation under conformance/differential.js (whose verdict() is
 * synchronous) and it makes every verdict reproducible offline from the frozen
 * evidence, forever.
 *
 * WHAT IT IS INDEPENDENT OF, AND WHAT IT IS NOT (state this, do not imply more).
 * A and B share a data source: the Blockscout index. An indexer-level fault —
 * a field rename, a stale shard, a wrong balance — hits both and they will agree
 * on being wrong. What they do NOT share is the derivation: A counts rows out of
 * the token-transfers list; B never reads that list at all and rules from address
 * metadata and token balances. So this pair catches the filter/parse/pagination
 * class that has bitten this instrument twice (the `address_hash` rename
 * 2026-09-13, the non-EVM payTo drop 2026-09-14) and does NOT catch an indexer
 * fault. Closing that second gap needs a non-Blockscout source; we do not have
 * an archive RPC key, and eth_getLogs on the free endpoints caps at a 2,000-block
 * range, so it is an open gap and is published as one rather than papered over.
 */

const USDC_BASE = '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913';

const NAME = 'A: count token-transfer rows (Blockscout /token-transfers)';

// Blockscout v2 names the token address `address_hash`. The original spelling
// here was `address`, which matched nothing and made every door read zero --
// fail-closed and silent, the worst kind. Accept both, and if NO row in a
// non-empty page carries a recognizable token address, refuse to return a count.
function tokenAddr(t) {
  const tok = t && t.token;
  if (!tok) return '';
  return String(tok.address_hash || tok.address || '').toLowerCase();
}
function toAddr(t) { return String(((t && t.to) || {}).hash || '').toLowerCase(); }
function fromAddr(t) { return String(((t && t.from) || {}).hash || '').toLowerCase(); }

/*
 * Returns { state, payers, transfers, usdc, evidence }.
 *
 * state is the only field the differential oracle compares. payers/usdc are
 * A-only detail that B structurally cannot produce, so comparing them would
 * manufacture a disagreement on every record and drown the real ones.
 *
 *   PAID          at least one inbound USDC transfer to this address is visible
 *   ZERO_OBSERVED zero inbound USDC observed AND the index independently says
 *                 this address has no token transfers at all
 *   UNKNOWN       anything else -- unreadable evidence, an unrecognized token
 *                 field, a page cap we hit, or zero rows that nothing corroborates
 *
 * UNKNOWN is a first-class answer, not an error. The whole defect this file
 * exists to stop is a reader collapsing "I could not see it" into "it is not there".
 */
function verdictForAddress(ev) {
  if (!ev) return { state: 'UNKNOWN', reason: 'no_evidence_captured' };
  if (ev.rail && ev.rail !== 'eip155:8453') {
    return { state: 'UNKNOWN', reason: 'rail_out_of_scope:' + ev.rail };
  }
  if (ev.fetch_errors && ev.fetch_errors.length) {
    return { state: 'UNKNOWN', reason: 'fetch_error:' + ev.fetch_errors[0] };
  }
  const pages = ev.transfer_pages;
  if (!Array.isArray(pages)) return { state: 'UNKNOWN', reason: 'transfer_pages_missing' };

  const rows = [];
  for (const p of pages) {
    if (!p || !Array.isArray(p.items)) return { state: 'UNKNOWN', reason: 'page_shape_unreadable' };
    rows.push(...p.items);
  }

  // The 2026-09-13 guard, kept: a filter that matches nothing is indistinguishable
  // from a world where nothing matched. If rows exist but none carries a token
  // address we recognize, the index changed shape under us -- say so, do not count.
  if (rows.length && !rows.some(tokenAddr)) {
    return { state: 'UNKNOWN', reason: 'token_field_unrecognized_refusing_to_report_zero' };
  }

  const self = String(ev.address || '').toLowerCase();
  const inbound = rows.filter((t) => tokenAddr(t) === USDC_BASE && toAddr(t) === self);
  const payers = new Set(inbound.map(fromAddr).filter(Boolean));
  const usdc = inbound.reduce((s, t) => s + Number(((t.total || {}).value) || 0) / 1e6, 0);

  if (inbound.length) {
    return {
      state: 'PAID',
      payers: payers.size,
      transfers: inbound.length,
      usdc: Number(usdc.toFixed(6)),
      // A page cap does not change PAID -- more history only adds. It DOES make
      // every count a floor, and a floor reported as a total is a lie of omission.
      counts_are_floor: !!ev.page_cap_hit,
    };
  }

  // Zero rows. On its own that is not evidence of anything: the filter may have
  // missed, the page may have been the wrong one. Corroborate against a signal
  // derived a different way before allowing a zero to stand.
  if (ev.page_cap_hit) return { state: 'UNKNOWN', reason: 'zero_in_scope_but_page_cap_hit' };
  if (ev.address_meta && ev.address_meta.has_token_transfers === false) {
    return { state: 'ZERO_OBSERVED', payers: 0, transfers: 0, usdc: 0 };
  }
  return { state: 'UNKNOWN', reason: 'zero_rows_uncorroborated' };
}

/*
 * Door-level roll-up. A door can advertise several payTo values across several
 * rails. Any rail we can actually read and that shows money makes the door PAID.
 * If we cannot read every advertised rail, the door is UNKNOWN even when the
 * rails we CAN read are empty -- that is exactly the daxpt failure: its Base leg
 * was genuinely empty and its XRPL leg held 5 distinct payers.
 */
function verdict(rec) {
  const paytos = (rec && rec.paytos) || [];
  const evidence = (rec && rec.evidence) || {};
  const live = paytos.filter((p) => !(p.sink && p.sink.is_sink));
  if (!live.length) return { state: 'UNKNOWN', reason: 'no_live_payto_resolved' };

  const per = live.map((p) => ({ payto: p, v: verdictForAddress(evidence[p.value]) }));
  if (per.some((x) => x.v.state === 'PAID')) return { state: 'PAID' };
  const unk = per.find((x) => x.v.state === 'UNKNOWN');
  // Carry the reason up; a roll-up that flattens WHY it could not rule loses most
  // of the coverage map that makes this pair worth running.
  if (unk) return { state: 'UNKNOWN', reason: unk.v.reason || null };
  return { state: 'ZERO_OBSERVED' };
}

module.exports = { NAME, verdict, verdictForAddress, USDC_BASE };

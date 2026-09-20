'use strict';
/**
 * rails — pure XRPL/Solana settlement verdicts from pre-fetched evidence.
 * Extracted verbatim from the scanner so the multi-rail roll-up recomputes
 * OFFLINE from the published corpus, no network, no keys.
 */
function xrplSummary(ev) {
  if (!ev || !ev.account_tx) return { state: 'UNKNOWN', reason: (ev && ev.fetch_errors[0]) || 'no_evidence' };
  const senders = new Set();
  let drops = 0, n = 0;
  for (const t of ev.account_tx.transactions) {
    const x = t.tx || t.tx_json || {};
    const m = t.meta || {};
    if (x.TransactionType !== 'Payment' || x.Destination !== ev.address) continue;
    const d = m.delivered_amount !== undefined ? m.delivered_amount : x.Amount;
    if (typeof d === 'string') drops += Number(d);
    n++; if (x.Account) senders.add(x.Account);
  }
  if (!n) return { state: 'ZERO_OBSERVED', payers: 0, transfers: 0, counts_are_floor: !!ev.page_cap_hit };
  return { state: 'PAID', payers: senders.size, transfers: n, xrp: Number((drops / 1e6).toFixed(6)),
    counts_are_floor: !!ev.page_cap_hit,
    transfers_semantics: 'validated inbound Payments delivering value; NOT de-duplicated', dedup_applied: false };
}
function solanaSummary(ev) {
  if (!ev || !Array.isArray(ev.token_accounts)) return { state: 'UNKNOWN', reason: (ev && ev.fetch_errors[0]) || 'no_evidence' };
  let total = 0;
  for (const t of ev.token_accounts) {
    const info = (((t.account || {}).data || {}).parsed || {}).info;
    const ui = info && info.tokenAmount && Number(info.tokenAmount.uiAmountString || info.tokenAmount.uiAmount || 0);
    if (Number.isFinite(ui)) total += ui;
  }
  if (total > 0) return { state: 'PAID', usdc_balance: Number(total.toFixed(6)), basis: 'current_balance_only_not_a_transfer_count' };
  return { state: 'UNKNOWN', reason: 'no_usdc_balance_and_this_probe_cannot_read_transfer_history' };
}
module.exports = { xrplSummary, solanaSummary };

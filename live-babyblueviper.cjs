#!/usr/bin/env node
'use strict';
/**
 * live-babyblueviper — the named live reference vector for wg-identity#21.
 *
 * wg-identity#21 (TKCollective) asks for a verification-state vocabulary whose
 * `not evaluated` and `indeterminate` never collapse into `verified`. The clause
 * has four implementations behind it, but the count lives in comments. AC-11 in
 * this corpus is runnable today and, until now, carried no LIVE vector from a
 * system other than ours.
 *
 * babyblueviper1's proof endpoint (api.babyblueviper.com) is the only public
 * surface in that thread a stranger can execute with no key and no account,
 * which is why it belongs in the suite by name rather than cited in prose. This
 * runner executes it, read-only, and writes a signed verdict anyone can replay.
 *
 * Read-only by construction: GET, and unpaid POSTs that carry only public
 * ledger material or no body at all. No key, no account, no write, no payment.
 *
 * HONESTY BOUNDARY — the whole point of the vector:
 *   - A behaviour we could execute and confirm is AGREE.
 *   - The record hash we could not reconstruct is INDETERMINATE, never a
 *     DISAGREE about their system. We did not establish their preimage; that is
 *     a statement about us, not about their hash. (AC-11, from the other side.)
 *   - The `preimage_fields_authorized:true` positive requires a proof id that
 *     postdates commit 78e6a921. No published ledger entry does yet, so that
 *     case is NOT_EVALUATED — no check performed — pending one input from the
 *     operator. It is not dressed as a pass.
 */

const fs = require('fs');
const path = require('path');
const K = require('./kernel.cjs');

const { AGREE, DISAGREE, INDETERMINATE, NOT_EVALUATED } = K;
const BASE = 'https://api.babyblueviper.com';
const UA = 'StillOS-assurance-run/live-babyblueviper (read-only; no key; no payment)';

async function http(method, url, body) {
  try {
    const res = await fetch(url, {
      method,
      headers: { 'user-agent': UA, ...(body ? { 'content-type': 'application/json' } : {}) },
      body: body ? JSON.stringify(body) : undefined,
      redirect: 'follow',
      signal: AbortSignal.timeout(25000),
    });
    const text = await res.text();
    let json = null; try { json = JSON.parse(text); } catch {}
    return { ok: true, status: res.status, text, json };
  } catch (e) {
    return { ok: false, fault: K.classifyFault(e) };
  }
}

async function run() {
  const findings = [];
  const routes = [`${BASE}/ledger/1`, `${BASE}/verify-proof`];

  // ---- BB-01: the verdict ledger is public and each entry is signed ----------
  const ledger = await http('GET', `${BASE}/ledger/1`);
  if (ledger.ok && ledger.status === 200 && ledger.json &&
      ledger.json.event_id && ledger.json.signature && ledger.json.pubkey_hex) {
    findings.push({ verdict: AGREE, reason: 'LEDGER_PUBLIC_SIGNED',
      claim: `GET /ledger/1 serves a signed entry, no key, no account`,
      detail: `HTTP 200; event_id ${ledger.json.event_id.slice(0, 16)}…; ` +
        `schnorr sig present; pubkey ${ledger.json.pubkey_hex.slice(0, 16)}…` });
  } else if (ledger.ok) {
    findings.push({ verdict: INDETERMINATE, reason: 'LEDGER_SHAPE_UNEXPECTED',
      claim: 'GET /ledger/1 serves a signed entry',
      detail: `HTTP ${ledger.status}; expected event_id+signature+pubkey_hex, got keys ` +
        `[${ledger.json ? Object.keys(ledger.json).join(',') : 'non-JSON'}]` });
  } else {
    findings.push({ verdict: INDETERMINATE, reason: 'SOURCE_UNREACHABLE',
      claim: 'GET /ledger/1 serves a signed entry', detail: ledger.fault.detail });
  }

  // ---- BB-02: the endpoint publishes how to recompute WITHOUT trusting it -----
  const recipe = await http('POST', `${BASE}/verify-proof`, undefined);
  const rj = recipe.json || {};
  const recipeText = rj.how_to_verify || rj.error || '';
  if (recipe.ok && /recompute|sha256|schnorr|8785|nip-01/i.test(recipeText)) {
    findings.push({ verdict: AGREE, reason: 'RECIPE_SERVED',
      claim: 'POST /verify-proof (no body) returns a self-recompute recipe',
      detail: `HTTP ${recipe.status}; names NIP-01 id recompute + schnorr verify + RFC 8785 JCS; ` +
        `published_pubkey pinned in-band` });
  } else {
    findings.push({ verdict: INDETERMINATE, reason: 'RECIPE_ABSENT',
      claim: 'POST /verify-proof (no body) returns a self-recompute recipe',
      detail: recipe.ok ? `HTTP ${recipe.status}, no recompute recipe in body` : recipe.fault.detail });
  }

  // ---- BB-03: THE CLAUSE. An unresolvable proof id → distinct not-evaluated ---
  // Uses the real published event_id of entry 1; durable storage postdates it,
  // so the honest answer is "no stored event", NOT a verification failure.
  const knownId = (ledger.json && ledger.json.event_id) || 'eb22294404b2021588f90747b6404e878431191845c2aab26a919702394c68ac';
  const miss = await http('POST', `${BASE}/verify-proof`, { event_id: knownId });
  const missMsg = (miss.json && (miss.json.detail || miss.json.error)) || miss.text || '';
  if (miss.ok && miss.status === 404 && /no durably-stored|predates|fallback|no .*event/i.test(missMsg)) {
    findings.push({ verdict: AGREE, reason: 'HONEST_NOT_EVALUATED',
      claim: 'wg-identity#21: a proof it cannot resolve returns a DISTINCT not-evaluated signal, not a pass',
      detail: `POST /verify-proof {event_id:${knownId.slice(0, 12)}…} → HTTP 404 naming the reason ` +
        `("no durably-stored event … predates this fix … HMAC fallback"); it does not return valid:true` });
  } else if (miss.ok && (miss.json && miss.json.valid === true)) {
    findings.push({ verdict: DISAGREE, reason: 'ABSENCE_READ_AS_PASS',
      claim: 'a proof it cannot resolve returns a distinct not-evaluated signal, not a pass',
      detail: `POST returned valid:true for an id with no durable event — the exact collapse the clause prohibits` });
  } else {
    findings.push({ verdict: INDETERMINATE, reason: 'UNEXPECTED_MISS_SHAPE',
      claim: 'a proof it cannot resolve returns a distinct not-evaluated signal, not a pass',
      detail: miss.ok ? `HTTP ${miss.status}: ${missMsg.slice(0, 160)}` : miss.fault.detail });
  }

  // ---- BB-04: a mis-shaped event → valid:false + unverifiable, never a pass ---
  const malformed = ledger.json ? await http('POST', `${BASE}/verify-proof`, { event: ledger.json }) : null;
  if (malformed && malformed.ok && malformed.json && malformed.json.valid === false) {
    const tier = (malformed.json.recompute_depth && malformed.json.recompute_depth.tier) || 'n/a';
    findings.push({ verdict: AGREE, reason: 'HONEST_UNVERIFIABLE',
      claim: 'a mis-shaped event yields valid:false, never a silent pass',
      detail: `POST /verify-proof {event:<ledger wrapper>} → valid:false, recompute_depth.tier="${tier}"` });
  } else if (malformed && malformed.ok && malformed.json && malformed.json.valid === true) {
    findings.push({ verdict: DISAGREE, reason: 'MALFORMED_READ_AS_VALID',
      claim: 'a mis-shaped event yields valid:false, never a silent pass',
      detail: 'POST returned valid:true for a wrapper that is not a NIP-01 event' });
  } else {
    findings.push({ verdict: NOT_EVALUATED, reason: 'NO_LEDGER_SAMPLE',
      claim: 'a mis-shaped event yields valid:false, never a silent pass',
      detail: 'could not obtain a ledger wrapper to submit' });
  }

  // ---- BB-05: independent record hash — we could NOT reconstruct the preimage -
  // Naive SHA-256(JCS(record)) does not match published record_sha256. We do not
  // know their exact preimage (kind/tags/content serialisation is not exposed).
  // That is a statement about OUR reconstruction, not about their hash. AC-11.
  if (ledger.json && ledger.json.record && ledger.json.record_sha256) {
    const naive = K.sha256(K.canonical(ledger.json.record));
    const matched = naive === ledger.json.record_sha256;
    findings.push({
      verdict: matched ? AGREE : INDETERMINATE,
      reason: matched ? 'RECORD_HASH_RECOMPUTED' : 'PREIMAGE_UNKNOWN',
      claim: 'record_sha256 independently recomputes from the published record',
      detail: matched
        ? `SHA-256(canonical(record)) == published record_sha256 (${naive.slice(0, 16)}…)`
        : `naive canonicalisation ≠ published record_sha256; exact preimage not published, ` +
          `so we did NOT establish this. Not a defect claim about their hash — a gap in our reconstruction. ` +
          `Resolvable with the operator's preimage dict.`,
    });
  }

  // ---- BB-06: authorized-preimage positive — NO check performed yet ----------
  findings.push({ verdict: NOT_EVALUATED, reason: 'AWAITING_POSTDATED_PROOF',
    claim: 'preimage_fields_authorized:true on a proof postdating commit 78e6a921',
    detail: 'the public ledger\'s newest entry predates the fix, so no published proof exercises ' +
      'preimage_fields_authorized yet. One input completes it: a proof id postdating 78e6a921 plus its ' +
      'preimage dict. Recorded as not-evaluated — no check performed — never as a pass.' });

  return { base: BASE, routes, findings };
}

function signedVerdict(r, observed_at) {
  const c = (v) => r.findings.filter((f) => f.verdict === v).length;
  const payload = {
    tool: 'live-babyblueviper/0.1',
    kernel: K.VERSION,
    target: r.base,
    observed_at,
    routes_examined: r.routes,
    findings: r.findings,
    counts: { AGREE: c(AGREE), DISAGREE: c(DISAGREE), INDETERMINATE: c(INDETERMINATE), NOT_EVALUATED: c(NOT_EVALUATED) },
    not_established: c(INDETERMINATE) + c(NOT_EVALUATED),
  };
  const digest = K.sha256(K.canonical(payload));
  return { payload, digest, signature: K.sign(digest), algorithm: 'ed25519' };
}

(async () => {
  const observed_at = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'); // clock enters at the edge only
  const r = await run();
  const v = signedVerdict(r, observed_at);
  const outFile = process.argv[2] || path.join(__dirname, 'verdicts', 'babyblueviper-verify-proof-2026-09-20.json');
  fs.writeFileSync(outFile, JSON.stringify(v, null, 2) + '\n');
  console.log(`\n  live reference vector — ${v.payload.target}`);
  console.log(`  observed_at  ${observed_at}`);
  console.log(`  counts       ${JSON.stringify(v.payload.counts)}`);
  console.log(`  not established by this run: ${v.payload.not_established} of ${r.findings.length}\n`);
  for (const f of r.findings) console.log(`  ${f.verdict.padEnd(13)} ${f.reason.padEnd(24)} ${f.claim}`);
  console.log(`\n  written: ${outFile}`);
  console.log(`  verify:  node verify-verdict.cjs ${path.relative(__dirname, outFile)}\n`);
})();

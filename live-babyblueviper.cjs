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
 *     postdates commit 78e6a921. The operator supplied one (wg-identity#21,
 *     2026-09-20T11:23:04Z); BB-06/07/08 execute it. Before that input existed
 *     the case was NOT_EVALUATED — no check performed — never dressed as a pass.
 *
 * SCOPE OF THE VECTOR, in the operator's own words and kept here so no reader
 * has to infer it:
 *   1. It is a FORMAT vector, not evidence about the artifact reviewed. The
 *      proof was issued on a benign artifact they authored, to exercise the
 *      authorization check. It shows the verifier accepts the authorized
 *      preimage set for the policy_version it names. It says nothing about the
 *      correctness of anything reviewed.
 *   2. The true negative CANNOT be produced by a third party. A properly signed
 *      proof declaring a reduced field list needs their signing key. So from
 *      outside, the negative side ships as tamper (BB-08), not as a forged
 *      reduced-field proof. We do not claim coverage we cannot execute.
 */

const fs = require('fs');
const path = require('path');
const K = require('./kernel.cjs');

const { AGREE, DISAGREE, INDETERMINATE, NOT_EVALUATED } = K;
const BASE = 'https://api.babyblueviper.com';
const UA = 'StillOS-assurance-run/live-babyblueviper (read-only; no key; no payment)';

// Supplied by @babyblueviper1 in wg-identity#21 on 2026-09-20T11:23:04Z as the
// named reference vector: a proof issued AFTER commit 78e6a921 (deployed
// 2026-09-19), which is the first that can exercise preimage_fields_authorized.
// Overridable so a stranger can point the same suite at their own proof id.
const PROOF_ID = process.env.BB_PROOF_ID ||
  '7aa10c9783ef2e96d33d8edb383583d126b6240589f824b39933600e79587002';

async function http(method, url, body) {
  // Every result is stamped as genuinely fetched in this run. `emit` will not
  // publish a finding attributed to anything without this stamp, so a synthetic
  // or hand-built "response" cannot launder a finding into the output.
  const stamp = (r) => Object.assign(r, {
    __fetched: true,
    __label: `${method} ${url.replace(BASE, '')}`,
    __bytes: r.text ? r.text.length : 0,
  });
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
    return stamp({ ok: true, status: res.status, text, json });
  } catch (e) {
    return stamp({ ok: false, fault: K.classifyFault(e) });
  }
}

/**
 * THE GATE, in the form that fits this runner.
 *
 * interop-matrix's defect was a literal standing in for a measurement. This
 * file's defect was different and worth naming precisely: BB-06 pushed a
 * finding with NO branch on live data at all — an unconditional NOT_EVALUATED
 * that looked, in the output, exactly like a case that had run and come back
 * inconclusive. A derivation gate alone would not have caught it, because by
 * then other observations had been made; the finding just wasn't decided from
 * any of them.
 *
 * So the requirement here is attribution, not merely derivation: every finding
 * must name the live response it was decided from. `emit` refuses a finding
 * whose observation is missing, or which was never actually fetched this run.
 * A hand-written finding has nothing to name and cannot be published.
 */
function emit(findings, observation, f) {
  if (!observation || observation.__fetched !== true) {
    const err = new Error(
      'FINDING_WITHOUT_OBSERVATION: ' + (f && f.reason) + ' — this finding names no live ' +
      'response fetched in this run. A finding decided from nothing is an assertion, and in ' +
      'the output it is indistinguishable from one that ran.');
    err.code = 'FINDING_WITHOUT_OBSERVATION';
    throw err;
  }
  const src = `decided from ${observation.__label} (${observation.ok
    ? 'HTTP ' + observation.status + ', ' + observation.__bytes + ' bytes'
    : 'transport fault: ' + (observation.fault && observation.fault.kind)})`;
  findings.push({ ...f, verdict: K.derived(f.verdict, src), decided_from: observation.__label });
}

async function run() {
  const findings = [];
  const routes = [`${BASE}/ledger/1`, `${BASE}/verify-proof`];

  // ---- BB-01: the verdict ledger is public and each entry is signed ----------
  const ledger = await http('GET', `${BASE}/ledger/1`);
  if (ledger.ok && ledger.status === 200 && ledger.json &&
      ledger.json.event_id && ledger.json.signature && ledger.json.pubkey_hex) {
    emit(findings, ledger, { verdict: AGREE, reason: 'LEDGER_PUBLIC_SIGNED',
      claim: `GET /ledger/1 serves a signed entry, no key, no account`,
      detail: `HTTP 200; event_id ${ledger.json.event_id.slice(0, 16)}…; ` +
        `schnorr sig present; pubkey ${ledger.json.pubkey_hex.slice(0, 16)}…` });
  } else if (ledger.ok) {
    emit(findings, ledger, { verdict: INDETERMINATE, reason: 'LEDGER_SHAPE_UNEXPECTED',
      claim: 'GET /ledger/1 serves a signed entry',
      detail: `HTTP ${ledger.status}; expected event_id+signature+pubkey_hex, got keys ` +
        `[${ledger.json ? Object.keys(ledger.json).join(',') : 'non-JSON'}]` });
  } else {
    emit(findings, ledger, { verdict: INDETERMINATE, reason: 'SOURCE_UNREACHABLE',
      claim: 'GET /ledger/1 serves a signed entry', detail: ledger.fault.detail });
  }

  // ---- BB-02: the endpoint publishes how to recompute WITHOUT trusting it -----
  const recipe = await http('POST', `${BASE}/verify-proof`, undefined);
  const rj = recipe.json || {};
  const recipeText = rj.how_to_verify || rj.error || '';
  if (recipe.ok && /recompute|sha256|schnorr|8785|nip-01/i.test(recipeText)) {
    emit(findings, recipe, { verdict: AGREE, reason: 'RECIPE_SERVED',
      claim: 'POST /verify-proof (no body) returns a self-recompute recipe',
      detail: `HTTP ${recipe.status}; names NIP-01 id recompute + schnorr verify + RFC 8785 JCS; ` +
        `published_pubkey pinned in-band` });
  } else {
    emit(findings, recipe, { verdict: INDETERMINATE, reason: 'RECIPE_ABSENT',
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
    emit(findings, miss, { verdict: AGREE, reason: 'HONEST_NOT_EVALUATED',
      claim: 'wg-identity#21: a proof it cannot resolve returns a DISTINCT not-evaluated signal, not a pass',
      detail: `POST /verify-proof {event_id:${knownId.slice(0, 12)}…} → HTTP 404 naming the reason ` +
        `("no durably-stored event … predates this fix … HMAC fallback"); it does not return valid:true` });
  } else if (miss.ok && (miss.json && miss.json.valid === true)) {
    emit(findings, miss, { verdict: DISAGREE, reason: 'ABSENCE_READ_AS_PASS',
      claim: 'a proof it cannot resolve returns a distinct not-evaluated signal, not a pass',
      detail: `POST returned valid:true for an id with no durable event — the exact collapse the clause prohibits` });
  } else {
    emit(findings, miss, { verdict: INDETERMINATE, reason: 'UNEXPECTED_MISS_SHAPE',
      claim: 'a proof it cannot resolve returns a distinct not-evaluated signal, not a pass',
      detail: miss.ok ? `HTTP ${miss.status}: ${missMsg.slice(0, 160)}` : miss.fault.detail });
  }

  // ---- BB-04: a mis-shaped event → valid:false + unverifiable, never a pass ---
  const malformed = ledger.json ? await http('POST', `${BASE}/verify-proof`, { event: ledger.json }) : null;
  if (malformed && malformed.ok && malformed.json && malformed.json.valid === false) {
    const tier = (malformed.json.recompute_depth && malformed.json.recompute_depth.tier) || 'n/a';
    emit(findings, malformed, { verdict: AGREE, reason: 'HONEST_UNVERIFIABLE',
      claim: 'a mis-shaped event yields valid:false, never a silent pass',
      detail: `POST /verify-proof {event:<ledger wrapper>} → valid:false, recompute_depth.tier="${tier}"` });
  } else if (malformed && malformed.ok && malformed.json && malformed.json.valid === true) {
    emit(findings, malformed, { verdict: DISAGREE, reason: 'MALFORMED_READ_AS_VALID',
      claim: 'a mis-shaped event yields valid:false, never a silent pass',
      detail: 'POST returned valid:true for a wrapper that is not a NIP-01 event' });
  } else {
    // `malformed` is null exactly when this branch fires — no ledger wrapper
    // existed to submit, so no request was made. The observation is the ledger
    // read that failed to yield one.
    emit(findings, malformed || ledger, { verdict: NOT_EVALUATED, reason: 'NO_LEDGER_SAMPLE',
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
    emit(findings, ledger, {
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

  // ---- BB-06: authorized-preimage positive, on the operator-supplied proof ----
  const proof = await http('POST', `${BASE}/verify-proof`, { event_id: PROOF_ID });
  routes.push(`${BASE}/verify-proof {event_id:${PROOF_ID.slice(0, 12)}…}`);
  const pj = proof.json || {};
  if (!proof.ok) {
    emit(findings, proof, { verdict: proof.fault.instrument ? NOT_EVALUATED : INDETERMINATE,
      reason: proof.fault.instrument ? 'ADAPTER_FAILED' : 'SOURCE_UNREACHABLE',
      claim: 'preimage_fields_authorized:true on a proof postdating commit 78e6a921',
      detail: proof.fault.detail });
  } else if (proof.status === 200 && pj.valid === true && pj.preimage_fields_authorized === true) {
    emit(findings, proof, { verdict: AGREE, reason: 'AUTHORIZED_PREIMAGE_SET',
      claim: 'preimage_fields_authorized:true on a proof postdating commit 78e6a921',
      detail: `POST /verify-proof {event_id:${PROOF_ID.slice(0, 12)}…} → HTTP 200, valid:true, ` +
        `preimage_fields_authorized:true (top-level), checks.decision_ref_recomputes:` +
        `${(pj.checks || {}).decision_ref_recomputes}, policy_version ` +
        `"${(pj.proof_payload || {}).policy_version}". FORMAT vector: it shows the verifier accepts ` +
        `the authorized set for the version named, not that anything reviewed is correct.` });
  } else if (proof.status === 404 && /no durably-stored/i.test(proof.text || '')) {
    // Observed 2026-09-20: this exact id answered HTTP 200 / valid:true at
    // 14:08Z and 404 "no durably-stored event" at 14:33Z. The verifier is not
    // wrong and nothing here contradicts it — the VECTOR stopped resolving.
    // A named reference vector a stranger cannot replay is not a reference
    // vector, so this is recorded as a durability fact about the fixture, never
    // as a finding about their verifier. Distinct from UNEXPECTED_PROOF_SHAPE
    // for the same reason absence is distinct from failure everywhere else here.
    emit(findings, proof, { verdict: NOT_EVALUATED, reason: 'VECTOR_NO_LONGER_RESOLVES',
      claim: 'preimage_fields_authorized:true on a proof postdating commit 78e6a921',
      detail: `POST /verify-proof {event_id:${PROOF_ID.slice(0, 12)}…} → HTTP 404 ` +
        `"no durably-stored event". The same id returned HTTP 200 with valid:true and ` +
        `preimage_fields_authorized:true earlier in this session. The check did not fail; ` +
        `it could not be performed, because the fixture is no longer retrievable. ` +
        `Says nothing about their verifier — it is a durability property of the vector.` });
  } else {
    emit(findings, proof, { verdict: INDETERMINATE, reason: 'UNEXPECTED_PROOF_SHAPE',
      claim: 'preimage_fields_authorized:true on a proof postdating commit 78e6a921',
      detail: `HTTP ${proof.status}; valid=${pj.valid}, preimage_fields_authorized=` +
        `${pj.preimage_fields_authorized}` });
  }

  // ---- BB-07: WE recompute decision_ref. Their own flag is not the evidence ---
  // checks.decision_ref_recomputes is the endpoint's account of its own work.
  // Per the kernel invariant, self-reported evidence alone can never be an AGREE,
  // so this case rebuilds the preimage here — their published construction (the
  // declared field list, absent fields as null, RFC 8785 JCS, sha256) against our
  // own canonicaliser — and compares. A mismatch is INDETERMINATE, not a defect
  // claim about their hash: it would mean our canonicalisation disagrees, and we
  // would not know whose is wrong without a third implementation.
  const payload = pj.proof_payload;
  const declared = payload && payload.decision_ref_preimage_fields;
  if (Array.isArray(declared) && payload && typeof pj.decision_ref === 'string') {
    const obj = {};
    for (const k of declared) obj[k] = (k in payload) ? payload[k] : null;
    const absent = declared.filter((k) => !(k in payload));
    const ours = 'sha256:' + K.sha256(K.canonical(obj));
    emit(findings, proof, {
      verdict: ours === pj.decision_ref ? AGREE : INDETERMINATE,
      reason: ours === pj.decision_ref ? 'DECISION_REF_RECOMPUTED' : 'CANONICALISATION_DISAGREES',
      claim: 'decision_ref recomputes independently from the published payload and declared field list',
      detail: ours === pj.decision_ref
        ? `${declared.length} declared fields (${absent.length} absent → null), canonicalised and ` +
          `hashed here: ${ours.slice(0, 23)}… == the proof's own decision_ref. Independent: their ` +
          `decision_ref_recomputes flag was not used as the evidence.`
        : `ours ${ours.slice(0, 23)}… ≠ published ${pj.decision_ref.slice(0, 23)}…; our ` +
          `canonicalisation and theirs disagree. Not a claim about their hash — with two ` +
          `implementations we cannot say whose is wrong.`,
    });
  } else {
    emit(findings, proof, { verdict: NOT_EVALUATED, reason: 'NO_PREIMAGE_MATERIAL',
      claim: 'decision_ref recomputes independently from the published payload and declared field list',
      detail: 'the response carried no proof_payload.decision_ref_preimage_fields to rebuild from' });
  }

  // ---- BB-08: the negative side a third party CAN construct ------------------
  // Their signing key is needed to forge a signed reduced-field proof, so the real
  // negative is out of reach from outside. What is in reach: tamper one byte of
  // the signed content and confirm the verifier (a) refuses it and (b) does not
  // report the downstream checks it could no longer run as FAILED.
  //
  // (b) is the load-bearing half, and there are THREE distinct ways to express it,
  // not two. A check that never ran can come back `false` (collapse — its own
  // short-circuit filed as a finding about the artifact), `null` (explicit
  // not-evaluated), or be OMITTED from the response entirely. Only the first is
  // the defect. We name which mechanism is in use rather than assuming one.
  //
  // This case was written asserting `null`, and the first run returned DISAGREE
  // against a system that had done nothing wrong. The measurement was ours: an
  // earlier probe read the response through `.get()`, which yields None for an
  // absent key and for a null key alike, so absent-vs-null was collapsed by the
  // instrument before the question was ever asked. Recorded because omission is
  // the mechanism this endpoint actually uses, and because the collapse it caused
  // is the same one AC-11 exists to prohibit, committed here.
  const CLAIM_08 = 'a tampered proof is refused, and the checks that could no longer ' +
    'run are not reported as failed';
  if (pj.event && typeof pj.event.content === 'string' && pj.event.content.length) {
    const ev = JSON.parse(JSON.stringify(pj.event));
    const last = ev.content.slice(-1);
    ev.content = ev.content.slice(0, -1) + (last === '0' ? '1' : '0');
    const t = await http('POST', `${BASE}/verify-proof`, { event: ev });
    const tj = t.json || {};
    const tc = tj.checks || {};
    // Classify each downstream check by its actual encoding. `in` distinguishes an
    // absent key from a present one holding null; a bare read cannot.
    const downstream = [
      ['checks.decision_ref_recomputes', tc, 'decision_ref_recomputes'],
      ['preimage_fields_authorized', tj, 'preimage_fields_authorized'],
    ].map(([label, obj, key]) => ({
      label,
      encoding: !(key in obj) ? 'ABSENT' : obj[key] === null ? 'NULL'
        : obj[key] === false ? 'FALSE' : 'PRESENT:' + JSON.stringify(obj[key]),
    }));
    const collapsed = downstream.filter((d) => d.encoding === 'FALSE');
    const separated = downstream.filter((d) => d.encoding === 'ABSENT' || d.encoding === 'NULL');
    const shape = downstream.map((d) => `${d.label}=${d.encoding}`).join(', ');
    const kept = Object.keys(tc).length;
    const full = Object.keys((pj.checks || {})).length;

    if (!t.ok) {
      emit(findings, t, { verdict: t.fault.instrument ? NOT_EVALUATED : INDETERMINATE,
        reason: t.fault.instrument ? 'ADAPTER_FAILED' : 'SOURCE_UNREACHABLE',
        claim: CLAIM_08, detail: t.fault.detail });
    } else if (tj.valid !== false) {
      emit(findings, t, { verdict: DISAGREE, reason: 'TAMPER_READ_AS_VALID',
        claim: CLAIM_08,
        detail: `valid=${JSON.stringify(tj.valid)} for an event whose signed content was altered` });
    } else if (collapsed.length) {
      emit(findings, t, { verdict: DISAGREE, reason: 'UNRUN_CHECKS_REPORT_FALSE',
        claim: CLAIM_08,
        detail: `valid:false correctly, but ${shape} — a check that never ran is reported as one ` +
          `that ran and failed` });
    } else if (separated.length === downstream.length) {
      const mech = [...new Set(separated.map((d) => d.encoding))].join('+');
      emit(findings, t, { verdict: AGREE, reason: 'UNRUN_CHECKS_' + mech,
        claim: CLAIM_08,
        detail: `one byte of event.content flipped → valid:false, id_integrity:${tc.id_integrity}, ` +
          `signature_valid:${tc.signature_valid}. The checks that could no longer run are encoded ` +
          `${mech}, never false: ${shape}. The response carries ${kept} check keys against ${full} ` +
          `on the valid proof — the short-circuit is visible in the shape. ` +
          (mech.includes('ABSENT')
            ? 'CONSUMER HAZARD, ours not theirs: omission is only honest if the reader distinguishes ' +
              'an absent key from a false one. Any reader using a falsy default (.get(k), obj[k] ?? false) ' +
              'converts not-evaluated into failed on arrival. This runner made that error before this ' +
              'line was written.'
            : 'An explicit null cannot be read as a failure by a falsy default.') });
    } else {
      emit(findings, t, { verdict: INDETERMINATE, reason: 'MIXED_DOWNSTREAM_ENCODING',
        claim: CLAIM_08,
        detail: `valid:false, but the downstream checks are encoded inconsistently: ${shape}` });
    }
  } else {
    // `t` is scoped to the branch above and does not exist here — there was no
    // event to tamper, so no tamper request was ever sent. The observation this
    // finding is decided from is the proof response that lacked the event.
    emit(findings, proof, { verdict: NOT_EVALUATED, reason: 'NO_EVENT_TO_TAMPER',
      claim: CLAIM_08,
      detail: 'the response carried no event.content to alter' });
  }

  return { base: BASE, routes, findings };
}

function signedVerdict(r, observed_at) {
  // THE GATE, at the only place it is cheap: before publication, before the
  // counts are taken, before anything is signed. Every finding's verdict must
  // arrive marked by emit(); an unmarked one fails the run instead of being
  // counted, printed and signed. Sealing unwraps in place, so everything below
  // sees plain values and the published shape is unchanged.
  const provenance = K.sealDerived({ findings: r.findings }, ['findings[].verdict']);
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
    derivation_gate: {
      enforced_paths: ['findings[].verdict'],
      rule: 'every finding must name the live response it was decided from, or the run fails before publication',
      proves: 'the verdict was selected from a response actually fetched in this run',
      does_not_prove: 'that the selection logic is correct',
      provenance,
    },
  };
  const digest = K.sha256(K.canonical(payload));
  return { payload, digest, signature: K.sign(digest), algorithm: 'ed25519' };
}

(async () => {
  const observed_at = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'); // clock enters at the edge only
  let r, v;
  try {
    r = await run();
    v = signedVerdict(r, observed_at);
  } catch (err) {
    if (err.code !== 'FINDING_WITHOUT_OBSERVATION' && err.code !== 'DERIVATION_GATE') throw err;
    console.error('\n  REFUSED TO PUBLISH\n');
    console.error('  ' + err.message.split('\n').join('\n  ') + '\n');
    process.exit(2);
  }
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

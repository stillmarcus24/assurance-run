#!/usr/bin/env node
'use strict';
/**
 * live-claim-audit — does a DEPLOYED system do what its operator PUBLICLY CLAIMS?
 *
 * A conformance vector corpus tests a document. It runs offline against fixtures
 * and answers "does this implementation match the spec". That is a different and
 * strictly easier question than the one that keeps producing real defects:
 *
 *   the running service contradicts its own published description
 *
 * Every defect this ecosystem has surfaced in the last week was that shape, and a
 * fixture suite would have missed all of them:
 *   - a service advertising x402 v2 whose paid path only ever read v1 (ours)
 *   - a package published at a version whose source differs at that version (ours)
 *   - a directory whose traction block excludes a rail its own detail record carries
 *   - a runner declaring RFC 8785 and shipping json.dumps
 *
 * Read-only by construction. GET only, never a payment, never a write. An unpaid
 * GET against a route the operator published is how their own 402 is meant to be
 * drawn; it is not a purchase attempt and it moves no money.
 *
 * Verdicts are the kernel's four. Anything we could not bind to a checkable claim
 * is NOT_EVALUATED. A claim whose evidence we could not retrieve is INDETERMINATE.
 * Neither is ever rendered as a pass — the false-green is the failure mode this
 * exists to catch in other people's tooling, so it may not appear in ours.
 */

const crypto = require('crypto');
const K = require('./kernel.cjs');

const AGREE = 'AGREE', DISAGREE = 'DISAGREE',
      INDETERMINATE = 'INDETERMINATE', NOT_EVALUATED = 'NOT_EVALUATED';

const UA = 'StillOS-live-claim-audit/0.1 (read-only; GET only; no payment attempted)';

async function get(url, timeout = 20000) {
  try {
    const res = await fetch(url, { headers: { 'user-agent': UA }, redirect: 'follow',
      signal: AbortSignal.timeout(timeout) });
    const text = await res.text();
    let json = null; try { json = JSON.parse(text); } catch {}
    return { ok: true, status: res.status, headers: res.headers, text, json };
  } catch (e) {
    // A fetch that threw is not automatically a fact about the host. The same
    // split the kernel enforces, enforced here: only a named network failure
    // licenses "their server did not answer".
    const f = K.classifyFault(e);
    return { ok: false, error: f.detail, fault: f };
  }
}

const sha = (s) => crypto.createHash('sha256').update(s).digest('hex').slice(0, 16);

function b64json(v) { try { return JSON.parse(Buffer.from(v, 'base64').toString('utf8')); } catch { return null; } }

/** Collect the operator's OWN published claims. Nothing here is our opinion. */
async function harvest(base) {
  const b = base.replace(/\/+$/, '');
  // RFC 8615: well-known URIs resolve from the ORIGIN, never from a sub-path.
  // Fetching <base>/x402/v3/.well-known/x402 manufactures a 404 and then reads it
  // as the operator's defect. Found while auditing 12 real directory listings —
  // 4 of the 12 have a path component, and every one produced a false finding.
  const origin = new URL(b).origin;
  const out = {};
  for (const [k, p] of [['discovery', '/.well-known/x402'], ['openapi', '/openapi.json'], ['llms', '/llms.txt']]) {
    out[k] = await get(origin + p);
    // A sub-path deployment may also serve its own copy; try it, prefer a 200.
    if (origin !== b && (!out[k].ok || out[k].status !== 200)) {
      const alt = await get(b + p);
      if (alt.ok && alt.status === 200) out[k] = alt;
    }
  }
  out.origin = origin;
  return out;
}

/** Pull every advertised route out of a discovery document, whatever its shape. */
function advertisedRoutes(doc, base) {
  const found = new Set();
  const walk = (n, d = 0) => {
    if (!n || d > 8 || typeof n !== 'object') return;
    if (Array.isArray(n)) return n.forEach((x) => walk(x, d + 1));
    for (const [k, v] of Object.entries(n)) {
      if (typeof v === 'string' && /^(\/|https:\/\/)/.test(v) && /resource|url|endpoint|path/i.test(k)) found.add(v);
      else walk(v, d + 1);
    }
  };
  walk(doc);
  return [...found].map((r) => (/^https:/.test(r) ? r : base.replace(/\/+$/, '') + r));
}

/** Parse both x402 challenge forms from one unpaid response. */
function challenges(res) {
  const out = { v1: null, v2: null };
  if (res.json && (res.json.x402Version || res.json.accepts)) out.v1 = res.json;
  const h = res.headers && res.headers.get && res.headers.get('payment-required');
  if (h) out.v2 = b64json(h);
  return out;
}

async function audit(base, { routeLimit = 6 } = {}) {
  const findings = [];
  const add = (f) => findings.push(f);

  // `new URL(base)` inside harvest() threw uncaught on a malformed target, which
  // took the whole run down with a stack trace — a crash is the one outcome that
  // records nothing at all, and an auditor that dies silently is worse than one
  // that reports honestly. Our input, so NOT_EVALUATED.
  try { new URL(base); } catch (e) {
    add({ verdict: NOT_EVALUATED, reason: 'AUDITOR_BAD_TARGET', claim: 'audit target',
      detail: `${K.classifyFault(e).kind} — "${base}" is not a URL we could parse; nothing was requested` });
    return { base, findings, routes: [] };
  }

  const h = await harvest(base);

  // --- claim: the operator publishes a discovery document at all
  if (!h.discovery.ok) {
    const ours = h.discovery.fault && h.discovery.fault.instrument;
    add(ours
      ? { verdict: NOT_EVALUATED, reason: 'AUDITOR_FETCH_FAILED', claim: '.well-known/x402 served',
          detail: `${h.discovery.fault.kind} — our own client raised before reaching the host; ` +
                  `this says nothing about the service and must never be recorded as one` }
      : { verdict: INDETERMINATE, reason: 'DISCOVERY_UNREACHABLE', claim: '.well-known/x402 served',
          detail: `${h.discovery.fault ? h.discovery.fault.kind : 'TRANSPORT'} — ${h.discovery.error}` });
    return { base, findings, routes: [] };
  }
  if (h.discovery.status !== 200 || !h.discovery.json) {
    // NOT a defect on its own. `.well-known/x402` is not mandatory, and a service
    // may be perfectly payable while being discovered some other way. Only a claim
    // of discoverability could make this a contradiction, and we hold no such claim
    // from the operator. Grading it DISAGREE would be inventing a spec they never
    // agreed to — the exact overreach this tool exists to avoid.
    add({ verdict: NOT_EVALUATED, reason: 'NO_DISCOVERY_DOCUMENT_TO_CHECK',
      claim: 'declared-vs-actual comparison',
      detail: `GET ${h.origin}/.well-known/x402 -> HTTP ${h.discovery.status}` +
              `${h.discovery.json ? '' : ' (not JSON)'}. No published claims to audit against; ` +
              `this is a gap in what we can check, not a finding about the service.` });
    return { base, findings, routes: [] };
  }
  add({ verdict: AGREE, reason: 'DISCOVERY_SERVED', claim: '.well-known/x402 served',
    detail: `HTTP 200, ${h.discovery.text.length}B, sha ${sha(h.discovery.text)}` });

  // --- claim: every route the operator advertises actually exists
  // Routes the operator advertises in discovery, PLUS routes their own OpenAPI
  // declares. Our own 402-without-terms defect existed on three paid routes that
  // the discovery document never surfaced — an auditor that only reads discovery
  // would have passed us. A service's paid surface is usually larger than the part
  // it advertises to crawlers, and the unadvertised part is where defects survive.
  const fromDiscovery = advertisedRoutes(h.discovery.json, base);
  const fromOpenApi = [];
  if (h.openapi.ok && h.openapi.status === 200 && h.openapi.json && h.openapi.json.paths) {
    for (const p of Object.keys(h.openapi.json.paths)) {
      if (/\{/.test(p)) continue; // templated paths need params we won't invent
      fromOpenApi.push(h.origin.replace(/\/+$/, '') + p);
    }
  }
  const routes = [...new Set([...fromDiscovery, ...fromOpenApi])].slice(0, routeLimit);
  if (!routes.length) {
    add({ verdict: NOT_EVALUATED, reason: 'NO_ROUTES_ADVERTISED',
      claim: 'advertised routes resolvable', detail: 'discovery doc declares no resource/url/endpoint fields' });
  }

  let sawChallenge = false;
  for (const r of routes) {
    const res = await get(r);
    if (!res.ok) {
      const ours = res.fault && res.fault.instrument;
      add(ours
        ? { verdict: NOT_EVALUATED, reason: 'AUDITOR_FETCH_FAILED', claim: `advertised route ${r}`,
            detail: `${res.fault.kind} — our own client raised; the route was never actually asked` }
        : { verdict: INDETERMINATE, reason: 'ROUTE_UNREACHABLE', claim: `advertised route ${r}`,
            detail: `${res.fault ? res.fault.kind : 'TRANSPORT'} — ${res.error}` });
      continue;
    }
    if (res.status === 404 || res.status === 410) {
      add({ verdict: DISAGREE, reason: 'ADVERTISED_ROUTE_MISSING', claim: `advertised route ${r}`,
        detail: `operator advertises it; live server returns HTTP ${res.status}` });
      continue;
    }

    const c = challenges(res);
    if (res.status === 402) {
      sawChallenge = true;
      // --- claim: the two challenge forms describe the SAME economic offer
      if (c.v1 && c.v2) {
        const a1 = (c.v1.accepts || [])[0] || {};
        const a2 = (c.v2.accepts || [])[0] || {};
        const same = (x, y) => String(x || '').toLowerCase() === String(y || '').toLowerCase();
        const payToSame = same(a1.payTo, a2.payTo);
        const amtSame = same(a1.maxAmountRequired || a1.amount, a2.maxAmountRequired || a2.amount);
        const assetSame = same(a1.asset, a2.asset);
        add({
          verdict: payToSame && amtSame && assetSame ? AGREE : DISAGREE,
          reason: payToSame && amtSame && assetSame ? 'V1_V2_OFFER_CONSISTENT' : 'V1_V2_OFFER_DIVERGES',
          claim: `${r} — v1 body and v2 header describe one offer`,
          detail: `payTo ${payToSame ? 'same' : `${a1.payTo} vs ${a2.payTo}`} | amount ${amtSame ? 'same' : `${a1.maxAmountRequired || a1.amount} vs ${a2.maxAmountRequired || a2.amount}`} | asset ${assetSame ? 'same' : 'DIFFERS'}`,
        });
      } else if (c.v1 && !c.v2) {
        add({ verdict: NOT_EVALUATED, reason: 'V1_ONLY', claim: `${r} — payment version surface`,
          detail: 'v1 body challenge only; no PAYMENT-REQUIRED header. Not a defect unless v2 is claimed elsewhere.' });
      } else if (c.v2 && !c.v1) {
        add({ verdict: NOT_EVALUATED, reason: 'V2_ONLY', claim: `${r} — payment version surface`,
          detail: 'v2 header only; no v1 body challenge.' });
      } else {
        // 402 asserts "payment required" — a claim the response must be able to back.
        // With no accepts[] and no PAYMENT-REQUIRED header there are no terms, so a
        // conforming client cannot construct a payment. Found first in OUR OWN service:
        // GET on a POST-only route answered 402 method_not_allowed, which is a 405.
        const why = res.json && res.json.error ? String(res.json.error) : 'no challenge in body or header';
        add({ verdict: DISAGREE, reason: 'STATUS_402_WITHOUT_TERMS',
          claim: `${r} — 402 carries payable terms`,
          detail: `HTTP 402 with no accepts[] and no PAYMENT-REQUIRED header (${why}). ` +
                  `A client that honours 402 cannot pay; if the real condition is not payment, this is a different status code.` });
      }
    } else if (res.status === 200) {
      add({ verdict: AGREE, reason: 'FREE_TIER_SERVES', claim: `${r} — unpaid GET`,
        detail: `HTTP 200 without payment (${res.text.length}B)` });
    } else {
      add({ verdict: INDETERMINATE, reason: 'UNEXPECTED_STATUS', claim: `advertised route ${r}`,
        detail: `HTTP ${res.status}` });
    }
  }

  // --- claim: an openapi document, if advertised, is actually served
  if (h.openapi.ok && h.openapi.status === 200 && h.openapi.json) {
    add({ verdict: AGREE, reason: 'OPENAPI_SERVED', claim: 'openapi.json served',
      detail: `${Object.keys(h.openapi.json.paths || {}).length} paths declared` });
  } else if (h.openapi.ok && h.openapi.status === 404) {
    add({ verdict: NOT_EVALUATED, reason: 'NO_OPENAPI', claim: 'openapi.json', detail: 'not published (not required)' });
  }

  if (!sawChallenge && routes.length) {
    add({ verdict: NOT_EVALUATED, reason: 'NO_PAID_SURFACE_OBSERVED', claim: 'paid surface',
      detail: 'no advertised route returned a 402 on an unpaid GET' });
  }
  return { base, findings, routes };
}

function report(r) {
  const c = (v) => r.findings.filter((f) => f.verdict === v).length;
  console.log('\n  live-claim-audit — ' + r.base);
  console.log('  ' + '-'.repeat(72));
  for (const f of r.findings) {
    const mark = f.verdict === DISAGREE ? '!!' : f.verdict === AGREE ? 'ok' : '  ';
    console.log(`  ${mark} ${f.verdict.padEnd(14)} ${f.reason}`);
    console.log(`       claim: ${f.claim}`);
    if (f.detail) console.log(`       ${f.detail}`);
  }
  console.log('  ' + '-'.repeat(72));
  console.log(`  AGREE ${c(AGREE)}  DISAGREE ${c(DISAGREE)}  INDETERMINATE ${c(INDETERMINATE)}  NOT_EVALUATED ${c(NOT_EVALUATED)}\n`);
  return c(DISAGREE);
}

/**
 * A signed verdict, reproducible by the party it is about.
 *
 * Two things a reader needs and a console dump does not give them: proof the
 * findings were not edited after the fact, and enough of the run to re-derive
 * them. So the signed payload carries the tool version, the target, every
 * finding verbatim, and the counts — and it is canonicalised through the
 * kernel's serialiser, so anyone with the public key can recompute the digest.
 *
 * `observed_at` is supplied, never invented here. A wall-clock field the tool
 * stamps itself makes the artifact unreproducible by its own subject: re-run it
 * and you get every verdict back and never the digest. That is a commitment
 * only its author can check, which is not a commitment.
 */
function signedVerdict(r, { observed_at }) {
  if (!observed_at) throw new Error('signedVerdict requires observed_at; the tool does not invent a clock');
  const c = (v) => r.findings.filter((f) => f.verdict === v).length;
  const payload = {
    tool: 'live-claim-audit/0.1.2',
    kernel: K.VERSION,
    target: r.base,
    observed_at,
    routes_examined: r.routes,
    findings: r.findings,
    counts: { AGREE: c(AGREE), DISAGREE: c(DISAGREE),
      INDETERMINATE: c(INDETERMINATE), NOT_EVALUATED: c(NOT_EVALUATED) },
    // Stated, not implied. Every verdict above that is not AGREE or DISAGREE is
    // something this run did NOT establish, and the reader is owed that number
    // next to the ones that sound like conclusions.
    not_established: c(INDETERMINATE) + c(NOT_EVALUATED),
  };
  const canonical = K.canonical(payload);
  const digest = K.sha256(canonical);
  return { payload, digest, signature: K.sign(digest), algorithm: 'ed25519' };
}

module.exports = { audit, report, harvest, advertisedRoutes, challenges, signedVerdict };

if (require.main === module) {
  const args = process.argv.slice(2);
  const base = args.find((a) => !a.startsWith('--'));
  const wantSigned = args.includes('--signed');
  const atArg = (args.find((a) => a.startsWith('--at=')) || '').slice(5);
  if (!base) {
    console.error('usage: live-claim-audit.cjs <https://base-url> [--signed] [--at=<iso8601>]');
    process.exit(2);
  }
  audit(base).then((r) => {
    const fail = report(r);
    if (wantSigned) {
      const v = signedVerdict(r, { observed_at: atArg || new Date().toISOString() });
      console.log(JSON.stringify(v, null, 2));
    }
    process.exit(fail ? 1 : 0);
  });
}

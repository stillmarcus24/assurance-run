#!/usr/bin/env node
'use strict';
/**
 * Assurance Run v0.1 — the kernel.
 *
 * One question: do two or more records describe the same economic event?
 * Four answers, never two:
 *
 *   AGREE          independently observed evidence matches the claim
 *   DISAGREE       independently observed evidence contradicts the claim
 *   INDETERMINATE  a check ran and the evidence could not settle it
 *   NOT_EVALUATED  no valid check ran at all
 *
 * The distinction between the last two is the whole point. Collapsing
 * "nothing was checked" into "checked, inconclusive" is how a gate that
 * never ran reads as a gate that passed.
 *
 * CORE INVARIANT (non-negotiable):
 *   Self-reported evidence ALONE can never produce an AGREE. If the only
 *   evidence is the counterparty's account of its own source, the verdict
 *   is INDETERMINATE / INSUFFICIENT_INDEPENDENCE. We would rather hand a
 *   customer a weaker verdict than a dishonest one — attesting to a report
 *   of a source is not attesting to the source.
 *
 * Inputs are frozen and hashed BEFORE observation so a run cannot quietly
 * redefine itself once the answer is known.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const VERSION = 'assurance-run/0.1';
// Paths are relative to this package and overridable by env, so a clean clone
// runs for a stranger with no setup. An absolute path to the author's own box
// is how a package that "works" only ever works for its author.
const HOME = process.env.ASSURANCE_HOME || path.join(__dirname, '.assurance');
const KEY_FILE = process.env.ASSURANCE_KEY || path.join(HOME, 'signing.key');
const PUB_FILE = process.env.ASSURANCE_PUB || path.join(HOME, 'signing.pub');
const RUN_DIR = process.env.ASSURANCE_RUNS || path.join(HOME, 'runs');

// ---------------------------------------------------------------- verdicts
const AGREE = 'AGREE';
const DISAGREE = 'DISAGREE';
const INDETERMINATE = 'INDETERMINATE';
const NOT_EVALUATED = 'NOT_EVALUATED';

// Independence classes. Only the first can ever yield AGREE.
const INDEPENDENT = 'independent_retrieval'; // we fetched the source ourselves
const SELF_REPORTED = 'self_reported';       // counterparty told us what it saw
const THIRD_PARTY = 'third_party_attested';  // a third party we do not control

// ------------------------------------------------------- fault classification
/**
 * Did OUR instrument break, or did the SOURCE fail to answer?
 *
 * `reachable: false` is a claim about the counterparty's system: we asked and
 * they could not settle it. An exception raised inside our own process is not
 * that claim — we may never have asked at all. Every adapter used to collapse
 * the two by catching everything into `reachable: false`, which put the exact
 * defect AC-11 prohibits one layer BELOW the kernel's guard, where AC-11 could
 * not see it (proved 2026-09-19: a `require()` of a missing module and a
 * malformed URL both reported the source as unreachable).
 *
 * The rule is positive identification, and it is deliberately asymmetric:
 * we say "the source was unreachable" ONLY when we can name the network-layer
 * failure that says so. Anything we cannot positively attribute to the wire is
 * charged to our own instrument, because an unclassified fault filed against a
 * counterparty is a claim we did not earn.
 */
const TRANSPORT_CODES = new Set([
  // POSIX / c-ares resolution and connection failures
  'ENOTFOUND', 'EAI_AGAIN', 'ECONNREFUSED', 'ECONNRESET', 'ECONNABORTED',
  'EHOSTUNREACH', 'ENETUNREACH', 'ENETDOWN', 'EPIPE', 'ETIMEDOUT', 'EPROTO',
  // undici transport
  'UND_ERR_CONNECT_TIMEOUT', 'UND_ERR_HEADERS_TIMEOUT', 'UND_ERR_BODY_TIMEOUT',
  'UND_ERR_SOCKET', 'UND_ERR_RESPONSE_STATUS_CODE', 'UND_ERR_CLOSED',
  // TLS: the peer's certificate or handshake, i.e. still about them
  'CERT_HAS_EXPIRED', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'ERR_TLS_CERT_ALTNAME_INVALID',
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'SELF_SIGNED_CERT_IN_CHAIN', 'ERR_SSL_WRONG_VERSION_NUMBER',
]);

function classifyFault(err) {
  const name = err && err.name;
  const msg = err && err.message ? String(err.message) : String(err);
  // A timeout is a real observation about the source: we asked and it did not
  // answer inside the window we declared. The window is ours, so we record it.
  if (name === 'TimeoutError' || name === 'AbortError' || name === 'HeadersTimeoutError') {
    return { instrument: false, kind: 'TIMEOUT', detail: msg };
  }
  for (const e of [err, err && err.cause]) {
    if (e && e.code && TRANSPORT_CODES.has(e.code)) {
      return { instrument: false, kind: 'TRANSPORT:' + e.code, detail: msg };
    }
  }
  // Everything else — ReferenceError, MODULE_NOT_FOUND, a URL we malformed
  // ourselves ("unknown scheme" arrives as a TypeError with no network code) —
  // is ours until proven otherwise.
  return {
    instrument: true,
    kind: 'INSTRUMENT:' + (name || 'Error') + ((err && err.code) ? ':' + err.code : ''),
    detail: msg,
  };
}

// ------------------------------------------------------------- canonical JSON
/**
 * Deterministic serialisation. Keys sorted, no floats that cannot round-trip,
 * amounts expected as strings by convention (a uint64 through a JS number is
 * a silent corruption — we have been bitten by exactly that).
 */
function canonical(value) {
  if (value === null) return 'null';
  const t = typeof value;
  if (t === 'number') {
    if (!Number.isFinite(value)) throw new Error('CANONICAL_NONFINITE_NUMBER');
    if (!Number.isSafeInteger(value) && Number.isInteger(value)) {
      throw new Error('CANONICAL_UNSAFE_INTEGER — pass large amounts as strings');
    }
    return JSON.stringify(value);
  }
  if (t === 'string' || t === 'boolean') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (t === 'object') {
    const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
  }
  throw new Error('CANONICAL_UNSUPPORTED_TYPE:' + t);
}

function sha256(s) {
  return crypto.createHash('sha256').update(typeof s === 'string' ? s : String(s)).digest('hex');
}

// ------------------------------------------------------------------ signing
function ensureKeys() {
  if (fs.existsSync(KEY_FILE) && fs.existsSync(PUB_FILE)) return;
  fs.mkdirSync(path.dirname(KEY_FILE), { recursive: true });
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  fs.writeFileSync(KEY_FILE, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  fs.writeFileSync(PUB_FILE, publicKey.export({ type: 'spki', format: 'pem' }), { mode: 0o644 });
}

function sign(payloadDigest) {
  ensureKeys();
  const privateKey = crypto.createPrivateKey(fs.readFileSync(KEY_FILE, 'utf8'));
  return crypto.sign(null, Buffer.from(payloadDigest), privateKey).toString('base64');
}

function verifySignature(payloadDigest, signature) {
  if (!fs.existsSync(PUB_FILE)) return false;
  const publicKey = crypto.createPublicKey(fs.readFileSync(PUB_FILE, 'utf8'));
  return crypto.verify(null, Buffer.from(payloadDigest), publicKey, Buffer.from(signature, 'base64'));
}

// -------------------------------------------------------------------- freeze
/**
 * Freeze the run specification. Everything that defines WHAT is being tested
 * must be here, and the digest must be computed before any observation.
 *
 * Required: event_id, claim, source, expected (the fields and values the claim
 * asserts). Optional but recorded: resource, window, rail, asset, scheme,
 * adapter, nonce.
 */
function freeze(spec) {
  const required = ['event_id', 'claim', 'source', 'expected'];
  for (const k of required) {
    if (spec[k] === undefined || spec[k] === null) throw new Error('FREEZE_MISSING_FIELD:' + k);
  }
  const frozen = {
    kernel_version: VERSION,
    event_id: spec.event_id,
    claim: spec.claim,
    source: spec.source,
    resource: spec.resource || null,
    expected: spec.expected,
    window: spec.window || null,
    rail: spec.rail || null,
    asset: spec.asset || null,
    scheme: spec.scheme || null,
    adapter: spec.adapter || null,
    adapter_version: spec.adapter_version || null,
    nonce: spec.nonce || null,
    frozen_at: spec.frozen_at || null, // caller supplies; kernel never invents a clock
  };
  frozen.spec_digest = sha256(canonical(frozen));
  Object.freeze(frozen);
  return frozen;
}

// --------------------------------------------------------------- provenance
/**
 * Every observation carries its own provenance or it is not admissible.
 * A bare value with no provenance is NOT_EVALUATED, not a silent pass.
 */
function provenanceOf(ev) {
  const required = ['source', 'observer', 'capture_method', 'observed_at',
    'raw_digest', 'adapter_version', 'independence_class'];
  const missing = required.filter((k) => ev == null || ev[k] === undefined || ev[k] === null);
  return { ok: missing.length === 0, missing };
}

// ---------------------------------------------------------------- evaluation
/**
 * The single generic comparator. Input A is the claim (frozen). Input B is
 * observed evidence. No customer-specific semantics live in here — adapters
 * normalise into `observed`, this function only ever compares.
 */
function evaluate(frozen, evidence) {
  // 1. No check ran at all.
  if (!evidence || evidence.attempted !== true) {
    return { verdict: NOT_EVALUATED, reason: 'NO_CHECK_ATTEMPTED' };
  }

  // 2. Evidence with no provenance is not evidence.
  const prov = provenanceOf(evidence);
  if (!prov.ok) {
    return { verdict: NOT_EVALUATED, reason: 'MISSING_PROVENANCE:' + prov.missing.join(',') };
  }

  // 2b. Our own instrument failed. Never a statement about the source.
  if (evidence.adapter_failed === true) {
    return { verdict: NOT_EVALUATED, reason: 'ADAPTER_FAILED',
      note: 'the adapter raised before producing an observation; this says nothing ' +
            'about the source and must never be recorded as one',
      error: evidence.error || null };
  }

  // 2c. The adapter was never wired. Not a failed check — no check exists yet.
  //     This used to return `reachable: false`, i.e. INDETERMINATE, which told a
  //     reader that we asked a source and it could not settle the claim. Nothing
  //     was ever asked: the operator did not configure the reader.
  if (evidence.not_configured === true) {
    return { verdict: NOT_EVALUATED, reason: 'ADAPTER_NOT_CONFIGURED',
      note: 'the adapter has no source wired; nothing was asked of anyone',
      error: evidence.error || null };
  }

  // 3. A schema we do not understand is never a pass and never a failure.
  if (evidence.schema_supported === false) {
    return { verdict: NOT_EVALUATED, reason: 'UNSUPPORTED_SCHEMA' };
  }

  // 4. A real attempt that could not reach the source is indeterminate.
  if (evidence.reachable === false) {
    return { verdict: INDETERMINATE, reason: 'SOURCE_UNREACHABLE' };
  }

  // 5. Adapter explicitly could not resolve.
  if (evidence.observed === undefined || evidence.observed === null) {
    return { verdict: INDETERMINATE, reason: 'NO_OBSERVATION_RESOLVED' };
  }

  // 6. A zero observed under a non-`exact` settlement scheme is a fact about
  //    where we looked, not about whether anyone paid. Buyer funds can move
  //    into the scheme's contract and never touch the advertised payTo.
  if (frozen.scheme && frozen.scheme !== 'exact' &&
      evidence.observed && evidence.observed.state === 'ZERO_OBSERVED') {
    return {
      verdict: INDETERMINATE,
      reason: 'ZERO_UNDER_NONEXACT_SCHEME',
      note: 'scheme is "' + frozen.scheme + '": settlement need never touch the advertised payTo, ' +
            'so an empty read is an observer scope statement, not evidence of non-payment',
    };
  }

  // 7. Compare. Field-wise over the frozen expectation only.
  const mismatches = [];
  for (const [k, want] of Object.entries(frozen.expected)) {
    const got = evidence.observed[k];
    if (got === undefined) { mismatches.push({ field: k, expected: want, observed: null, kind: 'absent' }); continue; }
    if (canonical(got) !== canonical(want)) mismatches.push({ field: k, expected: want, observed: got, kind: 'differs' });
  }

  if (mismatches.length) {
    // A contradiction stands regardless of independence: being told a wrong
    // number is still evidence the records disagree.
    return { verdict: DISAGREE, reason: 'FIELD_MISMATCH', mismatches };
  }

  // 8. THE INVARIANT. A match on self-reported evidence alone is not an AGREE.
  if (evidence.independence_class !== INDEPENDENT) {
    return {
      verdict: INDETERMINATE,
      reason: 'INSUFFICIENT_INDEPENDENCE',
      note: 'fields matched, but the evidence was not independently retrieved; ' +
            'this attests to a report of the source, not to the source',
      independence_class: evidence.independence_class,
    };
  }

  return { verdict: AGREE, reason: 'INDEPENDENT_MATCH' };
}

// ---------------------------------------------------------------------- run
async function run(spec, adapter, opts = {}) {
  const frozen = freeze(spec);
  let evidence;
  try {
    // `opts` is forwarded so a caller can supply observed_at. The kernel never
    // invents a clock -- an observation timestamp the kernel made up is not a
    // measurement, and observed_at is required provenance. Found 2026-09-15 when
    // the Starknet adapter returned a real, reachable reading that the evaluator
    // then correctly refused as MISSING_PROVENANCE: there was no supported way
    // to pass the timestamp through on the success path, only on the throw path.
    evidence = await adapter.observe(frozen, opts);
  } catch (err) {
    // AN ADAPTER THAT THREW IS NOT A STATEMENT ABOUT THE SOURCE.
    //
    // This previously set `reachable: false`, which the evaluator correctly reads
    // as INDETERMINATE / SOURCE_UNREACHABLE -- i.e. "we asked and the source could
    // not settle it". That is a claim about the world, and it is false: we never
    // asked. The instrument broke.
    //
    // Found 2026-09-15, in this repo, the day it was published: httpPublic threw
    // ReferenceError on EVERY successful fetch and every run reported the source
    // as unreachable. Three green suites, one of three adapters totally dead.
    // This is precisely the collapse this corpus exists to prohibit, committed by
    // the corpus itself -- an instrument failure wearing evidence's clothes.
    //
    // An adapter fault is OUR failure, so the verdict is NOT_EVALUATED.
    evidence = {
      attempted: true, adapter_failed: true,
      source: frozen.source, observer: adapter.name, capture_method: adapter.capture_method,
      observed_at: opts.observed_at || null, raw_digest: sha256('ADAPTER_THREW:' + err.message),
      adapter_version: adapter.version, independence_class: adapter.independence_class,
      error: err.message,
    };
  }

  const result = evaluate(frozen, evidence);

  const receipt = {
    kernel_version: VERSION,
    spec_digest: frozen.spec_digest,
    frozen,
    evidence,
    verdict: result.verdict,
    reason: result.reason,
    detail: result.mismatches || result.note || null,
  };
  receipt.receipt_digest = sha256(canonical(receipt));
  receipt.signature = sign(receipt.receipt_digest);
  return receipt;
}

// ------------------------------------------------------------------- replay
/**
 * Deterministic replay: same frozen input + same stored evidence + same
 * kernel version must reproduce the verdict and the digest byte-for-byte.
 * If it does not, the receipt is not reproducible and says so.
 */
function replay(receipt) {
  const redone = evaluate(receipt.frozen, receipt.evidence);
  const rebuilt = {
    kernel_version: receipt.kernel_version,
    spec_digest: receipt.frozen.spec_digest,
    frozen: receipt.frozen,
    evidence: receipt.evidence,
    verdict: redone.verdict,
    reason: redone.reason,
    detail: redone.mismatches || redone.note || null,
  };
  const digest = sha256(canonical(rebuilt));
  return {
    verdict_matches: redone.verdict === receipt.verdict,
    digest_matches: digest === receipt.receipt_digest,
    signature_valid: verifySignature(receipt.receipt_digest, receipt.signature),
    recomputed_verdict: redone.verdict,
    recomputed_digest: digest,
  };
}

function persist(receipt) {
  fs.mkdirSync(RUN_DIR, { recursive: true });
  const f = path.join(RUN_DIR, receipt.spec_digest.slice(0, 16) + '.json');
  fs.writeFileSync(f, JSON.stringify(receipt, null, 1));
  return f;
}

module.exports = {
  VERSION, AGREE, DISAGREE, INDETERMINATE, NOT_EVALUATED,
  INDEPENDENT, SELF_REPORTED, THIRD_PARTY,
  canonical, sha256, freeze, evaluate, run, replay, persist,
  sign, verifySignature, provenanceOf, classifyFault,
};

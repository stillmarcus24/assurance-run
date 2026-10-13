#!/usr/bin/env node
'use strict';
/*
 * acceptance-record-cold-check.cjs — an INDEPENDENT checker for the
 * acceptance-record-cold profile of
 * github.com/babyblueviper1/preaction-governance-conformance.
 *
 * WHY THIS EXISTS. x402-foundation/tsc#4 carries a table of implementations that
 * have run these vectors, and @TKCollective asked each to state its sentence-8
 * choice. Every implementation in that table is PYTHON: the reference checker,
 * actaseal's cold build, Noûs/omega, and Tetsuroh Hori's reader. This is the first
 * reading in another host language, which matters here specifically: the sibling
 * corpus records `record_commits` forking two engines on Python `is None` vs TS
 * `=== undefined` while every run stayed green, and this profile's own probe set
 * includes "the whitespace characters the two host languages' strip functions
 * disagree on". A second language is the control, not a formality.
 *
 * INDEPENDENCE, stated exactly. Written only from
 * `examples/acceptance-record-cold/README.md` (result tokens, Evaluation order,
 * sentences 1-8, readings A1-A8), the draft-krausz-verification-state-03 rules that
 * README quotes, and the vectors' own inputs. NOT opened: the reference
 * `tools/acceptance_record_check.py`, `tools/_ed25519.py`, `run_vectors.py`,
 * actaseal's checker, omega, and Hori's reader. Expectations were not read back
 * from any checker.
 *
 * WHAT IS OURS vs BORROWED:
 *   · Ed25519 verification — node:crypto (a platform primitive, not this suite's)
 *   · small-order point refusal — written here, from sentence 4
 *   · RFC 8785 JCS — written here (same rules as our tersign-reproduction.cjs)
 *   · sha256, base64url — node:crypto / Buffer
 *
 *   node acceptance-record-cold-check.cjs <vectors.json>
 *   node acceptance-record-cold-check.cjs <vectors.json> --json
 *   node acceptance-record-cold-check.cjs <vectors.json> --always-accept
 *        negative control: a checker that returns `verified` for everything.
 *        A row that cannot fail this is not evidence.
 */
const fs = require('fs');
const crypto = require('crypto');

// ── primitives ────────────────────────────────────────────────────────────────
const sha256hex = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

/** RFC 7515 §2 base64url: no padding, no standard-alphabet characters. */
const B64URL_RE = /^[A-Za-z0-9_-]*$/;
function b64urlDecode(s) {
  if (typeof s !== 'string' || !B64URL_RE.test(s)) return null;
  const buf = Buffer.from(s, 'base64url');
  // Round-trip guard: Buffer is lenient, the rule is not.
  if (buf.toString('base64url') !== s) return null;
  return buf;
}
function jsonObject(buf) {
  if (!buf) return null;
  let v;
  try { v = JSON.parse(buf.toString('utf8')); } catch { return null; }
  return (v && typeof v === 'object' && !Array.isArray(v)) ? v : null;
}

/** RFC 8785 (JCS) — used for the A8 record digest. */
function jcs(v) {
  if (v === null) return 'null';
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) throw new Error('non-finite number');
    return Number.isInteger(v) ? String(v) : JSON.stringify(v);
  }
  if (typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(jcs).join(',') + ']';
  // §3.2.3: sort member names by UTF-16 code unit, which is JS string order.
  const keys = Object.keys(v).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + jcs(v[k])).join(',') + '}';
}

/**
 * Sentence 4: the 8 points whose order divides 8, the identity among them, are not
 * keys of the confirming party. Canonical 32-byte little-endian encodings, listed
 * literally so the check does not depend on curve arithmetic.
 */
const SMALL_ORDER = new Set([
  '0100000000000000000000000000000000000000000000000000000000000000',
  '0000000000000000000000000000000000000000000000000000000000000000',
  '0000000000000000000000000000000000000000000000000000000000000080',
  '0100000000000000000000000000000000000000000000000000000000000080',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
  'e7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'e7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
]);
const isSmallOrder = (raw) => raw && raw.length === 32 && SMALL_ORDER.has(raw.toString('hex'));

const ED_DER_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
function verifyEd25519(rawPub, message, signature) {
  try {
    const key = crypto.createPublicKey({
      key: Buffer.concat([ED_DER_PREFIX, rawPub]), format: 'der', type: 'spki',
    });
    return crypto.verify(null, message, key, signature);
  } catch { return false; }
}

// ── the profile ───────────────────────────────────────────────────────────────
const HEX64 = /^[0-9a-f]{64}$/;                       // -03 §5.3.2, lowercase only
const TS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;  // sentence 5, exactly
const VERSION = 'acceptance-record-v0';               // A1
const DISPOSITIONS = new Set(['accepted', 'rejected', 'disputed']);
const SIGNED_MEMBERS = new Set([                      // sentence 1: others ignored
  'acceptance_version', 'accepted_at', 'accepted_record_sha256', 'confirming_party',
  'disposition', 'outcome_sha256', 'terms_sha256',
]);

const out = (result, conditions, extra) => ({ result, conditions, ...(extra || {}) });

/**
 * MUTANTS — each disables or weakens one rule this checker implements, so the corpus
 * can be asked whether it actually kills a wrong reading. A suite that cannot kill a
 * mutant does not pin that rule, and a 46/46 that no mutant can disturb is luck
 * rather than evidence. Each entry is a plausible misreading of the README, not a
 * random code edit.
 */
const MUTANTS = {
  precedence_not_strict: 'treats an acceptance at the outcome instant as preceding it (A7 read as <=)',
  no_hex_typecheck: 'accepts any JSON string as a *_sha256 member, so no suppression',
  complete_truthy: 'reads any truthy trust_material_complete as a declaration (sentence 8)',
  no_small_order_key: 'does not refuse a small-order trust-material key (sentence 4)',
  no_small_order_r: 'does not refuse a small-order signature R (sentence 4)',
  lenient_b64: 'accepts padded / standard-alphabet envelope members (sentence 2)',
  no_alg_check: 'does not require alg EdDSA (sentence 6)',
  authority_always: 'skips the authority step, so unknown is never reached (A6)',
  trim_party: 'trims confirming_party before the absent test (sentence 7)',
  version_any: 'accepts any acceptance_version (sentence 3)',
  signer_is_issuer_kid_only: 'reads A5 as the same kid only, dropping the key-bytes and party readings',
};
let MUT = null;
const m = (name) => MUT === name;

function check(c) {
  const record = c.accepted_record || {};

  // `no_record`: nothing was supplied. Disposition is not_responded, never a weaker
  // `accepted`.
  if (!c.acceptance) return out('no_record', [], { disposition: 'not_responded' });

  const INVALID = () => out('malformed', ['acceptance_member_invalid'], { disposition: null });

  // ── before the key step ────────────────────────────────────────────────────
  // Sentence 2: the three envelope members are base64url without padding.
  const dec = m('lenient_b64')
    ? (x) => (typeof x === 'string' ? Buffer.from(x.replace(/-/g, '+').replace(/_/g, '/'), 'base64') : null)
    : b64urlDecode;
  const protectedBuf = dec(c.acceptance.protected);
  const payloadBuf = dec(c.acceptance.payload);
  const sigBuf = dec(c.acceptance.signature);
  if (!protectedBuf || !payloadBuf || !sigBuf) return INVALID();

  // The protected header must decode to a JSON object (sentence 2) and carry
  // alg EdDSA and a string kid (sentence 6) — "with no usable kid there is nothing
  // to look up, so it is not key_unresolved".
  const header = jsonObject(protectedBuf);
  if (!header) return INVALID();
  if (!m('no_alg_check') && header.alg !== 'EdDSA') return INVALID();
  if (typeof header.kid !== 'string') return INVALID();

  // ── key step (§5.4.2), runs first and stops evaluation ─────────────────────
  // Sentence 8: a declaration only as the JSON value `true`.
  const complete = m('complete_truthy') ? !!c.trust_material_complete : c.trust_material_complete === true;
  const keyUnresolved = () => out('key_unresolved', [], {
    key_step: 'key_unresolved', disposition: null,
    ...(complete ? { policy_refusal: true } : {}),
  });

  const keys = (c.trust_material && Array.isArray(c.trust_material.keys)) ? c.trust_material.keys : [];
  // Sentence 8: on a duplicate kid, the FIRST Ed25519 entry for it is used.
  const entry = keys.find((k) => k && k.kid === header.kid && k.kty === 'OKP' && k.crv === 'Ed25519');
  if (!entry) return keyUnresolved();
  const rawPub = b64urlDecode(entry.x);
  if (!rawPub || rawPub.length !== 32) return keyUnresolved();
  // Sentence 4: a small-order key is not a key of the confirming party.
  if (!m('no_small_order_key') && isSmallOrder(rawPub)) return keyUnresolved();

  // Sentence 7: the signature covers the payload bytes AS GIVEN.
  const signingInput = Buffer.from(`${c.acceptance.protected}.${c.acceptance.payload}`, 'ascii');
  const sigInvalid = () => out('malformed', ['signature_invalid'], {
    key_step: 'signature_invalid', disposition: null,
  });
  if (sigBuf.length !== 64) return sigInvalid();
  // Sentence 4: a signature whose R is a small-order point is signature_invalid.
  if (!m('no_small_order_r') && isSmallOrder(sigBuf.subarray(0, 32))) return sigInvalid();
  if (!verifyEd25519(rawPub, signingInput, sigBuf)) return sigInvalid();

  // ── malformed conditions: report-all, with type-check suppression ───────────
  // A payload that decodes but is not a JSON object is found AFTER the key step.
  const p = jsonObject(payloadBuf);
  if (!p) return INVALID();

  const cond = new Set();
  const invalid = () => cond.add('acceptance_member_invalid');

  // Sentence 3 / A1
  if (!m('version_any') && (typeof p.acceptance_version !== 'string' || p.acceptance_version !== VERSION)) invalid();

  // Sentence 5: the timestamp form exactly, on both sides.
  const acceptedAtOk = typeof p.accepted_at === 'string' && TS.test(p.accepted_at);
  if (!acceptedAtOk) invalid();
  const outcomeAtOk = typeof record.outcome_at === 'string' && TS.test(record.outcome_at);
  if (!outcomeAtOk) invalid();
  // A7: strict. Compared only between two values of the pinned form.
  if (acceptedAtOk && outcomeAtOk && (m('precedence_not_strict') ? p.accepted_at <= record.outcome_at : p.accepted_at < record.outcome_at)) {
    cond.add('acceptance_precedes_outcome');
  }

  // A3/A2: confirming_party. Sentence 7 — byte-exact, NOT trimmed, so whitespace
  // only is a party name rather than absent.
  const partyStr = typeof p.confirming_party === 'string' ? (m('trim_party') ? p.confirming_party.trim() : p.confirming_party) : null;
  if (partyStr === null || partyStr === '') {
    cond.add('confirming_party_absent');
  }

  // A2: a signed record carrying not_responded contradicts itself.
  if (typeof p.disposition !== 'string' || !DISPOSITIONS.has(p.disposition)) invalid();

  // Digest members: well-typed means 64 lowercase hex, and an ill-typed member
  // raises acceptance_member_invalid ONLY — the mismatch it would cause is suppressed.
  const digest = (member, expected, mismatch) => {
    const v = p[member];
    if (typeof v !== 'string' || (!m('no_hex_typecheck') && !HEX64.test(v))) { invalid(); return; }
    if (typeof expected === 'string' && v !== expected) cond.add(mismatch);
  };
  digest('terms_sha256', record.terms_sha256, 'acceptance_terms_digest_mismatch');
  digest('outcome_sha256', record.outcome_sha256, 'acceptance_outcome_digest_mismatch');
  // A8: sha256 over the JCS bytes of the record AS SUPPLIED, every member included.
  let recordDigest = null;
  try { recordDigest = sha256hex(Buffer.from(jcs(record), 'utf8')); } catch { recordDigest = null; }
  digest('accepted_record_sha256', recordDigest, 'acceptance_record_digest_mismatch');

  // A5: the signer is the issuer if ANY of the three readings holds.
  const issuerEntry = keys.find((k) => k && k.kid === record.issuer_kid && k.kty === 'OKP' && k.crv === 'Ed25519');
  const issuerRaw = issuerEntry ? b64urlDecode(issuerEntry.x) : null;
  const sameKeyBytes = !!(issuerRaw && rawPub.equals(issuerRaw));
  const partyIsIssuer = typeof p.confirming_party === 'string' && p.confirming_party === record.issuer;
  const delegation = c.delegation || {};
  const issuerKids = Array.isArray(delegation[record.issuer]) ? delegation[record.issuer] : [];
  const signerIsIssuer = m('signer_is_issuer_kid_only')
    ? header.kid === record.issuer_kid
    : (sameKeyBytes || partyIsIssuer || issuerKids.includes(header.kid));
  if (signerIsIssuer) {
    cond.add('acceptance_signer_is_issuer');
  }

  if (cond.size) return out('malformed', [...cond], { disposition: null });

  // ── authority: only when nothing is malformed ───────────────────────────────
  // A6: resolves iff the delegation lists the signing kid under the confirming party.
  const partyKids = Array.isArray(delegation[p.confirming_party]) ? delegation[p.confirming_party] : [];
  if (!m('authority_always') && !partyKids.includes(header.kid)) {
    return out('unknown', ['acceptance_authority_unresolved'], { disposition: p.disposition });
  }
  return out('verified', [], { disposition: p.disposition });
}

// ── runner ────────────────────────────────────────────────────────────────────
const sameSet = (a, b) => a.length === b.length && [...a].sort().every((x, i) => x === [...b].sort()[i]);

function run(file, alwaysAccept) {
  const doc = JSON.parse(fs.readFileSync(file, 'utf8'));
  const rows = doc.vectors.map((v) => {
    const got = alwaysAccept
      ? { result: 'verified', conditions: [], disposition: 'accepted' }
      : check(v.case);
    const e = v.expect;
    // "Condition lists compare as SETS."
    let ok = got.result === e.result && sameSet(got.conditions || [], e.conditions || []);
    // key_step and policy_refusal are compared where the expectation states them.
    if (ok && 'key_step' in e) ok = got.key_step === e.key_step;
    if (ok && 'policy_refusal' in e) ok = (got.policy_refusal === true) === (e.policy_refusal === true);
    if (ok && 'disposition' in e) ok = (got.disposition ?? null) === e.disposition;
    return { id: v.id, expect: e, got, ok };
  });
  return rows;
}

if (require.main === module) {
  const file = process.argv[2];
  if (!file) { console.error('usage: node acceptance-record-cold-check.cjs <vectors.json> [--json] [--always-accept]'); process.exit(2); }
  const alwaysAccept = process.argv.includes('--always-accept');
  if (process.argv.includes('--mutants')) {
    const base = run(file, false).filter((r) => r.ok).length;
    console.log(`baseline ${base}/${run(file, false).length}\n`);
    let killed = 0;
    const names = Object.keys(MUTANTS);
    for (const name of names) {
      MUT = name;
      const rows = run(file, false);
      MUT = null;
      const fails = rows.filter((r) => !r.ok);
      if (fails.length) killed++;
      console.log(`  ${fails.length ? 'KILLED  ' : 'SURVIVED'} ${name.padEnd(28)} ${fails.length}/${rows.length} vectors catch it`);
      console.log(`           ${MUTANTS[name]}`);
      if (fails.length) console.log(`           by: ${fails.slice(0, 3).map((f) => f.id).join(', ')}${fails.length > 3 ? ` (+${fails.length - 3})` : ''}`);
    }
    console.log(`\nmutants killed by the corpus: ${killed}/${names.length}`);
    process.exit(0);
  }
  const rows = run(file, alwaysAccept);
  const pass = rows.filter((r) => r.ok).length;
  if (process.argv.includes('--json')) {
    console.log(JSON.stringify({ vectors: rows.length, agree: pass, rows }, null, 1));
  } else {
    for (const r of rows) {
      const g = `${r.got.result}${r.got.conditions && r.got.conditions.length ? '/' + r.got.conditions.join('+') : ''}`;
      const e = `${r.expect.result}${r.expect.conditions && r.expect.conditions.length ? '/' + r.expect.conditions.join('+') : ''}`;
      console.log(`  ${r.ok ? 'ok  ' : 'DIFF'} ${r.id.padEnd(50)} expect ${e.padEnd(46)} got ${g}`);
    }
    console.log(`\nacceptance-record-cold${alwaysAccept ? '  [ALWAYS-ACCEPT CONTROL]' : ''}`);
    console.log(`  vectors : ${rows.length}`);
    console.log(`  agree   : ${pass}/${rows.length}`);
  }
  process.exit(0);
}
module.exports = { check, run, jcs };

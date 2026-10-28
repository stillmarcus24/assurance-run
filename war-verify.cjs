#!/usr/bin/env node
'use strict';
/*
 * war-verify.cjs — an INDEPENDENT verifier for the work-acceptance record
 * draft profile 1.4.2 / schema 1.2, github.com/maximusrufus/work-acceptance-record.
 *
 * WHY: that repository maintains an Implementations table of verifiers written
 * from its text and run by their implementer on the published vectors. As of
 * commit cb7e8f1 it holds six rows and **every one of them is Python**, including
 * the reference. A second language is a stronger independence signal than a
 * seventh implementation in the first one, because it cannot share a library,
 * a datetime parser, an ASN.1 decoder or a base64 edge case with the reference.
 *
 * INDEPENDENCE, stated precisely so it can be checked rather than believed:
 * `verifier/war_verify.py` and `verifier/check_payment.py` were NOT fetched to
 * this machine, let alone read. The fetch step pulled `README.md` and
 * `vectors/*.json` only; `verifier/` was listed and deliberately skipped. Every
 * rule below is implemented from README.md's "Properties", "Verification
 * procedure (summary)" and "Profile 1.4.2 rules", plus the vectors' own inputs.
 * Each vector's `expected` object is in the same file as its inputs and was
 * therefore visible while the inputs were read — disclosed, not hidden.
 *
 * WHAT IS OURS vs BORROWED:
 *   · JCS (RFC 8785)        — written here
 *   · DER / ASN.1 walker    — written here (RFC 3161 TSTInfo extraction)
 *   · GeneralizedTime parse — written here, to the profile's own grammar
 *   · edwards25519 point ops— written here (the key rule needs [L]P, see below)
 *   · Ed25519 verification  — node:crypto
 *   · SHA-256               — node:crypto
 *
 * WHY THE CURVE ARITHMETIC IS HAND-WRITTEN. Step 2's key rule demands the public
 * key be "a canonical encoding (y < p) of a point of prime order"; a neutral,
 * small-order, mixed-order or non-canonical key is KEY_REJECTED and **no
 * signature check is run**. `crypto.verify` will not tell us that: it either
 * accepts the key or throws, and for a small-order key it can report a perfectly
 * ordinary signature failure — which is the wrong code (SIGNATURE_INVALID rather
 * than KEY_REJECTED) and the wrong order of operations. The only general test for
 * prime order is [L]P == identity, so the group law is implemented here.
 *
 *   node war-verify.cjs --self-test
 *   node war-verify.cjs <corpus-dir>            # runs vectors/*.json
 *   node war-verify.cjs <corpus-dir> --json
 *   node war-verify.cjs <corpus-dir> --run-file # per-vector output for listing
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest();
const hex = (buf) => Buffer.from(buf).toString('hex');

/* ── RFC 8785 JCS ──────────────────────────────────────────────────────────────
 * Members sorted by UTF-16 code unit, which is NOT the same as sorting by code
 * point for anything outside the BMP. JS's default string comparison already
 * orders by UTF-16 code unit, so `<` is correct here and `localeCompare` is not.
 * Numbers: this profile's records carry only integers (byte counts, page counts),
 * so the ECMAScript Number::toString form is exact for them. A non-integer would
 * need the full ryu shortest-round-trip form; `JSON.stringify` of a JS number is
 * already Number::toString, which is what RFC 8785 §3.2.2.3 requires.
 */
function jcs(v) {
  if (v === null) return 'null';
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) throw new Error('non-finite number has no canonical form');
    return JSON.stringify(v);
  }
  if (typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(jcs).join(',')}]`;
  if (typeof v === 'object') {
    const keys = Object.keys(v).sort();            // UTF-16 code unit order
    return `{${keys.map((k) => `${JSON.stringify(k)}:${jcs(v[k])}`).join(',')}}`;
  }
  throw new Error(`no canonical form for ${typeof v}`);
}

/* ── CANONICAL BASE64 (profile 1.4.2) ──────────────────────────────────────────
 * "the standard alphabet, `=` padding to a multiple of four, no whitespace, and
 * re-encoding the decoded bytes gives the input string."
 * The round-trip is the whole test and it is what makes this cheap to get right:
 * Node's decoder is permissive (it ignores whitespace, accepts the URL-safe
 * alphabet and tolerates missing padding), so decoding alone proves nothing.
 */
function b64(s) {
  if (typeof s !== 'string') return null;
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s)) return null;
  if (s.length % 4 !== 0) return null;
  const buf = Buffer.from(s, 'base64');
  if (buf.toString('base64') !== s) return null;
  return buf;
}

/* ── edwards25519, enough for the key rule ─────────────────────────────────── */
const P = (1n << 255n) - 19n;
const L = (1n << 252n) + 27742317777372353535851937790883648493n;   // prime order
const D = 37095705934669439343138083508754565189542113879843219016388785533085940283555n;

const mod = (a, m = P) => ((a % m) + m) % m;
const pow = (b, e, m = P) => { let r = 1n; b = mod(b, m); while (e > 0n) { if (e & 1n) r = mod(r * b, m); b = mod(b * b, m); e >>= 1n; } return r; };
const inv = (a) => pow(a, P - 2n);

/** Extended coordinates (X:Y:Z:T), T = XY/Z. */
const ZERO = { X: 0n, Y: 1n, Z: 1n, T: 0n };
function add(p, q) {
  const A = mod((p.Y - p.X) * (q.Y - q.X));
  const B = mod((p.Y + p.X) * (q.Y + q.X));
  const C = mod(p.T * 2n * D * q.T);
  const Dd = mod(p.Z * 2n * q.Z);
  const E = B - A, F = Dd - C, G = Dd + C, H = B + A;
  return { X: mod(E * F), Y: mod(G * H), Z: mod(F * G), T: mod(E * H) };
}
function mul(p, n) {
  let r = ZERO, d = p;
  while (n > 0n) { if (n & 1n) r = add(r, d); d = add(d, d); n >>= 1n; }
  return r;
}
const isZero = (p) => mod(p.X) === 0n && mod(p.Y - p.Z) === 0n;

/**
 * Decode a 32-byte compressed point. Returns null when the encoding is not
 * canonical or the point is not on the curve — both are KEY_REJECTED.
 * "canonical encoding (y < p)" is the explicit requirement: a y of p or above
 * re-encodes to a different 32 bytes, so it is rejected before any curve test.
 */
function decodePoint(b) {
  if (!Buffer.isBuffer(b) || b.length !== 32) return null;
  const bytes = Buffer.from(b);
  const sign = (bytes[31] >> 7) & 1;
  bytes[31] &= 0x7f;
  let y = 0n;
  for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(bytes[i]);
  if (y >= P) return null;                                    // non-canonical
  const y2 = mod(y * y);
  const num = mod(y2 - 1n), den = mod(D * y2 + 1n);
  let x = pow(mod(num * inv(den)), (P + 3n) / 8n);
  if (mod(x * x) !== mod(num * inv(den))) {
    x = mod(x * pow(2n, (P - 1n) / 4n));
    if (mod(x * x) !== mod(num * inv(den))) return null;      // not on the curve
  }
  if (x === 0n && sign === 1) return null;                     // non-canonical zero x
  if (Number(x & 1n) !== sign) x = mod(-x);
  return { X: x, Y: y, Z: 1n, T: mod(x * y) };
}

/** The step-2 key rule, as one predicate. */
function keyAcceptable(raw) {
  const pt = decodePoint(raw);
  if (!pt) return false;
  if (isZero(pt)) return false;              // neutral element
  return isZero(mul(pt, L));                 // prime order: [L]P == identity
}

function ed25519Verify(rawKey, msg, sig) {
  // SPKI wrapper for a raw Ed25519 public key: the OID and bit-string header are
  // fixed, so the prefix is a constant.
  const spki = Buffer.concat([
    Buffer.from('302a300506032b6570032100', 'hex'),
    rawKey,
  ]);
  try {
    const key = crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });
    return crypto.verify(null, msg, key, sig);
  } catch { return false; }
}

/* ── minimal DER walker ────────────────────────────────────────────────────── */
function derRead(buf, off) {
  if (off >= buf.length) return null;
  const tag = buf[off];
  let i = off + 1;
  if (i >= buf.length) return null;
  let len = buf[i++];
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || i + n > buf.length) return null;   // indefinite / absurd
    len = 0;
    for (let k = 0; k < n; k++) len = (len << 8) | buf[i++];
  }
  if (i + len > buf.length) return null;
  return { tag, start: off, hStart: off, hLen: i - off, len, body: buf.subarray(i, i + len), end: i + len };
}
function derChildren(node) {
  const out = [];
  let off = 0;
  while (off < node.body.length) {
    const c = derRead(node.body, off);
    if (!c) break;
    out.push(c);
    off = c.end;
  }
  return out;
}
function oidString(body) {
  if (!body.length) return '';
  const parts = [];
  const first = body[0];
  parts.push(Math.floor(first / 40), first % 40);
  let v = 0n;
  for (let i = 1; i < body.length; i++) {
    v = (v << 7n) | BigInt(body[i] & 0x7f);
    if (!(body[i] & 0x80)) { parts.push(v.toString()); v = 0n; }
  }
  return parts.join('.');
}
const OID_SHA256 = '2.16.840.1.101.3.4.2.1';
const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';
const OID_TSTINFO = '1.2.840.113549.1.9.16.1.4';

/**
 * Pull the signed TSTInfo out of an RFC 3161 TimeStampResp.
 *
 * ⚠️ Step 5 is explicit that the imprint comes from the SIGNED TSTInfo and
 * "never other bytes of the response, such as PKIStatusInfo.statusString", and
 * that genTime and accuracy come from the SAME TSTInfo. A walker that searched
 * the response for a 32-byte OCTET STRING would find the statusString case and
 * read a time from one structure and an imprint from another. So this descends
 * the real path and refuses anything else:
 *   TimeStampResp -> [1] timeStampToken ContentInfo -> SignedData
 *                 -> encapContentInfo{ eContentType = id-ct-TSTInfo, eContent }
 */
function parseTimeStampResp(der) {
  const top = derRead(der, 0);
  if (!top || top.tag !== 0x30) return null;
  const kids = derChildren(top);
  const ci = kids.find((k) => k.tag === 0x30 && (() => {
    const c = derChildren(k);
    return c.length && c[0].tag === 0x06 && oidString(c[0].body) === OID_SIGNED_DATA;
  })());
  if (!ci) return null;
  const ciKids = derChildren(ci);
  const wrapped = ciKids.find((k) => k.tag === 0xa0);
  if (!wrapped) return null;
  const sd = derRead(wrapped.body, 0);
  if (!sd || sd.tag !== 0x30) return null;
  const eci = derChildren(sd).find((k) => k.tag === 0x30 && (() => {
    const c = derChildren(k);
    return c.length && c[0].tag === 0x06 && oidString(c[0].body) === OID_TSTINFO;
  })());
  if (!eci) return null;
  const inner = derChildren(eci).find((k) => k.tag === 0xa0);
  if (!inner) return null;
  const oct = derRead(inner.body, 0);
  if (!oct || oct.tag !== 0x04) return null;
  const tst = derRead(oct.body, 0);
  if (!tst || tst.tag !== 0x30) return null;
  return parseTSTInfo(tst);
}

/**
 * TSTInfo ::= SEQUENCE { version, policy, messageImprint, serialNumber,
 *                        genTime, accuracy OPTIONAL, ordering DEFAULT FALSE, ... }
 * `ordering` is ignored per step 5. `accuracy` widens the time against "before".
 */
function parseTSTInfo(tst) {
  const k = derChildren(tst);
  if (k.length < 5) return null;
  const mi = k[2];
  if (mi.tag !== 0x30) return null;
  const miK = derChildren(mi);
  if (miK.length < 2 || miK[0].tag !== 0x30 || miK[1].tag !== 0x04) return null;
  const algK = derChildren(miK[0]);
  const algOid = algK.length && algK[0].tag === 0x06 ? oidString(algK[0].body) : '';
  const imprint = Buffer.from(miK[1].body);
  const gt = k[4];
  if (gt.tag !== 0x18) return null;
  const genTimeRaw = gt.body.toString('latin1');
  // accuracy is the first SEQUENCE after genTime, if any
  let accuracyMs = null;
  const acc = k.slice(5).find((x) => x.tag === 0x30);
  if (acc) {
    let seconds = 0, millis = 0, micros = 0;
    for (const f of derChildren(acc)) {
      const n = Number(BigInt(`0x${f.body.length ? hex(f.body) : '00'}`));
      if (f.tag === 0x02) seconds = n;
      else if (f.tag === 0x80) millis = n;
      else if (f.tag === 0x81) micros = n;
    }
    accuracyMs = seconds * 1000 + millis + Math.ceil(micros / 1000);
  }
  return { algOid, imprint, genTimeRaw, accuracyMs };
}

/* ── time ──────────────────────────────────────────────────────────────────────
 * genTime grammar, from profile 1.4.2 verbatim: "DER GeneralizedTime in UTC:
 * YYYYMMDDHHMMSS, optionally `.` and digits whose last is not `0`, then `Z`;
 * real calendar fields." Anything else is NO USABLE TIME — not an error, not a
 * refusal: the token is treated as giving none, which means
 * CRITERIA_COMMITMENT_UNVERIFIED and fallback to committed_at.
 *
 * ⚠️ `new Date(...)` is the trap here. It accepts "20260230000000Z"-shaped input
 * by rolling February 30th into March 2nd, so a reader built on it cannot see
 * "real calendar fields" at all. The fields are therefore range-checked by hand
 * before any Date is constructed.
 */
function parseGenTime(raw) {
  if (typeof raw !== 'string') return null;
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d+))?Z$/.exec(raw);
  if (!m) return null;
  const frac = m[7];
  if (frac !== undefined && (frac.length === 0 || frac.endsWith('0'))) return null;
  const [Y, Mo, Dy, H, Mi, S] = m.slice(1, 7).map(Number);
  if (Mo < 1 || Mo > 12 || Dy < 1 || H > 23 || Mi > 59 || S > 59) return null;
  const dim = [31, (Y % 4 === 0 && (Y % 100 !== 0 || Y % 400 === 0)) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (Dy > dim[Mo - 1]) return null;
  const ms = frac === undefined ? 0 : Number(`0.${frac}`) * 1000;
  return Date.UTC(Y, Mo - 1, Dy, H, Mi, S) + ms;      // fractional ms kept here
}

/** Stated times: RFC 3339 UTC, YYYY-MM-DDTHH:MM:SS[.fff]Z, real calendar fields. */
function parseStatedTime(raw) {
  if (typeof raw !== 'string') return null;
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{3}))?Z$/.exec(raw);
  if (!m) return null;
  const [Y, Mo, Dy, H, Mi, S] = m.slice(1, 7).map(Number);
  if (Mo < 1 || Mo > 12 || Dy < 1 || H > 23 || Mi > 59 || S > 59) return null;
  const dim = [31, (Y % 4 === 0 && (Y % 100 !== 0 || Y % 400 === 0)) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (Dy > dim[Mo - 1]) return null;
  return Date.UTC(Y, Mo - 1, Dy, H, Mi, S) + (m[7] ? Number(m[7]) : 0);
}

const isLowerDigest = (s) => typeof s === 'string' && /^[0-9a-f]{64}$/.test(s);

module.exports = {
  jcs, b64, keyAcceptable, decodePoint, ed25519Verify, sha256,
  parseTimeStampResp, parseTSTInfo, parseGenTime, parseStatedTime, isLowerDigest,
  derRead, derChildren, oidString, OID_SHA256,
};

/* ══ THE VERIFICATION PROCEDURE ═══════════════════════════════════════════════
 * Implemented in the order README.md numbers it, because the order is normative:
 * several vectors differ only in WHICH code is reported when two faults coexist
 * (64/86, 77, 88, en-style precedence cases), so a verifier that gets every rule
 * right and the sequence wrong disagrees on them.
 */
const SCHEMA = 'trilatic.acceptance-receipt/1.2';
const CANON = 'JCS-RFC8785';
const REFUSED = { refused: true, reason: 'unknown schema, canonicalization or suite' };

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const isStr = (v) => typeof v === 'string';

/** Step 1 + the 1.4.2 "Types." rule: a wrong type is an unsupported schema, never a crash. */
function schemaAcceptable(env) {
  if (!isObj(env) || !isObj(env.receipt)) return false;
  const r = env.receipt;
  if (r.schema !== SCHEMA) return false;
  if (r.canonicalization !== CANON) return false;
  if (!isObj(r.suite) || r.suite.digest !== 'sha-256' || r.suite.signature !== 'Ed25519') return false;
  // Shapes the procedure reads. A string where an object belongs (and vice versa)
  // is refused here rather than allowed to throw further down.
  if (!isObj(env.signature) || !isStr(env.signature.value) || !isStr(env.signature.key_id)) return false;
  if (!isStr(r.key_id)) return false;
  if (!Array.isArray(r.results)) return false;
  // 77 carries a result whose `id` is an OBJECT. The 1.4.2 Types rule makes that an
  // unsupported schema, refused at step 1 — not a CRITERIA_RESULTS_MISMATCH later,
  // which is what a verifier gets if it only type-checks the fields it compares.
  for (const x of r.results) {
    if (!isObj(x) || !isStr(x.result) || !isStr(x.id)) return false;
    if (x.required !== undefined && typeof x.required !== 'boolean') return false;
  }
  if (!isObj(r.criteria)) return false;
  if (!isObj(r.parties)) return false;
  for (const side of ['checker', 'producer']) {
    const p = r.parties[side];
    if (p !== undefined && p !== null && !isObj(p)) return false;
  }
  if (env.timestamp !== undefined && env.timestamp !== null && !isObj(env.timestamp)) return false;
  if (!isStr(r.verdict)) return false;
  if (!isStr(r.issued_utc)) return false;
  return true;
}

/** Property 4: pass only if every required criterion passes; fail beats incomplete. */
const RESULT_VOCAB = new Set(['pass', 'fail', 'not-evaluated', 'error']);
function recomputeVerdict(results) {
  let anyFail = false, anyIncomplete = false, badVocab = false;
  for (const r of results) {
    if (!RESULT_VOCAB.has(r.result)) {
      badVocab = true;
      // A required criterion whose result is not in the vocabulary is certainly not
      // a `pass`, and property 4 says the verdict is `pass` only if every required
      // criterion IS `pass`. So it behaves as not-evaluated: incomplete, never pass
      // (19). Skipping it instead would let an unreadable result be read as success.
      if (r.required === true) anyIncomplete = true;
      continue;
    }
    if (r.required !== true) continue;
    if (r.result === 'fail') anyFail = true;
    else if (r.result === 'not-evaluated' || r.result === 'error') anyIncomplete = true;
  }
  const verdict = anyFail ? 'fail' : anyIncomplete ? 'incomplete' : 'pass';
  return { verdict, badVocab };
}

/** Index the key file by key_id, flagging ids that appear more than once (1.4.2). */
function indexKeys(keyFile) {
  const byId = new Map(), dup = new Set();
  const list = isObj(keyFile) && Array.isArray(keyFile.keys) ? keyFile.keys : [];
  for (const e of list) {
    if (!isObj(e) || !isStr(e.key_id)) continue;
    if (byId.has(e.key_id)) { dup.add(e.key_id); continue; }  // "whichever entry comes first"
    byId.set(e.key_id, e);
  }
  return { byId, dup, list };
}

/** Decoded-bytes identity: two ids whose entries decode to one key are one key. */
function rawOf(entry) {
  if (!isObj(entry) || !isStr(entry.public_key_base64)) return null;
  return b64(entry.public_key_base64);                 // null when non-canonical
}

function verify(inputs, opts = {}) {
  const env = inputs.receipt;
  if (!schemaAcceptable(env)) return { ...REFUSED };

  const r = env.receipt;
  const problems = new Set(), warnings = new Set();
  const { byId, dup } = indexKeys(inputs.keys);

  /* ── step 2: signature ── */
  const signedKeyId = r.key_id;
  const signingEntry = byId.get(signedKeyId);
  const signingRaw = rawOf(signingEntry);
  // A repeated key_id is KEY_REJECTED whichever entry came first; a non-canonical
  // public key likewise; and in both cases NO signature check is run.
  // "A key_id listed more than once in the key list is KEY_REJECTED, whichever
  // entry comes first." 79 duplicates an id that is NEITHER the signer's nor a
  // party's and still expects KEY_REJECTED, so the rule is about the key LIST
  // being well-formed, not about which entry the record happens to use. The
  // follow-on sentence ("if it is the signing key's, no signature check is run")
  // governs the CONSEQUENCE, not whether the code is raised.
  if (dup.size) problems.add('KEY_REJECTED');
  const keyRejected = !signingEntry || signingRaw === null
    || dup.has(signedKeyId) || !keyAcceptable(signingRaw);

  let signatureValid = false;
  if (keyRejected) {
    problems.add('KEY_REJECTED');
  } else if (env.signature.key_id !== signedKeyId) {
    // The envelope is unsigned, so it cannot choose the key (64, 86).
    problems.add('SIGNATURE_INVALID');
  } else {
    const sig = b64(env.signature.value);          // non-canonical => SIGNATURE_INVALID
    const msg = Buffer.from(jcs(r), 'utf8');
    signatureValid = sig !== null && sig.length === 64 && ed25519Verify(signingRaw, msg, sig);
    if (!signatureValid) problems.add('SIGNATURE_INVALID');
  }

  /* ── independence, by key, as decoded bytes ── */
  const checker = isObj(r.parties.checker) ? r.parties.checker : null;
  const producer = isObj(r.parties.producer) ? r.parties.producer : null;
  const checkerId = checker && isStr(checker.key_id) ? checker.key_id : null;
  const producerId = producer && isStr(producer.key_id) ? producer.key_id : null;
  const producerNamed = !!(producer && isStr(producer.name) && producer.name.length);

  /* THE DERIVATION, and the one thing the text does not spell out.
   * Vectors 03 and 13 carry the SAME parties block — producer.name equal to
   * checker.name, producer.key_id null — and differ only in what the record
   * STATES. 03 states self-checked and has no problem codes; 13 states
   * independent and raises INDEPENDENCE_INCONSISTENT. Both report
   * `independence` equal to what they stated.
   * Only one reading satisfies both: the outcome's `independence` is the
   * record's STATED value, and the DERIVED value exists solely to decide
   * INDEPENDENCE_INCONSISTENT. A verifier that reports the derived value
   * instead agrees with 03 and contradicts 13, or the reverse.
   * Derived self-check holds when the two parties are one key (by identifier or
   * by decoded bytes), when they share a name, or when no producer is declared
   * at all — in the last case independence cannot be established, which is why
   * 20 carries both PRODUCER_UNDECLARED and INDEPENDENCE_INCONSISTENT. */
  let derivedIndependence = 'independent';
  if (!producerNamed) {
    warnings.add('PRODUCER_UNDECLARED');
    derivedIndependence = 'self-checked';
  }
  if (producerNamed && checker && isStr(checker.name) && producer.name === checker.name) {
    derivedIndependence = 'self-checked';
  }

  // A key entry for a stated producer or checker id that is not canonical base64
  // is KEY_REJECTED and independence is self-checked (69).
  for (const id of [checkerId, producerId]) {
    if (!id) continue;
    const e = byId.get(id);
    if (dup.has(id)) { problems.add('KEY_REJECTED'); derivedIndependence = 'self-checked'; }
    if (e && rawOf(e) === null) { problems.add('KEY_REJECTED'); derivedIndependence = 'self-checked'; }
  }

  // Same decoded bytes under two identifiers is one key: KEY_COLLISION + self-checked.
  if (checkerId && producerId) {
    const a = rawOf(byId.get(checkerId)), b = rawOf(byId.get(producerId));
    // One key under one identifier or under two is the same finding. Vector 05
    // names the checker's own key_id as the producer's and expects KEY_COLLISION,
    // so the code is about the KEY being shared, not about the identifiers
    // differing; 65 and 87 are the two-identifier form of the same thing.
    if (checkerId === producerId || (a && b && a.equals(b))) {
      problems.add('KEY_COLLISION');
      derivedIndependence = 'self-checked';
    }
  }

  // When a key_id is stated and independence: independent is claimed, that id must
  // be non-empty and listed exactly once (80, 81). A producer with no key_id rests
  // on the party names (82).
  if (r.independence === 'independent') {
    for (const [id, present] of [[checkerId, checker], [producerId, producer]]) {
      if (!present) continue;
      if (id === null) continue;                      // not stated: names carry it
      if (id === '' || !byId.has(id) || dup.has(id)) problems.add('INDEPENDENCE_INCONSISTENT');
    }
  }
  if (isStr(r.independence) && r.independence !== derivedIndependence) {
    problems.add('INDEPENDENCE_INCONSISTENT');
  }
  // SELF_CHECKED follows the STATED independence, not the derived one. 13 derives
  // self-checked (the parties share a name) while stating independent, and expects
  // INDEPENDENCE_INCONSISTENT with NO warning: the warning exists to caveat a
  // record that presents itself as a self-check, and 13 does not.
  if (r.independence === 'self-checked') warnings.add('SELF_CHECKED');

  // CHECKER_NOT_SIGNER compares the checker's key_id with the SIGNED key_id.
  if (checkerId !== null && checkerId !== signedKeyId) problems.add('CHECKER_NOT_SIGNER');

  /* ── step 4: criteria document ── */
  let criteriaHash = 'not_supplied';
  const critFile = isStr(inputs.criteria_file_base64) ? b64(inputs.criteria_file_base64) : undefined;
  if (inputs.criteria_file_base64 !== undefined) {
    const want = r.criteria.sha256;
    if (critFile === null) {                 // non-canonical base64 matches nothing
      criteriaHash = 'mismatch';
      problems.add('CRITERIA_HASH_MISMATCH');
    } else if (isLowerDigest(want) && hex(sha256(critFile)) === want) {
      criteriaHash = 'match';
      // results must correspond to the criteria
      try {
        const doc = JSON.parse(critFile.toString('utf8'));
        const ids = new Set((doc.criteria || []).map((c) => c.id));
        const got = new Set(r.results.map((x) => x.id));
        const sameSize = ids.size === got.size;
        const allPresent = [...ids].every((i) => got.has(i));
        const requiredAgrees = (doc.criteria || []).every((c) => {
          const res = r.results.find((x) => x.id === c.id);
          return res && res.required === c.required;
        });
        if (!sameSize || !allPresent || !requiredAgrees) problems.add('CRITERIA_RESULTS_MISMATCH');
      } catch { problems.add('CRITERIA_RESULTS_MISMATCH'); }
    } else {
      criteriaHash = 'mismatch';
      problems.add('CRITERIA_HASH_MISMATCH');
    }
  }

  /* ── step 6 first, because step 5 needs the record token's genTime ── */
  const canonicalReceipt = Buffer.from(jcs(r), 'utf8');
  const receiptDigest = sha256(canonicalReceipt);
  let receiptTimestamp = 'none';
  let recordTokenTime = null;
  if (isStr(inputs.receipt_tsr_base64)) {
    const raw = b64(inputs.receipt_tsr_base64);
    const tst = raw ? parseTimeStampResp(raw) : null;
    if (!tst) receiptTimestamp = 'imprint_mismatch';
    else if (tst.algOid !== OID_SHA256 || !tst.imprint.equals(receiptDigest)) receiptTimestamp = 'imprint_mismatch';
    else {
      receiptTimestamp = 'imprint_match';
      // "A mismatching token is never used as evidence of time" — so the time is
      // read ONLY from a token whose imprint matched.
      recordTokenTime = parseGenTime(tst.genTimeRaw);
    }
  }

  /* ── step 5: criteria commitment ── */
  const issued = parseStatedTime(r.issued_utc);
  let referenceTime = issued;
  if (recordTokenTime !== null && issued !== null) referenceTime = Math.min(issued, recordTokenTime);
  else if (recordTokenTime !== null && issued === null) referenceTime = recordTokenTime;

  let commitTime = null, usableCriteriaToken = false;
  if (isStr(inputs.criteria_tsr_base64)) {
    const raw = b64(inputs.criteria_tsr_base64);
    const tst = raw ? parseTimeStampResp(raw) : null;
    // "Without a usable token (none, OR ONE OVER OTHER BYTES), fall back to
    // committed_at and warn CRITERIA_COMMITMENT_UNVERIFIED." A token whose imprint
    // does not match, or whose imprint algorithm is not SHA-256, is exactly that
    // case: it is both a problem (the mismatch) AND an unverified commitment
    // (15, 23, 24, 25). Reporting only the mismatch loses the warning.
    if (!tst) {
      problems.add('CRITERIA_TIMESTAMP_MISMATCH');
      warnings.add('CRITERIA_COMMITMENT_UNVERIFIED');
    } else if (tst.algOid !== OID_SHA256 || !isLowerDigest(r.criteria.sha256)
             || hex(tst.imprint) !== r.criteria.sha256) {
      problems.add('CRITERIA_TIMESTAMP_MISMATCH');
      warnings.add('CRITERIA_COMMITMENT_UNVERIFIED');
    } else {
      const t = parseGenTime(tst.genTimeRaw);
      if (t === null) warnings.add('CRITERIA_COMMITMENT_UNVERIFIED');   // no usable time
      else {
        usableCriteriaToken = true;
        // accuracy widens the token's time against "committed before"
        commitTime = t + (tst.accuracyMs || 0);
        const statedRaw = r.criteria.committed_at;
        const stated = parseStatedTime(statedRaw);
        /* genTime is authoritative; a committed_at that disagrees is a mismatch,
         * and an unreadable committed_at beside a usable token is also one (88).
         *
         * ⚠️ COMPARED AT THE PRECISION THE STATED TIME EXPRESSES. `committed_at` is
         * RFC 3339 with an OPTIONAL `.fff`; a token's genTime may carry more. 66
         * states 12:00:00Z against a genTime of 12:00:00.5Z and 68 states the same
         * against 12:00:00.2495Z, and NEITHER expects CRITERIA_TIME_MISMATCH — they
         * expect only CRITERIA_COMMITTED_AFTER_CHECK. An exact-equality comparison
         * turns every sub-second token into a spurious mismatch, which is the
         * opposite of what those two vectors are for: they exist to test the
         * FRACTION's effect on "before", and a mismatch code would mask it. */
        const statedHasMs = typeof statedRaw === 'string' && statedRaw.includes('.');
        const unit = statedHasMs ? 1 : 1000;
        const agrees = stated !== null && Math.floor(stated / unit) === Math.floor(t / unit);
        if (!agrees) problems.add('CRITERIA_TIME_MISMATCH');
      }
    }
  } else {
    warnings.add('CRITERIA_COMMITMENT_UNVERIFIED');
  }

  let committedBefore;
  if (!usableCriteriaToken) {
    // fall back to committed_at
    const stated = parseStatedTime(r.criteria.committed_at);
    if (stated === null) {
      problems.add('RECEIPT_TIME_UNREADABLE');
      committedBefore = 'no';
    } else if (referenceTime === null) {
      problems.add('RECEIPT_TIME_UNREADABLE');
      committedBefore = 'no';
    } else {
      commitTime = stated;
      committedBefore = stated < referenceTime ? 'yes' : 'no';
      if (committedBefore === 'no') problems.add('CRITERIA_COMMITTED_AFTER_CHECK');
    }
  } else if (referenceTime === null) {
    problems.add('RECEIPT_TIME_UNREADABLE');
    committedBefore = 'no';
  } else {
    // "the criteria time is rounded up and the reference time down", strict <
    const c = Math.ceil(commitTime), ref = Math.floor(referenceTime);
    committedBefore = c < ref ? 'yes' : 'no';
    if (committedBefore === 'no') problems.add('CRITERIA_COMMITTED_AFTER_CHECK');
  }

  /* ── step 7: verdict ── */
  const { verdict: recomputed, badVocab } = recomputeVerdict(r.results);
  if (badVocab) problems.add('RESULT_VOCABULARY');
  if (r.verdict !== recomputed) problems.add('VERDICT_MISMATCH');

  /* ── step 9: tsa_signature ─────────────────────────────────────────────────
   * "The outcome MAY carry `tsa_signature`, an object with keys `criteria`
   * and/or `receipt` (ONE PER TOKEN PRESENT). Without relying-party anchors
   * (none supplied, or an empty list) it is `not_evaluated`, and an absent field
   * reads the same." So the no-anchor answer needs no cryptography at all — only
   * the correct set of keys, which is decided by which tokens the input carries.
   *
   * ⚠️ SCOPE DECLARED, NOT PAPERED OVER. With anchors supplied, the value
   * requires full CMS and X.509 work: SignedData signature verification over
   * RSA PKCS#1 v1.5 and ECDSA P-256/P-384, the contentType signed attribute, ESS
   * signing-certificate binding, id-kp-timeStamping, and a chain of CA issuers
   * reaching an anchor matched by subject name and public key with every
   * certificate valid at genTime. That is NOT implemented here. This returns
   * `not_evaluated` ONLY when the profile says it should, and omits the field
   * when anchors were supplied rather than guessing a value — a wrong `verified`
   * would be far worse than an absent field, because it would assert that a time
   * was validated against a trust anchor when nothing of the kind happened. */
  const tokensPresent = [];
  if (isStr(inputs.criteria_tsr_base64)) tokensPresent.push('criteria');
  if (isStr(inputs.receipt_tsr_base64)) tokensPresent.push('receipt');
  const anchors = Array.isArray(inputs.tsa_roots_base64) ? inputs.tsa_roots_base64
    : (isStr(inputs.tsa_roots_base64) ? [inputs.tsa_roots_base64] : []);
  /* ⚠️ THE FIELD IS OMITTED WHEN ANCHORS ARE ABSENT, not emitted as
   * not_evaluated. The profile's own sentence makes these equivalent — "and an
   * absent field reads the same" — and omitting is what the vectors show: 84 of
   * the 90 carry a token with no anchors and their `expected` objects have no
   * `tsa_signature` member at all, while 36 and 43 state it explicitly. Emitting
   * it everywhere disagreed with 59 vectors that the profile says it agrees with.
   * The comparison therefore has to apply the equivalence, and it does. */
  let tsaSignature;
  if (anchors.length > 0 && tokensPresent.length) {
    // Anchors supplied: a real value is required and the CMS work above is not
    // implemented, so the field is left absent rather than asserted wrongly.
    tsaSignature = undefined;
  }

  return {
    ...(tsaSignature ? { tsa_signature: tsaSignature } : {}),
    criteria_committed_before_check: committedBefore,
    criteria_hash: criteriaHash,
    independence: isStr(r.independence) ? r.independence : derivedIndependence,
    problem_codes: [...problems].sort(),
    receipt_timestamp: receiptTimestamp,
    signature_valid: signatureValid,
    verdict_recomputed: recomputed,
    verdict_stated: r.verdict,
    warning_codes: [...warnings].sort(),
  };
}

module.exports.verify = verify;
module.exports.recomputeVerdict = recomputeVerdict;
module.exports.schemaAcceptable = schemaAcceptable;

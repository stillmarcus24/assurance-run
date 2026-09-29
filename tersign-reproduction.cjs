#!/usr/bin/env node
'use strict';
/*
 * tersign-reproduction.cjs — an INDEPENDENT verifier for the evidence-record
 * conformance corpus at github.com/tersignhq/evidence-record-conformance.
 *
 * WHY THIS EXISTS. Tersign published four criteria any Phase 1 corpus should meet
 * (x402-foundation/tsc#4, 2026-09-28) and named the one they do not yet meet:
 *
 *   "A corpus run only by implementations that share code or authors is not
 *    reproduced. No verifier, ours included, is the reference. ...to our knowledge
 *    no implementation we did not write has run the full set."
 *
 * This is that run. It shares no code with `verify.py`: `verify.py` was never read
 * while writing this file. Every rule here was implemented from `MANIFEST.json`'s
 * normative fields and `README.md`'s class table, plus the vectors' own inputs.
 * Where the spec was ambiguous the ambiguity is recorded in the report rather than
 * resolved by looking at the expected answer.
 *
 * WHAT IS OURS vs BORROWED:
 *   · JSON parser        — written here, token-preserving (see WHY below)
 *   · RFC 8785 JCS       — written here, same rules as StillOS core/kya_intent_receipt.cjs
 *   · keccak256          — viem (a third-party library, not Tersign's)
 *   · sha256             — node:crypto
 *
 * WHY A HAND-WRITTEN JSON PARSER, and not JSON.parse. Two corpus vectors are
 * unrepresentable after JSON.parse, by design:
 *   · n35 / n38 carry the wire token `2.0` / `3.0`. JSON.parse collapses both to the
 *     integer 2 / 3, so a verifier built on it cannot see the number-token class at
 *     all and silently passes the vector that exists to catch it.
 *   · n2 carries integer-like object keys. A JS engine hoists those into ascending
 *     numeric order on object rebuild, which silently defeats sort-then-stringify —
 *     RFC 8785 §3.2.3 orders by UTF-16 code unit, so "1" < "10" < "2".
 * So the parser keeps key insertion order as an array of entries, keeps numbers as
 * their raw source token, and rejects duplicate names.
 *
 *   node tersign-reproduction.cjs --self-test            # primitives, known answers
 *   node tersign-reproduction.cjs <path-to-corpus>       # run all vectors
 *   node tersign-reproduction.cjs <path> --json          # machine-readable report
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ── primitives ────────────────────────────────────────────────────────────────
let keccak256, toBytes;
try {
  ({ keccak256, toBytes } = require('/home/marcus/still-os-consciousness/node_modules/viem/_cjs/index.js'));
} catch {
  try { ({ keccak256, toBytes } = require('viem')); }
  catch { console.error('need viem for keccak256'); process.exit(2); }
}
const kec = (buf) => keccak256(buf).slice(2);                    // hex, no 0x
const kecUtf8 = (s) => kec(Buffer.from(s, 'utf8'));
const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

/** A reject with a pinned reason code from the suite's closed set. */
class Reject extends Error {
  constructor(reason, detail) { super(detail || reason); this.reason = reason; }
}

// ── token-preserving JSON parser ──────────────────────────────────────────────
// Node shapes: {t:'o',e:[[k,node]]} {t:'a',v:[node]} {t:'s',v} {t:'n',tok} {t:'b',v} {t:'z'}
function parseJson(text) {
  let i = 0;
  const err = (m) => { throw new Reject('canonicalization_reject', `${m} at ${i}`); };
  const ws = () => { while (i < text.length && ' \t\n\r'.includes(text[i])) i++; };

  function value() {
    ws();
    const c = text[i];
    if (c === '{') return obj();
    if (c === '[') return arr();
    if (c === '"') return { t: 's', v: str() };
    if (c === 't') { lit('true'); return { t: 'b', v: true }; }
    if (c === 'f') { lit('false'); return { t: 'b', v: false }; }
    if (c === 'n') { lit('null'); return { t: 'z' }; }
    return num();
  }
  function lit(w) { if (text.slice(i, i + w.length) !== w) err(`expected ${w}`); i += w.length; }
  function obj() {
    i++; const e = []; const seen = new Set(); ws();
    if (text[i] === '}') { i++; return { t: 'o', e }; }
    for (;;) {
      ws();
      if (text[i] !== '"') err('expected key');
      const k = str();
      // RFC 8785 has no defined behaviour for duplicate names; the suite rejects them.
      if (seen.has(k)) throw new Reject('canonicalization_reject', `duplicate object name ${JSON.stringify(k)}`);
      seen.add(k);
      ws(); if (text[i] !== ':') err('expected :'); i++;
      e.push([k, value()]);
      ws();
      if (text[i] === ',') { i++; continue; }
      if (text[i] === '}') { i++; return { t: 'o', e }; }
      err('expected , or }');
    }
  }
  function arr() {
    i++; const v = []; ws();
    if (text[i] === ']') { i++; return { t: 'a', v }; }
    for (;;) {
      v.push(value()); ws();
      if (text[i] === ',') { i++; continue; }
      if (text[i] === ']') { i++; return { t: 'a', v }; }
      err('expected , or ]');
    }
  }
  function str() {
    i++; let out = '';
    for (;;) {
      const c = text[i];
      if (c === undefined) err('unterminated string');
      if (c === '"') { i++; return out; }
      if (c === '\\') {
        i++;
        const e = text[i++];
        if (e === 'u') { out += String.fromCharCode(parseInt(text.slice(i, i + 4), 16)); i += 4; }
        else if (e === 'n') out += '\n';
        else if (e === 't') out += '\t';
        else if (e === 'r') out += '\r';
        else if (e === 'b') out += '\b';
        else if (e === 'f') out += '\f';
        else if (e === '"' || e === '\\' || e === '/') out += e;
        else err(`bad escape \\${e}`);
        continue;
      }
      out += c; i++;
    }
  }
  function num() {
    const start = i;
    if (text[i] === '-') i++;
    while (i < text.length && /[0-9eE+.\-]/.test(text[i])) i++;
    const tok = text.slice(start, i);
    if (!/^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$/.test(tok)) err(`bad number ${tok}`);
    return { t: 'n', tok };
  }

  const v = value(); ws();
  if (i !== text.length) err('trailing content');
  return v;
}

/** Plain-JS view of a node, for logic that does not hash. Numbers become JS numbers. */
function toJS(n) {
  if (n === undefined) return undefined;          // absent member, not a crash
  switch (n.t) {
    case 'o': { const o = {}; for (const [k, v] of n.e) o[k] = toJS(v); return o; }
    case 'a': return n.v.map(toJS);
    case 's': return n.v;
    case 'n': return Number(n.tok);
    case 'b': return n.v;
    default: return null;
  }
}
/** Is this key present at all (as opposed to present-and-null)? */
const hasKey = (n, k) => n && n.t === 'o' && n.e.some(([kk]) => kk === k);
const get = (n, k) => { if (!n || n.t !== 'o') return undefined; const f = n.e.find(([kk]) => kk === k); return f && f[1]; };

// ── RFC 8785 (JCS) over a parsed node ─────────────────────────────────────────
// Number domain of this corpus: I-JSON integers, |n| <= 2^53-1, and the boundary is
// the TOKEN class — a fraction or exponent form is rejected even when integer-valued
// (`2.0`, `1e2`). That is why the token is carried this far instead of a Number.
const MAX_SAFE = 9007199254740991;
function jcs(n) {
  switch (n.t) {
    case 'z': return 'null';
    case 'b': return n.v ? 'true' : 'false';
    case 's': return JSON.stringify(n.v);
    case 'n': {
      if (!/^-?(0|[1-9][0-9]*)$/.test(n.tok)) {
        throw new Reject('number_domain_reject', `non-integer JSON number token "${n.tok}" in the digest domain`);
      }
      const v = Number(n.tok);
      if (!Number.isSafeInteger(v) || Math.abs(v) > MAX_SAFE) {
        throw new Reject('number_domain_reject', `integer ${n.tok} outside I-JSON range`);
      }
      return String(v);
    }
    case 'a': return '[' + n.v.map(jcs).join(',') + ']';
    case 'o': {
      // §3.2.3: sort by UTF-16 code units. JS string relational operators are exactly
      // code-unit order, so this is the standard ordering, not a coincidence of locale.
      const e = n.e.slice().sort((x, y) => (x[0] < y[0] ? -1 : x[0] > y[0] ? 1 : 0));
      return '{' + e.map(([k, v]) => JSON.stringify(k) + ':' + jcs(v)).join(',') + '}';
    }
    default: throw new Reject('canonicalization_reject', `unknown node ${n.t}`);
  }
}
const contentAddress = (node) => kecUtf8(jcs(node));   // MANIFEST content_address

// ── CRYPTO PROFILE: counter-signature recovery over the links ─────────────────
//
// MANIFEST `profile` puts this outside the stdlib core and says exactly why it
// matters: "a structurally complete set recomputed wholesale by one forging party
// passes the structural predicate; the counter-signatures are what prevent that in
// production." So the structural run above is necessary and not sufficient, and this
// is the half that closes it.
//
// THE TRAP THIS CODE IS WRITTEN AROUND. secp256k1 recovery returns *an* address for
// essentially any (hash, signature) pair. A verifier that recovers an address and
// reports success has verified nothing; verification only exists relative to an
// EXPECTED signer. So every function here demands the expected signer as an argument
// and there is no "recover and pass" path.
const secp = (() => {
  try { return require('/home/marcus/still-os-consciousness/node_modules/viem/_cjs/index.js'); }
  catch { try { return require('viem'); } catch { return null; } }
})();
// Signing (test-only, for the known-answer vectors) lives on a separate viem export
// path than recovery. Recovery — the only thing a verifier needs — is on `secp`.
const secpAccounts = (() => {
  try { return require('/home/marcus/still-os-consciousness/node_modules/viem/_cjs/accounts/index.js'); }
  catch { try { return require('viem/accounts'); } catch { return null; } }
})();

/** EIP-191 personal_sign preimage: "\x19Ethereum Signed Message:\n" + len + msg. */
function eip191Digest(messageBytes) {
  const prefix = Buffer.from(`\x19Ethereum Signed Message:\n${messageBytes.length}`, 'utf8');
  return kec(Buffer.concat([prefix, messageBytes]));
}

/**
 * Recover the address that produced `sig` over `messageBytes` under personal_sign.
 * Returns a lowercase 0x address. NEVER treat a successful return as verification —
 * compare it to an expected signer.
 */
async function recoverPersonalSign(messageBytes, sig) {
  const hash = '0x' + eip191Digest(messageBytes);
  const addr = await secp.recoverAddress({ hash, signature: sig });
  return addr.toLowerCase();
}

/**
 * The crypto-profile predicate: every link in a structurally valid chain set must
 * carry a counter-signature that recovers to `expectedSigner`.
 *
 * `linkSignatures` is {seq: sig}. A link with no signature is NOT a pass — an
 * unsigned link is the forging case the profile exists to catch, so it rejects.
 */
async function verifyLinkCounterSignatures(input, expectedSigner, linkSignatures) {
  const want = normId(expectedSigner);
  if (!want || want.kind !== 'addr') throw new Reject('crypto_reject', 'expected signer does not parse as an address');
  const { hseq, links } = chainSet(input);                 // structural first, always
  const checked = [];
  for (let s = 1; s <= hseq; s++) {
    const sig = linkSignatures && linkSignatures[s];
    if (!sig) throw new Reject('crypto_reject', `link ${s} carries no counter-signature`);
    const got = await recoverPersonalSign(Buffer.from(links[s - 1], 'hex'), sig);
    if (got !== want.v) {
      throw new Reject('crypto_reject', `link ${s} counter-signature recovers to ${got}, expected ${want.v}`);
    }
    checked.push(s);
  }
  return { links_verified: checked.length, signer: want.v };
}

// ── identifier normalization (MANIFEST identifier_normalization) ──────────────
// Two syntaxes, both evaluated by every criterion that compares identity:
//   0x-addresses            -> strip + lowercase
//   scheme-qualified ids    -> strip, case-significant
// An identifier that does not parse AFTER normalization is not evaluable and fails
// closed. n13 is the whole reason this exists: a party appends a space to its own
// address and relabels itself as its own outside witness.
// TWO CALLS THE SPEC DOES NOT FIX, made switchable rather than decided silently.
// The suite names percent-encoding a "stated open sibling" and does not settle it,
// and the trailing-slash rule is inferred from n31 rather than written. Picking one
// reading and reporting a green run would hide that; so both readings are
// implementable and `--policy-matrix` reports exactly which vectors move between
// them. That turns "a reader may disagree" into a measured consequence the working
// group can price.
const POLICY = {
  // n31's alias bypass ("org:caldera-robotics/" vs "org:caldera-robotics") is only
  // caught if a trailing slash normalizes away. Default ON because n31 exists.
  stripTrailingSlash: true,
  // Percent-decoding would make "org:caldera%2Drobotics" the same identifier. Default
  // OFF: the suite declines to fix it, and inventing a rule is not reproduction.
  percentDecode: false,
};
function normId(raw, policy) {
  const P = policy || POLICY;
  if (typeof raw !== 'string') return null;
  const s = raw.trim();
  if (/^0x[0-9a-fA-F]{40}$/.test(s)) return { kind: 'addr', v: s.toLowerCase() };
  // lowercase alnum scheme, exactly one colon, printable non-space ASCII path
  const m = /^([a-z0-9]+):([\x21-\x7e]+)$/.exec(s);
  if (m && !m[2].includes(':')) {
    let p = m[2];
    if (P.stripTrailingSlash) p = p.replace(/\/+$/, '');
    if (P.percentDecode) { try { p = decodeURIComponent(p); } catch { return null; } }
    return { kind: 'urn', v: `${m[1]}:${p}` };
  }
  return null;
}
const sameId = (a, b) => a && b && a.kind === b.kind && a.v === b.v;
const hexNorm = (s) => (typeof s === 'string' ? s.trim().toLowerCase().replace(/^0x/, '') : null);
const hexBytes = (s) => { const h = hexNorm(s); return h && /^[0-9a-f]*$/.test(h) && h.length % 2 === 0 ? Buffer.from(h, 'hex') : null; };

// ── per-kind criteria ─────────────────────────────────────────────────────────
const RECOGNIZED_PHASES = new Set(['funding', 'delivery', 'settlement']);
const RECOGNIZED_CLAIMS = new Set(['independent', 'none', 'issuer_attested']);

function seqBE8(n) { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; }
const ZERO32 = Buffer.alloc(32);

/** keccak256(artifact_digest || prev_digest || seq_uint64_be); null prev -> 32 zero bytes. */
function chainLink(artifact, prev, seq) {
  const a = hexBytes(artifact); if (!a) throw new Reject('continuity_reject', 'artifact_digest does not parse');
  const p = prev === null || prev === undefined ? ZERO32 : hexBytes(prev);
  if (!p) throw new Reject('continuity_reject', 'prev_digest does not parse');
  return kec(Buffer.concat([a, p, seqBE8(seq)]));
}

/**
 * Structural chain_set predicate. Returns the recomputed links in seq order.
 * Completeness = every seq 1..head.seq present exactly once. A second record at an
 * occupied seq rejects (n39) whatever the issuer attests; witness material beside the
 * set is permitted and is NOT load-bearing for completeness (p24/n34).
 */
function chainSet(input) {
  const headNode = get(input, 'head');
  const head = headNode ? toJS(headNode) : null;
  const seqNode = get(headNode, 'seq');
  if (!head || !seqNode) throw new Reject('completeness_reject', 'no head');
  // A sequence number is an integer token. `3.0` is not one (n38) — and this rejects
  // on completeness, not number domain: the head commits to no records we can close.
  if (seqNode.t !== 'n' || !/^-?(0|[1-9][0-9]*)$/.test(seqNode.tok)) {
    throw new Reject('completeness_reject', `head commits no records (seq "${seqNode.t === 'n' ? seqNode.tok : seqNode.t}" is not an integer token)`);
  }
  const hseq = Number(seqNode.tok);
  if (hseq < 1) throw new Reject('completeness_reject', `head commits no records (seq ${hseq} < 1)`);

  const recsNode = get(input, 'records');
  const recs = recsNode && recsNode.t === 'a' ? recsNode.v.map(toJS) : null;
  if (!recs) throw new Reject('completeness_reject', 'no records');

  const bySeq = new Map();
  for (const r of recs) {
    if (!Number.isInteger(r.seq)) throw new Reject('completeness_reject', 'record seq is not an integer');
    if (bySeq.has(r.seq)) throw new Reject('completeness_reject', `duplicate seq [${r.seq}] under committed head`);
    bySeq.set(r.seq, r);
  }
  for (let s = 1; s <= hseq; s++) {
    if (!bySeq.has(s)) throw new Reject('completeness_reject', `seq ${s} absent from a set the head closes at ${hseq}`);
  }
  if (bySeq.size !== hseq) throw new Reject('completeness_reject', `${bySeq.size} records under a head closing at ${hseq}`);

  // head.digest equals the final record's artifact digest
  const last = bySeq.get(hseq);
  if (hexNorm(head.digest) !== hexNorm(last.artifact_digest)) {
    throw new Reject('continuity_reject', 'head.digest is not the final record artifact digest');
  }
  // prev pointers chain raw artifact digests; genesis prev = null
  const links = [];
  for (let s = 1; s <= hseq; s++) {
    const r = bySeq.get(s);
    const expectPrev = s === 1 ? null : hexNorm(bySeq.get(s - 1).artifact_digest);
    const gotPrev = r.prev_digest === null || r.prev_digest === undefined ? null : hexNorm(r.prev_digest);
    if (expectPrev !== gotPrev) throw new Reject('continuity_reject', `seq ${s} prev_digest is not seq ${s - 1}'s artifact digest`);
    const link = chainLink(r.artifact_digest, r.prev_digest ?? null, s);
    // Where a record presents a link, it must recompute. n17's relabeled record carries
    // the link computed for its ORIGINAL position, which is how a renumbered omission
    // stays visible.
    if (r.link !== undefined && hexNorm(r.link) !== link) {
      throw new Reject('continuity_reject', `seq ${s} presented link does not recompute`);
    }
    links.push(link);
  }
  return { hseq, links, head };
}

/** acc_0 = keccak256(utf8('tersign-chain-commitment-v1')); acc_n = keccak256(acc_{n-1} || link_n) */
function chainCommitment(input) {
  const { hseq, links, head } = chainSet(input);
  let acc = kecUtf8('tersign-chain-commitment-v1');
  for (let s = 1; s <= hseq; s++) acc = kec(Buffer.concat([Buffer.from(acc, 'hex'), Buffer.from(links[s - 1], 'hex')]));
  if (hexNorm(head.acc) !== acc) {
    throw new Reject('continuity_reject', 'accumulator mismatch: head.acc does not commit to the presented prefix');
  }
  return true;
}

/**
 * An independence claim reaches exactly as far as the record's DERIVED commitments.
 * Position is the independence axis and is decided BEFORE scope (MANIFEST
 * commitment_derivation: "who delivered is not read by the derivation").
 */
function independence(input) {
  const claimedNode = get(input, 'claimed');
  const claimed = claimedNode ? toJS(claimedNode) : undefined;

  // Fail closed on the trigger itself. An exact-equality trigger reads any unfamiliar
  // claim — including a STRONGER one — as no claim at all, switching the check off
  // exactly where more was asserted.
  const claims = claimed === undefined ? [] : (Array.isArray(claimed) ? claimed : [claimed]);
  for (const c of claims) {
    if (typeof c !== 'string' || !RECOGNIZED_CLAIMS.has(c)) {
      throw new Reject('independence_reject', `unrecognized claim ${JSON.stringify(claimed)}: not interpretable by this verifier`);
    }
  }
  const assertsIndependence = claims.includes('independent');

  const partiesNode = get(input, 'parties');
  const parties = (partiesNode && partiesNode.t === 'a' ? toJS(partiesNode) : []).map(normId);
  if (parties.some((p) => p === null)) throw new Reject('independence_reject', 'a party identifier does not parse after normalization');

  // A declared commitment scope is itself a rejectable input, whatever it holds —
  // enforced on the KEY's presence, so an explicit null rejects identically (n23).
  // Otherwise a record asserts the very scope the commitment-scope rule bounds.
  const declared = hasKey(input, 'record_commits');

  if (!assertsIndependence) {
    // Silence is a valid state (p9, p11, p22). A declared scope with no claim over it
    // is still the presence defect (n24 asserts independence, so it lands above).
    return true;
  }

  // ── position: is any attestor outside the parties ──
  const attNode = get(input, 'attestations');
  if (!attNode || attNode.t !== 'a') throw new Reject('independence_reject', 'independence claimed with no attestations');
  const atts = attNode.v;
  if (!atts.length) throw new Reject('independence_reject', 'independence claimed with no attestations');
  let outside = 0;
  for (const a of atts) {
    if (a.t !== 'o') throw new Reject('independence_reject', 'attestation is not an object');
    const by = normId(toJS(get(a, 'by')));
    if (!by) throw new Reject('independence_reject', 'attestor identifier does not parse after normalization');
    if (!parties.some((p) => sameId(p, by))) outside++;
  }
  if (outside === 0) throw new Reject('independence_reject', 'attested only by parties to the transaction');

  if (declared) {
    throw new Reject('independence_reject', 'record_commits is declared beside a derivable result; commitments are derived, never declared');
  }

  // ── scope: covers must be inside the DERIVED commitment set ──
  if (!hasKey(input, 'covers')) return true;          // unscoped claim, position settled it
  const covers = toJS(get(input, 'covers'));
  if (!Array.isArray(covers)) throw new Reject('independence_reject', 'covers is not a list');

  const sr = get(input, 'settlement_result');
  const srj = sr ? toJS(sr) : null;
  const hasDeliverable = hasKey(input, 'deliverable_bytes') || hasKey(input, 'deliverable_digest');
  const derivableFieldsPresent = !!sr || hasDeliverable;
  if (!derivableFieldsPresent) {
    throw new Reject('independence_reject', 'no evaluable commitments: a scoped claim over a record presenting no derivable fields is unevaluable');
  }
  const derived = new Set();
  if (srj && srj.success === true && typeof srj.transaction === 'string' && srj.transaction !== '') derived.add('settlement');
  if (srj && typeof srj.network === 'string' && srj.network !== '') derived.add('network');
  if (hasDeliverable) {
    const bytes = toJS(get(input, 'deliverable_bytes'));
    const dig = toJS(get(input, 'deliverable_digest'));
    if (typeof bytes === 'string' && typeof dig === 'string' && kecUtf8(bytes) === hexNorm(dig)) derived.add('delivery');
  }
  if (derived.size === 0) {
    throw new Reject('independence_reject', 'record commits to nothing derivable; the scoped claim overreaches');
  }
  for (const c of covers) {
    if (!derived.has(c)) {
      throw new Reject('independence_reject', `claim covers "${c}", which is outside the record's derived commitments {${[...derived].join(',')}}`);
    }
  }
  return true;
}

/** boundary_binding: the boundary must bind the prefix AND the position it sits at. */
function boundary(input) {
  const prefixNode = get(input, 'prefix');
  const evNode = get(input, 'boundary_event');
  if (!prefixNode || !evNode) throw new Reject('boundary_reject', 'prefix or boundary_event absent');
  const prefix = toJS(prefixNode);
  const ev = toJS(evNode);

  // The prefix digest is taken under the suite IN FORCE when the boundary was written.
  // n29 presents the successor suite's digest of the same bytes: an engine that
  // re-hashes history agrees with it, which is exactly why this discriminates.
  const want = contentAddress(prefixNode);
  if (hexNorm(ev.prefixDigest) !== want) {
    throw new Reject('boundary_reject', `boundary names prefix ${want}, presented prefix digests to ${hexNorm(ev.prefixDigest)}`);
  }
  // Prefix-only binding is a fabricated boundary: without a position it can be
  // replayed at any point in the sequence (n25).
  if (!Number.isInteger(ev.position)) throw new Reject('boundary_reject', 'boundary binds no position');
  if (ev.position !== prefix.length) throw new Reject('boundary_reject', `boundary position ${ev.position} is not the prefix length ${prefix.length}`);
  // Coverage claimed past what was attested is a downgrade (n26).
  const covered = hasKey(input, 'covered_through') ? toJS(get(input, 'covered_through')) : null;
  if (covered !== null) {
    if (!Number.isInteger(ev.attestedPrefixLength)) throw new Reject('boundary_reject', 'coverage claimed with no attested prefix length');
    if (ev.attestedPrefixLength < covered) {
      throw new Reject('boundary_reject', `coverage through ${covered} claimed over an attestation of length ${ev.attestedPrefixLength}`);
    }
  }
  return true;
}

function evaluate(kind, input) {
  switch (kind) {
    case 'digest_recompute': {
      const got = contentAddress(get(input, 'payload'));
      const want = hexNorm(toJS(get(input, 'expected_digest')));
      if (got !== want) throw new Reject('recompute_mismatch', `recomputed 0x${got}, presented 0x${want}`);
      return true;
    }
    case 'canonical_bytes': {
      // p25/n35 present the payload as raw TEXT precisely so the number token survives.
      const textNode = get(input, 'payload_text');
      const node = textNode ? parseJson(toJS(textNode)) : get(input, 'payload');
      const got = jcs(node);
      const claimed = toJS(get(input, 'claimed_canonical'));
      if (got !== claimed) throw new Reject('canonicalization_reject', 'claimed canonical bytes are not the canonical form');
      return true;
    }
    case 'chain_link': {
      const j = toJS(input);
      const got = chainLink(j.artifact_digest, j.prev_digest ?? null, j.seq);
      if (got !== hexNorm(j.expected_link)) throw new Reject('continuity_reject', `link recomputes to 0x${got}, presented 0x${hexNorm(j.expected_link)}`);
      return true;
    }
    case 'chain_set': chainSet(input); return true;
    case 'chain_commitment': chainCommitment(input); return true;
    case 'anchor_relation': {
      const sub = hexBytes(toJS(get(input, 'subject_digest')));
      if (!sub) throw new Reject('existence_reject', 'subject_digest does not parse');
      const got = sha256(sub);
      const want = hexNorm(toJS(get(input, 'anchored_digest')));
      if (got !== want) throw new Reject('existence_reject', `anchored digest is sha256 of a different subject (recomputed ${got})`);
      return true;
    }
    case 'offer_binding': {
      const receipt = toJS(get(input, 'receipt')) || {};
      // A receipt committing to no offer digest cannot bind terms, and fails closed.
      if (typeof receipt.offerDigest !== 'string') throw new Reject('binding_reject', 'receipt commits to no offer digest');
      const got = contentAddress(get(input, 'offer'));
      if (got !== hexNorm(receipt.offerDigest)) throw new Reject('binding_reject', `presented offer digests to 0x${got}, receipt commits to 0x${hexNorm(receipt.offerDigest)}`);
      return true;
    }
    case 'decision_evidence_binding': {
      const rec = toJS(get(input, 'record')) || {};
      if (typeof rec.decisionEvidenceDigest !== 'string') throw new Reject('binding_reject', 'record binds no decision evidence');
      const got = contentAddress(get(input, 'decision_evidence'));
      if (got !== hexNorm(rec.decisionEvidenceDigest)) throw new Reject('binding_reject', `presented reduction digests to 0x${got}, record commits to 0x${hexNorm(rec.decisionEvidenceDigest)}`);
      return true;
    }
    case 'phase_claim': {
      const rec = toJS(get(input, 'record')) || {};
      const as = toJS(get(input, 'presented_as'));
      // Fail closed on an unrecognized phase (n18): a phase this verifier cannot
      // interpret is not evidence that the phases agree.
      if (!RECOGNIZED_PHASES.has(rec.economic_phase)) throw new Reject('phase_reject', `unrecognized economic phase ${JSON.stringify(rec.economic_phase)}`);
      if (!RECOGNIZED_PHASES.has(as)) throw new Reject('phase_reject', `unrecognized presented phase ${JSON.stringify(as)}`);
      if (rec.economic_phase !== as) throw new Reject('phase_reject', `record evidences ${rec.economic_phase}, presented as ${as}`);
      return true;
    }
    case 'independence_claim': independence(input); return true;
    case 'boundary_binding': boundary(input); return true;
    // An unimplemented criterion must NOT return a reject. First run of this file
    // had boundary_binding written but never wired into this switch, and the
    // `unknown_kind` reject AGREED with the expected verdict on 3 of the 5 boundary
    // vectors — a criterion that did not exist scored as a pass. Only comparing the
    // reject REASON as well as the verdict exposed it. Hence `error`, not a Reject.
    default: { const e = new Error(`no criterion implemented for kind ${kind}`); e.unimplemented = true; throw e; }
  }
}

// ── runner ────────────────────────────────────────────────────────────────────
function run(corpusDir, policy) {
  // Policy is applied for the duration of the run and restored, so a matrix run
  // cannot leak one reading into the next.
  const saved = { ...POLICY };
  if (policy) Object.assign(POLICY, policy);
  try { return runInner(corpusDir); } finally { Object.assign(POLICY, saved); }
}
function runInner(corpusDir) {
  const manifest = JSON.parse(fs.readFileSync(path.join(corpusDir, 'MANIFEST.json'), 'utf8'));
  const rows = [];
  for (const entry of manifest.vectors) {
    const raw = fs.readFileSync(path.join(corpusDir, 'vectors', entry.file), 'utf8');
    // Parsed with OUR parser, so number tokens and key order survive to the criterion.
    const vecNode = parseJson(raw);
    const kind = toJS(get(vecNode, 'kind'));
    // Expectations are read AFTER the criterion runs and are optional, so the suite
    // can be run blind (expect/reason deleted from the bytes). The first version of
    // this runner crashed without them — which would have made the independence claim
    // unfalsifiable: a verifier that cannot run without the answer key has not shown
    // it is not using it. Control A in REPRODUCTION.md is that run.
    const expect = hasKey(vecNode, 'expect') ? toJS(get(vecNode, 'expect')) : null;
    const expectReason = hasKey(vecNode, 'reason') ? toJS(get(vecNode, 'reason')) : null;
    const input = get(vecNode, 'input');

    let verdict, reason = null, detail = null;
    try { evaluate(kind, input); verdict = 'valid'; }
    catch (e) {
      if (e instanceof Reject) { verdict = 'reject'; reason = e.reason; detail = e.message; }
      // An exception that is not a verdict IS the failure this corpus names: a verifier
      // that raises produces no verdict at all. Recorded as `error`, never as a reject.
      else { verdict = 'error'; reason = 'instrument_failure'; detail = `${e.name}: ${e.message}`; }
    }
    const blind = expect === null;
    const verdictAgrees = blind ? null : verdict === expect;
    const reasonAgrees = blind ? null : (expect === 'valid' ? true : reason === expectReason);
    rows.push({
      file: entry.file, kind, expect, expect_reason: expectReason,
      got: verdict, got_reason: reason, detail,
      agrees: blind ? null : (verdictAgrees && reasonAgrees),
      verdict_agrees: verdictAgrees, reason_agrees: reasonAgrees,
    });
  }
  return { suite: manifest.suite, version: manifest.version, rows };
}

// ── self-test: our primitives against known answers, no corpus ───────────────
function selfTest() {
  let p = 0, f = 0;
  const ok = (n, c) => { if (c) p++; else { f++; console.log(`  FAIL ${n}`); } };

  // RFC 8785 §3.2.3 orders by UTF-16 code unit, NOT numerically. This is the n2 trap.
  ok('integer-like keys sort by code unit', jcs(parseJson('{"10":1,"2":2,"1":3}')) === '{"1":3,"10":1,"2":2}');
  // A supplementary-plane key sorts FIRST by code unit and LAST by code point (n12).
  // The inversion only shows against a HIGH BMP key: U+1F600's lead surrogate is
  // 0xD83D, which is below U+FFFD but its code point 0x1F600 is above it. Against a
  // low key like "z" (0x7A) both orderings agree, so "z" cannot witness the bug —
  // the first version of this test used "z" and passed vacuously in both directions.
  const supp = jcs(parseJson('{"\\ud83d\\ude00":1,"\\ufffd":2}'));
  ok('supplementary-plane key sorts first by code unit', supp.indexOf('\u{1f600}') < supp.indexOf('�'));
  ok('...and last by code point, so the two orders differ',
    [...'\u{1f600}�'].sort((a, b) => a.codePointAt(0) - b.codePointAt(0))[0] === '�');
  ok('nested objects sort recursively', jcs(parseJson('{"b":{"d":1,"c":2},"a":3}')) === '{"a":3,"b":{"c":2,"d":1}}');
  ok('arrays keep order', jcs(parseJson('[3,1,2]')) === '[3,1,2]');

  // Number TOKEN class, the reason JSON.parse cannot be used here.
  let threw = null;
  try { jcs(parseJson('{"a":2.0}')); } catch (e) { threw = e; }
  ok('integer-valued float token rejects', threw && threw.reason === 'number_domain_reject');
  threw = null;
  try { jcs(parseJson('{"a":1e2}')); } catch (e) { threw = e; }
  ok('exponent form rejects', threw && threw.reason === 'number_domain_reject');
  threw = null;
  try { jcs(parseJson('{"a":9007199254740993}')); } catch (e) { threw = e; }
  ok('integer past 2^53-1 rejects', threw && threw.reason === 'number_domain_reject');
  ok('2^53-1 boundary is accepted', jcs(parseJson('{"a":9007199254740991}')) === '{"a":9007199254740991}');
  ok('plain integer survives', jcs(parseJson('{"a":2}')) === '{"a":2}');

  threw = null;
  try { parseJson('{"a":1,"a":2}'); } catch (e) { threw = e; }
  ok('duplicate object name rejects', threw && threw.reason === 'canonicalization_reject');

  // JSON.parse would collapse both of these to the same thing; ours does not.
  ok('token is preserved distinctly from its value', parseJson('2.0').tok === '2.0' && parseJson('2').tok === '2');
  ok('key insertion order is preserved', parseJson('{"10":1,"2":2}').e.map((x) => x[0]).join() === '10,2');

  // Primitives.
  ok('keccak256 known answer', kecUtf8('') === 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470');
  ok('sha256 known answer', sha256(Buffer.from('abc')) === 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  ok('seq 1 big-endian uint64', seqBE8(1).toString('hex') === '0000000000000001');
  ok('genesis prev substitutes 32 zero bytes', ZERO32.length === 32 && ZERO32.every((b) => b === 0));

  // Identifier normalization (n13/n14/n31).
  ok('address normalizes case and whitespace', sameId(normId(' 0xAbC0000000000000000000000000000000000001 '), normId('0xabc0000000000000000000000000000000000001')));
  ok('unparseable attestor fails closed', normId('0x9d38BA84730271eb27Ac9bD4​Bd2620c08dB4FDa6') === null);
  ok('urn trailing slash is the same identifier', sameId(normId('org:caldera-robotics/'), normId('org:caldera-robotics')));
  ok('urn path case is significant', !sameId(normId('org:Caldera'), normId('org:caldera')));
  ok('urn with inner slash is kept', normId('org:trustline-custody/eu-west').v === 'org:trustline-custody/eu-west');
  ok('two colons do not parse', normId('a:b:c') === null);

  ok('present-and-null is distinguishable from absent', hasKey(parseJson('{"record_commits":null}'), 'record_commits') === true
    && hasKey(parseJson('{"x":1}'), 'record_commits') === false);

  console.log(`\ntersign-reproduction self-test: ${p} passed, ${f} failed`);
  return f === 0;
}

/**
 * CRYPTO-PROFILE self-test. The corpus carries no counter-signature material over the
 * links (measured: see REPRODUCTION.md), so this half cannot be exercised by the
 * corpus and is proven here against keys generated in-process instead.
 */
async function cryptoSelfTest() {
  let p = 0, f = 0;
  const ok = (n, c) => { if (c) p++; else { f++; console.log(`  FAIL ${n}`); } };
  if (!secp || !secpAccounts) { console.log("  viem unavailable — crypto profile untested"); return false; }

  // EIP-191 known answer, independent of our own signing path.
  ok('eip191 known answer', eip191Digest(Buffer.from('hello world', 'utf8'))
    === 'd9eba16ed0ecae432b71fe008c98cc872bb4cc214d3220a36f365326cf807d68');

  // The canonical PUBLISHED Ethereum documentation test key (address
  // 0x2c7536E3605D9C16a7a3D7b1898e529396a65c23). Holds nothing, belongs to nobody,
  // and is in this file so the crypto tests are reproducible by a reader. No StillOS
  // key material appears anywhere in this repository.
  const pk = '0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318';
  const acct = secpAccounts.privateKeyToAccount(pk);
  const signer = acct.address.toLowerCase();

  // Sign a real chain set's links, then verify recovery against the expected signer.
  const setNode = parseJson(JSON.stringify({
    head: { seq: 2, digest: '0x' + 'b'.repeat(64) },
    records: [
      { seq: 1, artifact_digest: '0x' + 'a'.repeat(64), prev_digest: null },
      { seq: 2, artifact_digest: '0x' + 'b'.repeat(64), prev_digest: '0x' + 'a'.repeat(64) },
    ],
  }));
  const { links } = chainSet(setNode);
  const sigs = {};
  for (let i = 0; i < links.length; i++) {
    sigs[i + 1] = await acct.signMessage({ message: { raw: '0x' + links[i] } });
  }
  const good = await verifyLinkCounterSignatures(setNode, signer, sigs);
  ok('every link counter-signature recovers to the expected signer', good.links_verified === 2 && good.signer === signer);

  // The forging case the profile exists for: structurally perfect, wrong signer.
  const other = secpAccounts.privateKeyToAccount('0x' + '11'.repeat(32));
  const forged = { 1: sigs[1], 2: await other.signMessage({ message: { raw: '0x' + links[1] } }) };
  let e = null;
  try { await verifyLinkCounterSignatures(setNode, signer, forged); } catch (x) { e = x; }
  ok('a link signed by another key rejects', e && e.reason === 'crypto_reject' && /recovers to/.test(e.message));

  // An unsigned link is not a pass. This is the default-open hole: "no signature to
  // check" must never read as "nothing wrong".
  e = null;
  try { await verifyLinkCounterSignatures(setNode, signer, { 1: sigs[1] }); } catch (x) { e = x; }
  ok('a link with NO counter-signature rejects', e && e.reason === 'crypto_reject' && /carries no counter-signature/.test(e.message));
  e = null;
  try { await verifyLinkCounterSignatures(setNode, signer, {}); } catch (x) { e = x; }
  ok('an entirely unsigned set rejects', e && e.reason === 'crypto_reject');

  // Recovery without an expected signer is not verification — there is no API for it.
  e = null;
  try { await verifyLinkCounterSignatures(setNode, 'not-an-address', sigs); } catch (x) { e = x; }
  ok('no expected signer means no verdict', e && /expected signer does not parse/.test(e.message));

  // A valid signature over the WRONG link fails: the signature must bind the link.
  const swapped = { 1: sigs[2], 2: sigs[1] };
  e = null;
  try { await verifyLinkCounterSignatures(setNode, signer, swapped); } catch (x) { e = x; }
  ok('a signature over a different link rejects', e && e.reason === 'crypto_reject');

  // Structural failure must halt before the crypto check, not after.
  const gappy = parseJson(JSON.stringify({
    head: { seq: 3, digest: '0x' + 'b'.repeat(64) },
    records: [{ seq: 1, artifact_digest: '0x' + 'a'.repeat(64), prev_digest: null }],
  }));
  e = null;
  try { await verifyLinkCounterSignatures(gappy, signer, sigs); } catch (x) { e = x; }
  ok('structural predicate runs first', e && e.reason === 'completeness_reject');

  console.log(`\ncrypto-profile self-test: ${p} passed, ${f} failed`);
  return f === 0;
}

/** Run the corpus under both readings of each undecided normalization call. */
function policyMatrix(corpusDir) {
  const sig = (rows) => new Map(rows.map((r) => [r.file, `${r.got}/${r.got_reason || '-'}`]));
  const combos = [
    { stripTrailingSlash: true, percentDecode: false },   // the default, and what REPRODUCTION.md reports
    { stripTrailingSlash: false, percentDecode: false },
    { stripTrailingSlash: true, percentDecode: true },
    { stripTrailingSlash: false, percentDecode: true },
  ];
  const base = sig(run(corpusDir, combos[0]).rows);
  const out = [];
  for (const c of combos) {
    const rows = run(corpusDir, c).rows;
    const agree = rows.filter((r) => r.agrees).length;
    const moved = [...sig(rows)].filter(([f, v]) => base.get(f) !== v).map(([f]) => f);
    out.push({ policy: c, vectors: rows.length, agree, moved });
  }
  return out;
}

module.exports = {
  parseJson, jcs, contentAddress, normId, evaluate, run, selfTest,
  eip191Digest, recoverPersonalSign, verifyLinkCounterSignatures, cryptoSelfTest,
  policyMatrix, POLICY, chainSet,
};

if (require.main === module) {
  const argv = process.argv.slice(2);
  if (argv.includes('--self-test')) {
    const structural = selfTest();
    cryptoSelfTest().then((c) => process.exit(structural && c ? 0 : 1));
    return;
  }
  const dir = argv.find((a) => !a.startsWith('--'));
  if (dir && argv.includes('--policy-matrix')) {
    console.log('\n◆ POLICY MATRIX — the two normalization calls the spec does not fix\n');
    for (const r of policyMatrix(dir)) {
      const label = `stripTrailingSlash=${r.policy.stripTrailingSlash} percentDecode=${r.policy.percentDecode}`;
      console.log(`  ${label.padEnd(52)} agree ${r.agree}/${r.vectors}   moved-vs-default ${r.moved.length}${r.moved.length ? ': ' + r.moved.map((f) => f.replace('.json', '')).join(', ') : ''}`);
    }
    process.exit(0);
  }
  if (!dir) { console.log('usage: node tersign-reproduction.cjs <corpus-dir> [--json]'); process.exit(2); }
  const r = run(dir);
  if (argv.includes('--json')) { console.log(JSON.stringify(r, null, 2)); process.exit(0); }

  const dis = r.rows.filter((x) => !x.agrees);
  for (const x of r.rows) {
    const mark = x.agrees ? 'AGREE ' : '  DIFF';
    console.log(`  [${mark}] ${x.file.replace('.json', '').padEnd(44)} expect ${x.expect}/${x.expect_reason || '-'}  got ${x.got}/${x.got_reason || '-'}`);
  }
  console.log(`\n${r.suite} v${r.version}`);
  console.log(`  vectors            : ${r.rows.length}`);
  console.log(`  independent AGREE  : ${r.rows.length - dis.length}`);
  console.log(`  DISAGREE           : ${dis.length}`);
  if (dis.length) {
    console.log('\n  disagreements:');
    for (const x of dis) {
      console.log(`    ${x.file}`);
      console.log(`        kind     ${x.kind}`);
      console.log(`        expected ${x.expect} / ${x.expect_reason || '-'}`);
      console.log(`        ours     ${x.got} / ${x.got_reason || '-'}`);
      console.log(`        detail   ${x.detail}`);
    }
  }
  process.exit(0);
}

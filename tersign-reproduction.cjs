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


/**
 * MUTANTS — each is a PLAUSIBLE MISREADING of the suite's own normative text, not a
 * random code edit. Running the corpus against each asks the only question a clean
 * score cannot: would this corpus have caught a wrong reading? A mutant that survives
 * names a rule the suite states but does not bind.
 */
const MUTANTS = {
  jcs_sort_by_codepoint: 'sorts member names by code POINT instead of UTF-16 code unit (RFC 8785 3.2.3)',
  allow_duplicate_names: 'lets a duplicate object name through as last-wins',
  number_allow_integral_float: 'accepts 2.0 as the integer 2 in the digest domain',
  number_no_ijson_bound: 'drops the I-JSON integer range check',
  surrogate_values_only: 'checks unpaired surrogates in values but not in member names',
  surrogate_after_numbers: 'decides number tokens before shape, so n92 rejects on the number domain',
  seq_value_not_token: 'checks seq as a parsed value rather than a token, so 1e2 passes',
  seq_no_upper_bound: 'drops the 2^53-1 upper bound on seq',
  id_trim_unicode_ws: 'uses String.trim(), which also strips U+FEFF',
  id_no_percent_decode: 'does not percent-decode unreserved triplets',
  id_no_trailing_strip: 'does not strip trailing / . and #',
  id_case_sensitive: 'compares identifiers without lowercasing',
  id_addr_no_prefix_fold: 'folds 0x-address digits but not the 0x/0X prefix',
  id_no_caip10_equiv: 'does not treat a scheme-qualified final 0x component as the same address',
  genesis_prev_any: 'accepts any prev_digest for a genesis link instead of 32 zero bytes',
};
let MUT = process.env.TERSIGN_MUT || null;
const mu = (n) => MUT === n;

/** A reject with a pinned reason code from the suite's closed set. */
class Reject extends Error {
  constructor(reason, detail) { super(detail || reason); this.reason = reason; }
}

// ── token-preserving JSON parser ──────────────────────────────────────────────
// Node shapes: {t:'o',e:[[k,node]]} {t:'a',v:[node]} {t:'s',v} {t:'n',tok} {t:'b',v} {t:'z'}
/**
 * MANIFEST.canonicalization: a `payload_text` that is not a string holding JSON text
 * rejects as canonicalization_reject (n43/n44) — this verifier used to call .slice on
 * it and throw a TypeError, which is not a verdict.
 *
 * And: "its shape, an unpaired surrogate included, is decided before its number
 * tokens (n92)". An unpaired UTF-16 surrogate is not encodable as UTF-8, so the text
 * has no canonical bytes at all; that decision precedes the number-token domain, so
 * a text carrying both a lone surrogate and `2.0` rejects on canonicalization.
 */
function hasLoneSurrogate(s) {
  for (let k = 0; k < s.length; k++) {
    const c = s.charCodeAt(k);
    if (c >= 0xd800 && c <= 0xdbff) {           // high surrogate: needs a low after it
      const n = k + 1 < s.length ? s.charCodeAt(k + 1) : 0;
      if (!(n >= 0xdc00 && n <= 0xdfff)) return true;
      k++;
    } else if (c >= 0xdc00 && c <= 0xdfff) return true; // low surrogate with no high
  }
  return false;
}

function parseJson(text) {
  if (typeof text !== 'string') throw new Reject('canonicalization_reject', 'payload_text is not a string holding JSON text');
  // ⚠️ DO NOT scan the RAW text for unpaired surrogates. A pair written with one half
  // raw and the other escaped ("\ud842" + a raw U+DFB7) is unpaired in the raw text
  // and a VALID PAIR after unescaping. A raw-text scan rejects it wrongly. The corpus
  // does not catch this: its half-raw vectors (n41/n42/n93) all REPEAT a name, so they
  // reject on the duplicate first and mask the defect — and MANIFEST.canonicalization
  // says in as many words that "no vector pins whether a pair written half raw accepts
  // where it repeats no name". This verifier scored 162/162 with the bug in it.
  // The surrogate decision belongs on the PARSED tree, in canonicalBytes().
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
      if (!mu('allow_duplicate_names') && seen.has(k)) throw new Reject('canonicalization_reject', `duplicate object name ${JSON.stringify(k)}`);
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

/**
 * Canonical bytes of a payload under test.
 *
 * "its shape, an unpaired surrogate included, is decided BEFORE its number tokens
 * (n92)". n92 writes the surrogate as a `\udfb7` ESCAPE, so it does not exist until
 * the string is unescaped and a raw-text scan cannot see it — the tree is swept
 * first, then serialized, so a payload carrying both a lone surrogate and `2.0`
 * rejects on canonicalization rather than on the number domain.
 *
 * ⚠️ This is deliberately NOT done inside parseJson: that same parser loads the
 * vector FILES, several of which legitimately carry escaped lone surrogates as test
 * data. Sweeping at parse time rejected the envelope and killed the whole run.
 */
function canonicalBytes(node) {
  if (mu('surrogate_after_numbers')) { const r = jcs(node); assertNoLoneSurrogate(node); return r; }
  assertNoLoneSurrogate(node);
  return jcs(node);
}

/** Depth-first sweep for an unpaired surrogate in any string value or member name. */
function assertNoLoneSurrogate(n) {
  if (!n || typeof n !== 'object') return;
  switch (n.t) {
    case 's':
      if (hasLoneSurrogate(n.v)) throw new Reject('canonicalization_reject', 'string value carries an unpaired surrogate');
      return;
    case 'a': n.v.forEach(assertNoLoneSurrogate); return;
    case 'o':
      for (const [k, v] of n.e) {
        if (!mu('surrogate_values_only') && hasLoneSurrogate(k)) throw new Reject('canonicalization_reject', 'member name carries an unpaired surrogate');
        assertNoLoneSurrogate(v);
      }
      return;
    default:
  }
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
    case 's':
      // An unpaired surrogate has no UTF-8 encoding, so the value has no canonical
      // bytes. JSON.stringify would happily emit a \udXXX escape and hide that.
      if (hasLoneSurrogate(n.v)) throw new Reject('canonicalization_reject', 'string value carries an unpaired surrogate');
      return JSON.stringify(n.v);
    case 'n': {
      const intRe = mu('number_allow_integral_float') ? /^-?(0|[1-9][0-9]*)(\.0+)?$/ : /^-?(0|[1-9][0-9]*)$/;
      if (!intRe.test(n.tok)) {
        throw new Reject('number_domain_reject', `non-integer JSON number token "${n.tok}" in the digest domain`);
      }
      const v = Number(n.tok);
      if (!mu('number_no_ijson_bound') && (!Number.isSafeInteger(v) || Math.abs(v) > MAX_SAFE)) {
        throw new Reject('number_domain_reject', `integer ${n.tok} outside I-JSON range`);
      }
      return String(v);
    }
    case 'a': return '[' + n.v.map(jcs).join(',') + ']';
    case 'o': {
      // §3.2.3: sort by UTF-16 code units. JS string relational operators are exactly
      // code-unit order, so this is the standard ordering, not a coincidence of locale.
      const e = n.e.slice().sort(mu('jcs_sort_by_codepoint')
        ? (x, y) => ([...x[0]].map(c=>c.codePointAt(0)) < [...y[0]].map(c=>c.codePointAt(0)) ? -1 : 1)
        : (x, y) => (x[0] < y[0] ? -1 : x[0] > y[0] ? 1 : 0));
      return '{' + e.map(([k, v]) => {
        if (!mu('surrogate_values_only') && hasLoneSurrogate(k)) throw new Reject('canonicalization_reject', 'member name carries an unpaired surrogate');
        return JSON.stringify(k) + ':' + jcs(v);
      }).join(',') + '}';
    }
    default: throw new Reject('canonicalization_reject', `unknown node ${n.t}`);
  }
}
const contentAddress = (node) => kecUtf8(canonicalBytes(node));   // MANIFEST content_address

/**
 * A binding criterion recomputes the commitment over a PRESENTED object. If that
 * object has no canonical bytes at all (an unpaired surrogate, n94/n95/n96), the
 * commitment cannot be recomputed and the binding is unverifiable — which is that
 * criterion's own rejection, not a canonicalization verdict about the record.
 */
function boundAddress(node, reason) {
  try { return contentAddress(node); }
  catch (e) {
    if (e instanceof Reject && e.reason === 'canonicalization_reject') throw new Reject(reason, `presented object has no canonical bytes: ${e.detail || e.message}`);
    throw e;
  }
}

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
// MANIFEST.identifier_normalization rule (1): exactly this White_Space set is
// stripped, "and no others" — so U+FEFF (a format character, n52) and U+001C (a
// control character without the property, n53) are NOT stripped and do not parse.
// String.prototype.trim() strips U+FEFF, which is why it cannot be used here.
const WS_CLASS = '\\u0009-\\u000D\\u0020\\u0085\\u00A0\\u1680\\u2000-\\u200A\\u2028\\u2029\\u202F\\u205F\\u3000';
const WS_RE = new RegExp(`^[${WS_CLASS}]+|[${WS_CLASS}]+$`, 'g');
const wsStrip = (s) => s.replace(WS_RE, '');
const ADDR_RE = /^0[xX][0-9a-fA-F]{40}$/;
const UNRESERVED = /^[A-Za-z0-9\-._~]$/;

/** One left-to-right pass, never repeated (RFC 3986 §6.2.2.2, §2.4). */
function decodeUnreservedOnce(p) {
  let out = '';
  for (let k = 0; k < p.length; k++) {
    if (p[k] === '%' && k + 2 < p.length && /^[0-9a-fA-F]{2}$/.test(p.slice(k + 1, k + 3))) {
      const ch = String.fromCharCode(parseInt(p.slice(k + 1, k + 3), 16));
      if (UNRESERVED.test(ch)) { out += ch; k += 2; continue; }
    }
    out += p[k];
  }
  return out;
}

/**
 * MANIFEST.identifier_normalization, rules (1)-(4). Returns null for "does not
 * parse", which fails the claim closed — a non-parsing identifier is never counted
 * outside the parties.
 */
function normId(raw) {
  if (typeof raw !== 'string') return null;
  const s = mu('id_trim_unicode_ws') ? raw.trim() : wsStrip(raw);
  // (2) a 0x-address compares lowercased, PREFIX INCLUDED, so 0X with upper-case
  // digits and the EIP-55 checksum form are one address (n106/p56).
  if (ADDR_RE.test(s)) return { kind: 'addr', v: mu('id_addr_no_prefix_fold') ? s.slice(0,2) + s.slice(2).toLowerCase() : s.toLowerCase() };
  // (3) scheme-qualified ASCII: letter, then [A-Za-z0-9+.-], one colon, then one or
  // more printable non-space ASCII.
  const m = /^([A-Za-z][A-Za-z0-9+.\-]*):([\x21-\x7e]+)$/.exec(s);
  if (!m) return null;                                   // (4) anything else
  const scheme = m[1].toLowerCase();
  let p = mu('id_no_percent_decode') ? m[2] : decodeUnreservedOnce(m[2]);
  if (p.includes('%')) return null;                      // any % left -> does not parse
  if (p.includes('?')) return null;                      // a query component
  // a dot-segment in the path, from the colon to the first ? or #
  const pathPart = p.split('#')[0];
  if (pathPart.split('/').some((seg) => seg === '.' || seg === '..')) return null;
  if (!mu('id_case_sensitive')) p = p.toLowerCase();
  if (!mu('id_no_trailing_strip')) p = p.replace(/[/.#]+$/, '');                          // every trailing / . and #
  if (p.includes('#')) return null;                      // a fragment with content
  if (!p.length) return null;                            // non-empty path (n51)
  if (!/^[\x21-\x7e]+$/.test(p)) return null;
  return { kind: 'urn', v: `${scheme}:${p}`, tail: p.split(':').pop() };
}

/**
 * Rule (5): equal after normalization, OR both name the same 0x-address — where a
 * scheme-qualified identifier whose FINAL colon-separated component is a 0x-address
 * names that address, whatever the scheme (CAIP-10, did:pkh, did:ethr, acct:).
 */
const addrOf = (a) => {
  if (!a) return null;
  if (a.kind === 'addr') return a.v;
  if (mu('id_no_caip10_equiv')) return null;
  return a.tail && ADDR_RE.test(a.tail) ? a.tail.toLowerCase() : null;
};
const sameId = (a, b) => {
  if (!a || !b) return false;
  const x = addrOf(a), y = addrOf(b);
  if (x && y) return x === y;
  return a.kind === b.kind && a.v === b.v;
};
const hexNorm = (s) => (typeof s === 'string' ? s.trim().toLowerCase().replace(/^0x/, '') : null);
const hexBytes = (s) => { const h = hexNorm(s); return h && /^[0-9a-f]*$/.test(h) && h.length % 2 === 0 ? Buffer.from(h, 'hex') : null; };

// ── per-kind criteria ─────────────────────────────────────────────────────────
// v0.5.5 closed the economic-phase vocabulary at five words, each compared as an
// exact string (MANIFEST.phase_claim). `refund` and `reversal` were absent here
// because this verifier was written against v0.5.3, where p49/p50 did not exist.
const RECOGNIZED_PHASES = new Set(['funding', 'delivery', 'settlement', 'refund', 'reversal']);
const RECOGNIZED_CLAIMS = new Set(['independent', 'none', 'issuer_attested']);

/**
 * MANIFEST.chain_link pins `seq` as an integer TOKEN in [1, 2^53-1]. Enforced on the
 * parser's raw token node, never on the JS value: `1e2` and `100` are the same JS
 * number and different tokens, and only the token form is normative here.
 */
const IJSON_MAX = 9007199254740991; // 2^53-1 (p43 accepts this exact bound)
function assertSeqToken(node) {
  if (!node || node.t !== 'n') throw new Reject('continuity_reject', 'seq is not a JSON number token');
  if (!mu('seq_value_not_token') && !/^(0|[1-9][0-9]*)$/.test(node.tok)) throw new Reject('continuity_reject', `seq token ${JSON.stringify(node.tok)} is not an integer form`);
  if (mu('seq_value_not_token') && !Number.isInteger(Number(node.tok))) throw new Reject('continuity_reject', 'seq is not an integer');
  const v = Number(node.tok);
  if (v < 1) throw new Reject('continuity_reject', 'seq is below the lower bound of 1');
  if (!mu('seq_no_upper_bound') && v > IJSON_MAX) throw new Reject('continuity_reject', 'seq is past the I-JSON integer bound 2^53-1');
  return v;
}

function seqBE8(n) { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; }
const ZERO32 = Buffer.alloc(32);

/** keccak256(artifact_digest || prev_digest || seq_uint64_be); null prev -> 32 zero bytes. */
function chainLink(artifact, prev, seq) {
  const a = hexBytes(artifact); if (!a) throw new Reject('continuity_reject', 'artifact_digest does not parse');
  const p = prev === null || prev === undefined ? (mu('genesis_prev_any') ? Buffer.alloc(32, 1) : ZERO32) : hexBytes(prev);
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

  // head.digest is read HERE, in the completeness stage, not later with continuity.
  // MANIFEST.chain_set is explicit and names both vectors: "a head with no digest
  // (n165) or with a digest that does not parse (n169, 0x and 62 hex digits) rejects
  // with completeness_reject, NOT with continuity_reject." Our reader only looked at
  // head.digest when comparing it to the final record's artifact digest, so an
  // absent or malformed digest fell through to the continuity comparison and got
  // continuity_reject — the right verdict for the wrong reason.
  // The distinction is substantive: a head whose digest cannot be read is a set we
  // cannot close, which is a completeness failure. Continuity is about whether the
  // links between records hold, and it has not been reached yet.
  // 32-byte hex after the whitespace strip of identifier_normalization, lowercased.
  const hdigRaw = head.digest;
  const hdig = typeof hdigRaw === 'string' ? wsStrip(hdigRaw).toLowerCase().replace(/^0x/, '') : null;
  if (hdig === null || !/^[0-9a-f]{64}$/.test(hdig)) {
    throw new Reject('completeness_reject', `head digest ${JSON.stringify(hdigRaw)} does not parse as a 32-byte hex digest`);
  }

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
  const want = boundAddress(prefixNode, 'boundary_reject');
  if (hexNorm(ev.prefixDigest) !== want) {
    throw new Reject('boundary_reject', `boundary names prefix ${want}, presented prefix digests to ${hexNorm(ev.prefixDigest)}`);
  }
  // Prefix-only binding is a fabricated boundary: without a position it can be
  // replayed at any point in the sequence (n25).
  if (!Number.isInteger(ev.position)) throw new Reject('boundary_reject', 'boundary binds no position');
  if (ev.position !== prefix.length) throw new Reject('boundary_reject', `boundary position ${ev.position} is not the prefix length ${prefix.length}`);
  /* ── attestedPrefixLength and covered_through, rewritten 2026-10-28 ───────────
   * 9 of 284 vectors were accepting here and should reject, and every one of them
   * is this field. The defect was that we only looked at `attestedPrefixLength`
   * when `covered_through` was present and non-null — i.e. we treated it as an
   * input to the coverage comparison rather than as a field with its own validity.
   *
   * MANIFEST.boundary_binding: "when the member is PRESENT, WHATEVER ITS VALUE, it
   * must be an integer token from 0 to the number of entries in `prefix`,
   * inclusive, WHETHER OR NOT COVERAGE IS CLAIMED." So presence is the trigger, not
   * coverage, and the bound is checked unconditionally.
   *
   * ⚠️ "INTEGER TOKEN", which is why this reads NODES and not toJS(). n156 carries
   * the token `0.0`: numerically 0, inside the range, and `Number.isInteger(0)` is
   * true — a reader working from parsed numbers accepts it and cannot do otherwise.
   * The vector exists to catch exactly that reader. Same shape as n38's `3.0` head
   * seq in chain_set. This is the second time in this corpus that carrying the raw
   * token this far is the only thing that makes a vector visible.
   *
   * Vectors: n153 (one past, beside coverage), n155 (99), n159 (3 for a two-entry
   * prefix), n154 (-1), n156 (token 0.0), n157 (false), n158 (null), n170 (the
   * string "0"), n171 (covered_through null). Accepting twins that pin the
   * boundaries: p67 (absent), p63 (0, no coverage claimed), p18/p20/p64 (the
   * prefix's own length).
   */
  const intToken = (node) => {
    if (!node || node.t !== 'n') return null;                 // false, null, a string: not a token
    if (!/^-?(0|[1-9][0-9]*)$/.test(node.tok)) return null;   // `0.0`, `1e2`: not an integer token
    return Number(node.tok);
  };

  const aplPresent = hasKey(evNode, 'attestedPrefixLength');
  let apl = null;
  if (aplPresent) {
    apl = intToken(get(evNode, 'attestedPrefixLength'));
    if (apl === null) {
      throw new Reject('boundary_reject', 'attestedPrefixLength is present and is not an integer token');
    }
    if (apl < 0 || apl > prefix.length) {
      throw new Reject('boundary_reject', `attestedPrefixLength ${apl} is outside 0..${prefix.length} for the presented prefix`);
    }
  }

  // `covered_through`: may be absent; when PRESENT, whatever its value, it must be a
  // non-negative integer token (n171 carries null and rejects), the event must carry
  // `attestedPrefixLength` (n167 carries none and rejects), and coverage may not
  // exceed it (n26 over an empty attestation, n166 over one reaching 2).
  if (hasKey(input, 'covered_through')) {
    const covered = intToken(get(input, 'covered_through'));
    if (covered === null || covered < 0) {
      throw new Reject('boundary_reject', 'covered_through is present and is not a non-negative integer token');
    }
    if (!aplPresent) throw new Reject('boundary_reject', 'coverage claimed with no attested prefix length');
    if (apl < covered) {
      throw new Reject('boundary_reject', `coverage through ${covered} claimed over an attestation of length ${apl}`);
    }
  }
  return true;
}

/* ── COMPOSITION INDEPENDENCE (MANIFEST.composition_independence) ──────────────
 * Added 2026-10-28. This kind was added upstream after this reader was written, so
 * all 39 of its vectors were producing `error / instrument_failure` — no verdict at
 * all, which is the failure the corpus exists to catch.
 *
 * TWO RECORDS JOINED BY DIGEST: `findings` (a record of findings about a party's
 * work) and `decision` (the counterparty's decision on that work, committing to the
 * findings by `findings_digest`).
 *
 * ORDER IS NORMATIVE AND IT IS NOT THE ORDER I WOULD HAVE PICKED:
 *   1. THE JOIN IS DECIDED FIRST -> binding_reject.
 *   2. Then `claimed` is read exactly as independence_claim reads it.
 *   3. Under a claim, the findings are evaluated as an independence_claim record
 *      whose `attestations` are `findings_attestations` and whose `parties` are
 *      `parties` followed by `counterparty`.  -> independence_reject
 * Defined-member validation sits ahead of all three (see assertDefinedMembers).
 *
 * WHY THIS REUSES independence() ON A SYNTHETIC NODE rather than reimplementing it:
 * the manifest says the findings are evaluated *as an independence_claim record*.
 * Two copies of that logic would drift, and a second implementation that happened
 * to agree would prove nothing about the first. The substitution is only in which
 * members supply attestations and parties.
 *
 * ⚠️ THE DECISION IS NOT AN INDEPENDENT FINDING. Of the decision the criterion reads
 * ONLY `findings_digest`. `decision_attestations` and an attestation's `role` are
 * read by no criterion — so an attestor named only on the decision is never counted
 * toward independence, and whether `counterparty` names the decision's attestor is
 * not checked. Counting the decision's attestors here would be the exact confusion
 * the kind exists to catch: a party's own decision laundered into independence.
 *
 * ⚠️ wsStrip, NOT hexNorm, for the digest. `hexNorm` uses JS `.trim()`, whose
 * whitespace set includes U+FEFF; identifier_normalization strips only the Unicode
 * White_Space property characters and says U+FEFF explicitly does NOT parse. On a
 * digest the difference is an accept where the suite rejects.
 */
function compositionIndependence(input) {
  // ── 1. the join, decided first ──
  const findingsNode = get(input, 'findings');
  const decisionNode = get(input, 'decision');
  if (!findingsNode || findingsNode.t !== 'o') throw new Reject('binding_reject', 'findings is not a JSON object');
  if (!decisionNode || decisionNode.t !== 'o') throw new Reject('binding_reject', 'decision is not a JSON object');

  const fdNode = get(decisionNode, 'findings_digest');
  const fdRaw = fdNode === undefined ? undefined : toJS(fdNode);
  if (typeof fdRaw !== 'string') throw new Reject('binding_reject', 'decision carries no findings_digest string');
  const fd = wsStrip(fdRaw).toLowerCase();
  if (!/^0x[0-9a-f]{64}$/.test(fd)) {
    throw new Reject('binding_reject', `findings_digest ${JSON.stringify(fdRaw)} is not 0x followed by 64 hex digits`);
  }
  const want = `0x${boundAddress(findingsNode, 'binding_reject')}`;
  if (fd !== want) throw new Reject('binding_reject', `decision commits to ${fd}, findings canonicalize to ${want}`);

  // ── 2/3. claimed, then the findings as an independence_claim record ──
  const partiesNode = get(input, 'parties');
  if (!partiesNode || partiesNode.t !== 'a' || !partiesNode.v.length) {
    throw new Reject('independence_reject', 'parties is not a non-empty array');
  }
  const cpNode = get(input, 'counterparty');
  // "whose `parties` are `parties` followed by `counterparty`" — the parties the
  // record declares AND the counterparty are all parties to the transaction, so an
  // attestor naming the counterparty is inside, not outside.
  const synthParties = { t: 'a', v: cpNode === undefined ? [...partiesNode.v] : [...partiesNode.v, cpNode] };
  const synth = {
    t: 'o',
    e: [
      ['claimed', get(input, 'claimed')],
      ['parties', synthParties],
      ['attestations', get(input, 'findings_attestations')],
    ].filter(([, v]) => v !== undefined),
  };
  independence(synth);
  return true;
}

/* ── CLOSED-WORLD MEMBER VALIDATION (defined_members, v0.5.8+) ─────────────────
 * Added 2026-10-28. This reader was built OPEN-WORLD: it checked the members it
 * knew and let every other name through, so 46 of 284 vectors at v0.6.2 walked
 * past it — 30 accepting outright that must reject, and 16 rejecting for a
 * content reason where the suite expects unknown_member_reject.
 *
 * The precedence was the one thing the manifest did not make obvious to me and
 * Tersign stated it directly (tersignhq/evidence-record-conformance#16,
 * 2026-10-27): "the member check runs first, in every kind and inside each closed
 * object" — MANIFEST.json `defined_members.rule`: "an input that also fails the
 * criterion rejects with unknown_member_reject". So this runs BEFORE evaluate(),
 * not inside it. A content-first engine lands somewhere defensible but different,
 * which is exactly the 16 wrong-reason misses.
 *
 * THE LISTS ARE PINNED HERE AND ASSERTED AGAINST THE MANIFEST, because the rule
 * requires it: "Each engine pins the lists in its code, and its run fails if
 * `closed` differs from them." Reading them out of the manifest at runtime would
 * make this check unfalsifiable — it would agree with any corpus by construction,
 * including a corpus whose lists had silently changed.
 *
 * ⚠️ EXACT STRING COMPARISON ONLY. No case folding, no trimming, no Unicode
 * normalization, no confusable mapping. The vectors that punish each shortcut:
 * n126 `Presented_as`, n127 `sеq` with a Cyrillic U+0435, n128 fullwidth `ｂｙ`
 * which NFKC folds to `by`, n149 `covered_through ` with a trailing space. A
 * reader that normalizes names accepts all four.
 *
 * ⚠️ `constructor` (n131) and `__proto__` (n132) are members like any other. Safe
 * here only because the parser keeps members as an entry ARRAY — a reader that
 * rebuilt plain JS objects would lose `__proto__` to the prototype slot entirely.
 */
const CLOSED = {
  digest_recompute: { input: ['expected_digest', 'payload'] },
  canonical_bytes: { input: ['claimed_canonical', 'payload', 'payload_text'] },
  chain_link: { input: ['artifact_digest', 'expected_link', 'prev_digest', 'seq'] },
  chain_set: {
    input: ['attestations', 'head', 'records', 'witness'],
    'input.head': ['digest', 'seq'],
    'input.records[]': ['artifact_digest', 'link', 'prev_digest', 'seq'],
  },
  chain_commitment: {
    input: ['attestations', 'head', 'records', 'witness'],
    'input.head': ['acc', 'digest', 'seq'],
    'input.records[]': ['artifact_digest', 'link', 'prev_digest', 'seq'],
  },
  anchor_relation: { input: ['anchored_digest', 'subject_digest'] },
  phase_claim: { input: ['presented_as', 'record'] },
  independence_claim: {
    input: ['attestations', 'claimed', 'covers', 'deliverable_bytes', 'deliverable_digest',
      'deliverable_signer', 'parties', 'payTo', 'record_commits', 'settlement_result'],
    'input.attestations[]': ['by', 'role'],
  },
  offer_binding: { input: ['offer', 'receipt'] },
  decision_evidence_binding: { input: ['decision_evidence', 'record'] },
  boundary_binding: { input: ['boundary_event', 'covered_through', 'prefix'] },
  composition_independence: {
    input: ['claimed', 'counterparty', 'decision', 'decision_attestations', 'findings',
      'findings_attestations', 'parties'],
    'input.decision_attestations[]': ['by', 'role'],
    'input.findings_attestations[]': ['by', 'role'],
  },
};

/** The rule's own requirement: the run FAILS if the pinned lists drift from the corpus. */
function assertClosedListsMatchManifest(manifest) {
  const theirs = (manifest.defined_members || {}).closed;
  if (!theirs) throw new Error('MANIFEST.json carries no defined_members.closed — cannot verify pinned lists');
  const norm = (o) => JSON.stringify(Object.keys(o).sort().map((k) =>
    [k, Object.keys(o[k]).sort().map((p) => [p, [...o[k][p]].sort()])]));
  if (norm(theirs) !== norm(CLOSED)) {
    throw new Error('pinned CLOSED lists differ from MANIFEST.json defined_members.closed — '
      + 'the corpus changed its closed sets; update the pinned lists deliberately, do not read theirs at runtime');
  }
}

/**
 * Members of one closed object. Returns the offending name, or null.
 *
 * A closed object that is NOT a JSON object has no members to read, and the kind's
 * criterion decides it as before (n16, p62) — and the entries AFTER it are still
 * checked (n148). So a non-object is skipped, never treated as an error and never
 * allowed to abort the walk.
 */
function unknownMemberIn(node, allowed) {
  if (!node || node.t !== 'o') return null;
  for (const [name] of node.e) if (!allowed.includes(name)) return name;
  return null;
}

function assertDefinedMembers(kind, input) {
  const spec = CLOSED[kind];
  if (!spec) return;                       // kind outside the closed-member rule
  // "An `input` that is not a JSON object is outside the suite, and no vector pins
  // what a verifier does with one." Leave it to the criterion.
  if (!input || input.t !== 'o') return;

  for (const [p, allowed] of Object.entries(spec)) {
    if (p === 'input') {
      const bad = unknownMemberIn(input, allowed);
      if (bad !== null) throw new Reject('unknown_member_reject', `input carries undefined member ${JSON.stringify(bad)} for kind ${kind}`);
      continue;
    }
    const m = /^input\.([A-Za-z_][A-Za-z0-9_]*)(\[\])?$/.exec(p);
    if (!m) throw new Error(`unrecognized closed-object path in pinned lists: ${p}`);
    const [, field, isArray] = m;
    const node = get(input, field);
    if (node === undefined) continue;      // "a listed name may be absent"
    if (isArray) {
      if (!node || node.t !== 'a') continue;   // not an array: criterion's problem, not a member one
      for (let i = 0; i < node.v.length; i++) {
        const bad = unknownMemberIn(node.v[i], allowed);
        if (bad !== null) throw new Reject('unknown_member_reject', `${field}[${i}] carries undefined member ${JSON.stringify(bad)} for kind ${kind}`);
      }
    } else {
      const bad = unknownMemberIn(node, allowed);
      if (bad !== null) throw new Reject('unknown_member_reject', `${field} carries undefined member ${JSON.stringify(bad)} for kind ${kind}`);
    }
  }
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
      const got = canonicalBytes(node);
      const claimed = toJS(get(input, 'claimed_canonical'));
      if (got !== claimed) throw new Reject('canonicalization_reject', 'claimed canonical bytes are not the canonical form');
      return true;
    }
    case 'chain_link': {
      const j = toJS(input);
      // MANIFEST.chain_link: "seq is an integer TOKEN in [1, 2^53-1]". The token class
      // is the boundary, so an exponent or fraction form rejects even when
      // integer-valued. 0 (n75), past 2^53-1 (n76), fraction (n77), exponent (n97),
      // string (n87), boolean (n88) and null (n89) all reject with continuity_reject.
      // Checked on the raw token, before any arithmetic — BigInt(null) used to throw.
      assertSeqToken(get(input, 'seq'));
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
      const got = boundAddress(get(input, 'offer'), 'binding_reject');
      if (got !== hexNorm(receipt.offerDigest)) throw new Reject('binding_reject', `presented offer digests to 0x${got}, receipt commits to 0x${hexNorm(receipt.offerDigest)}`);
      return true;
    }
    case 'decision_evidence_binding': {
      const rec = toJS(get(input, 'record')) || {};
      if (typeof rec.decisionEvidenceDigest !== 'string') throw new Reject('binding_reject', 'record binds no decision evidence');
      const got = boundAddress(get(input, 'decision_evidence'), 'binding_reject');
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
    case 'composition_independence': compositionIndependence(input); return true;
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
  // The rule requires the engine to pin the lists and FAIL if the corpus differs.
  assertClosedListsMatchManifest(manifest);
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
    try {
      // defined_members: decided BEFORE the kind's criterion (MANIFEST.json
      // defined_members.rule; confirmed by Tersign in issue #16, 2026-10-27).
      assertDefinedMembers(kind, input);
      evaluate(kind, input); verdict = 'valid';
    }
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
  // v0.5.4 made normalization lowercase the whole identifier, scheme included
  // (n45/n58/p31). This assertion previously encoded the opposite, which was correct
  // against v0.5.3 and is wrong against this corpus.
  ok('urn case folds, scheme and path', sameId(normId('ORG:Caldera'), normId('org:caldera')));
  ok('urn with inner slash is kept', normId('org:trustline-custody/eu-west').v === 'org:trustline-custody/eu-west');
  // Rule (5) requires CAIP-10 (eip155:8453:0x...) and did:pkh to parse and to name
  // their final 0x component, so a multi-colon identifier must NOT be rejected.
  // The old single-colon assertion predates that rule.
  ok('caip-10 parses and names its address',
    sameId(normId('eip155:8453:0xabc0000000000000000000000000000000000001'), normId('0xABC0000000000000000000000000000000000001')));
  ok('did:pkh names the same address across schemes',
    sameId(normId('did:pkh:eip155:1:0xabc0000000000000000000000000000000000001'), normId('ethereum:0xAbC0000000000000000000000000000000000001')));
  ok('distinct addresses stay distinct',
    !sameId(normId('eip155:1:0xabc0000000000000000000000000000000000001'), normId('0xdef0000000000000000000000000000000000002')));

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
  // exported for tersign-crypto-profile.cjs so the crypto runner reuses the SAME
  // link recipe rather than reimplementing it and agreeing with itself.
  chainLink, canonicalBytes, assertSeqToken, toJS,
};

if (require.main === module) {
  const argv = process.argv.slice(2);
  if (argv.includes('--self-test')) {
    const structural = selfTest();
    cryptoSelfTest().then((c) => process.exit(structural && c ? 0 : 1));
    return;
  }
  if (argv.includes('--mutants')) {
    const dir0 = argv.find((a) => !a.startsWith('--'));
    const base = run(dir0).rows.filter((r) => r.agrees).length;
    const total = run(dir0).rows.length;
    console.log(`baseline ${base}/${total}\n`);
    let killed = 0; const names = Object.keys(MUTANTS);
    for (const name of names) {
      MUT = name;
      let rows;
      try { rows = run(dir0).rows; } catch (e) { rows = null; }
      MUT = null;
      if (!rows) { console.log(`  KILLED   ${name.padEnd(30)} threw`); killed++; continue; }
      const fails = rows.filter((r) => !r.agrees);
      if (fails.length) killed++;
      console.log(`  ${fails.length ? 'KILLED  ' : 'SURVIVED'} ${name.padEnd(30)} ${String(fails.length).padStart(3)}/${rows.length} vectors catch it`);
      console.log(`           ${MUTANTS[name]}`);
      if (fails.length) console.log(`           by: ${fails.slice(0,3).map((f)=>f.file.replace('.json','')).join(', ')}${fails.length>3?` (+${fails.length-3})`:''}`);
    }
    console.log(`\nmutants killed by the corpus: ${killed}/${names.length}`);
    process.exit(0);
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

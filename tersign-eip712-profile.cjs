#!/usr/bin/env node
'use strict';
/*
 * tersign-eip712-profile.cjs — an INDEPENDENT runner for the EIP-712 payload
 * signature profile of github.com/tersignhq/evidence-record-conformance
 * (crypto/EIP712_MANIFEST.json, 46 vectors at v0.6.2).
 *
 * WHY THIS FILE EXISTS. The structural suite (284) and the counter-signature
 * profile (50) were both being run here. This third profile had NO runner at all,
 * so 46 of the corpus's 380 vectors were simply absent from our column — and an
 * absent run reads, to anyone scanning the thread, exactly like agreement. That is
 * the failure mode this corpus is built to expose, and we were an instance of it.
 *
 * Same discipline as the other two runners: `crypto/verify_eip712.py` and
 * `crypto/gen_eip712_vectors.py` were NOT read. Every rule below comes from
 * `crypto/EIP712_MANIFEST.json`'s normative fields (`domain`, `primary_type`,
 * `type`, `integer_domain`, `signer_shape`, `defined_fields`, `reject_reasons`)
 * and from the vectors' own inputs and `origin.source` descriptions.
 *
 * WHAT IS OURS vs BORROWED:
 *   · token-preserving JSON parser  — tersign-reproduction.cjs (ours)
 *   · keccak256                     — viem (third-party, not Tersign's)
 *   · secp256k1 recovery            — viem
 *   · EIP-712 encoding              — written here, by hand, deliberately
 *
 * WHY EIP-712 HASHING IS HAND-ROLLED AND NOT TAKEN FROM viem's hashTypedData.
 * A library's typed-data helper validates and coerces its inputs: it will reject
 * or normalize a boolean where a uint256 belongs, a null where a string belongs, a
 * negative integer, a value above 2**256-1. Those are precisely the faults vectors
 * en29-en33 pin, and the reject REASON the suite expects for them is
 * malformed_input decided by THIS runner's field check. Routing them through a
 * library would either throw something that is not a verdict, or silently coerce
 * and accept. The encoding is four keccaks; the correctness risk of writing it is
 * far smaller than the risk of a helper hiding the vectors.
 *
 *   node tersign-eip712-profile.cjs --self-test
 *   node tersign-eip712-profile.cjs <path-to-corpus>
 *   node tersign-eip712-profile.cjs <path-to-corpus> --json
 */
const fs = require('fs');
const path = require('path');
const R = require('/home/marcus/assurance-run/tersign-reproduction.cjs');

let keccak256, secp;
try {
  const viem = require('/home/marcus/still-os-consciousness/node_modules/viem/_cjs/index.js');
  ({ keccak256 } = viem); secp = viem;
} catch {
  try { const viem = require('viem'); ({ keccak256 } = viem); secp = viem; }
  catch { console.error('need viem for keccak256 + recovery'); process.exit(2); }
}
const kec = (buf) => keccak256(buf).slice(2);                       // hex, no 0x
const kecUtf8 = (s) => kec(Buffer.from(s, 'utf8'));

const SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const HALF_N = SECP256K1_N / 2n;
const MAX_UINT256 = (1n << 256n) - 1n;

/** A reject with a reason from the profile's declared closed set. */
class Rej extends Error {
  constructor(reason, detail) { super(detail || reason); this.reason = reason; }
}

/* ── PINNED PROFILE CONSTANTS ──────────────────────────────────────────────────
 * Pinned in code and asserted against the manifest by assertProfilePins(), for the
 * same reason the other two runners pin their closed sets: a runner that reads the
 * domain and the type string out of the manifest at run time agrees with any corpus
 * by construction, including one whose domain silently changed. The assertion is
 * what makes this falsifiable.
 */
const DOMAIN = { name: 'x402 receipt', version: '1', chainId: 1n };
const PRIMARY_TYPE = 'Receipt';
const RECEIPT_TYPE = 'Receipt(uint256 version,string network,string resourceUrl,string payer,uint256 issuedAt,string transaction)';
// The domain has exactly name, version, chainId — no verifyingContract, no salt —
// so the EIP712Domain type string carries exactly those three, in that order.
const DOMAIN_TYPE = 'EIP712Domain(string name,string version,uint256 chainId)';
const ENVELOPE_KEYS = ['format', 'payload', 'signature', 'signer'];
// Order matters: this is the field order the Receipt type declares, and EIP-712
// encodes struct members in declaration order.
const RECEIPT_FIELDS = [
  { name: 'version', type: 'uint256' },
  { name: 'network', type: 'string' },
  { name: 'resourceUrl', type: 'string' },
  { name: 'payer', type: 'string' },
  { name: 'issuedAt', type: 'uint256' },
  { name: 'transaction', type: 'string' },
];
const SUPPORTED_FORMAT = 'eip712';
const SUPPORTED_VERSION = 1n;

function assertProfilePins(man) {
  const bad = [];
  if (man.primary_type !== PRIMARY_TYPE) bad.push(`primary_type ${man.primary_type}`);
  if (man.type !== RECEIPT_TYPE) bad.push('type string');
  if (man.domain.name !== DOMAIN.name) bad.push(`domain.name ${man.domain.name}`);
  if (man.domain.version !== DOMAIN.version) bad.push(`domain.version ${man.domain.version}`);
  if (BigInt(man.domain.chainId) !== DOMAIN.chainId) bad.push(`domain.chainId ${man.domain.chainId}`);
  const domainKeys = Object.keys(man.domain).sort().join(',');
  if (domainKeys !== 'chainId,name,version') bad.push(`domain members ${domainKeys} — the EIP712Domain type string must change with them`);
  // The field list and order must match the type string we pinned.
  const fromType = /^Receipt\((.*)\)$/.exec(RECEIPT_TYPE)[1].split(',')
    .map((p) => { const [t, n] = p.split(' '); return { name: n, type: t }; });
  if (JSON.stringify(fromType) !== JSON.stringify(RECEIPT_FIELDS)) bad.push('RECEIPT_FIELDS does not match the pinned type string');
  if (bad.length) {
    throw new Error(`pinned profile constants differ from crypto/EIP712_MANIFEST.json: ${bad.join('; ')} — `
      + 'update the pins deliberately; do not read the manifest at run time');
  }
}

/* ── EIP-712 encoding ──────────────────────────────────────────────────────────
 * encodeData for this type is six 32-byte words: a uint256 as a big-endian word, a
 * string as keccak256 of its UTF-8 bytes. structHash = keccak256(typeHash || words).
 * digest = keccak256(0x19 || 0x01 || domainSeparator || structHash).
 */
const word = (hex32) => Buffer.from(hex32, 'hex');
const uintWord = (v) => {
  let h = v.toString(16);
  if (h.length > 64) throw new Error('uint over 32 bytes');     // unreachable: range-checked earlier
  return word(h.padStart(64, '0'));
};
const strWord = (s) => word(kecUtf8(s));

function domainSeparator() {
  return kec(Buffer.concat([
    word(kecUtf8(DOMAIN_TYPE)),
    strWord(DOMAIN.name),
    strWord(DOMAIN.version),
    uintWord(DOMAIN.chainId),
  ]));
}

function receiptDigest(fields) {
  const words = [word(kecUtf8(RECEIPT_TYPE))];
  for (const f of RECEIPT_FIELDS) {
    words.push(f.type === 'uint256' ? uintWord(fields[f.name]) : strWord(fields[f.name]));
  }
  const structHash = kec(Buffer.concat(words));
  return kec(Buffer.concat([
    Buffer.from([0x19, 0x01]),
    word(domainSeparator()),
    word(structHash),
  ]));
}

/* ── field reading, all of it before the signature ─────────────────────────────
 * crypto/EIP712_MANIFEST.json defined_fields: "a key beyond them, in the envelope
 * or in the payload, rejects as malformed_input whatever its value, BEFORE THE
 * SIGNATURE IS READ". en36/en37 are that precedence with a bad signature attached;
 * en27 is the general payload-before-signature order. en38/en39 add the key with a
 * NULL value — "a key counts by its name, whatever its value" — so presence is the
 * test, never truthiness.
 */
const member = (objNode, name) => {
  if (!objNode || objNode.t !== 'o') return undefined;
  const hit = objNode.e.find(([k]) => k === name);
  return hit ? hit[1] : undefined;
};
const has = (objNode, name) => !!objNode && objNode.t === 'o' && objNode.e.some(([k]) => k === name);

/** An unpaired UTF-16 surrogate has no UTF-8 encoding, so the field cannot be hashed (en19). */
const hasLoneSurrogate = (s) => {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) { const n = s.charCodeAt(i + 1); if (!(n >= 0xdc00 && n <= 0xdfff)) return true; i++; }
    else if (c >= 0xdc00 && c <= 0xdfff) return true;
  }
  return false;
};

/**
 * uint256 from a JSON number TOKEN. en26 carries the token `1.0`: JSON.parse turns
 * it into 1 and a runner built on parsed numbers cannot see the vector at all. Same
 * class as the counter-signature profile's cn29 and the structural suite's n38.
 * Range is the full uint256 domain — integer_domain is explicit that there is no
 * freshness or policy bound on issuedAt (ep7/ep8/ep9), so -1 (en9/en29) and 2**256
 * (en25) reject on the TYPE, not on plausibility.
 */
function uint256FromToken(node, name) {
  if (node === undefined) throw new Rej('malformed_input', `${name} is absent`);
  if (node.t !== 'n') throw new Rej('malformed_input', `${name} is not a JSON number (en8/en30/en31 class)`);
  if (!/^(0|[1-9][0-9]*)$/.test(node.tok)) throw new Rej('malformed_input', `${name} token ${JSON.stringify(node.tok)} is not a non-negative integer token`);
  const v = BigInt(node.tok);
  if (v > MAX_UINT256) throw new Rej('malformed_input', `${name} is above the uint256 domain`);
  return v;
}

function stringField(node, name) {
  if (node === undefined) throw new Rej('malformed_input', `${name} is absent`);
  if (node.t !== 's') throw new Rej('malformed_input', `${name} is not a JSON string`);
  if (hasLoneSurrogate(node.v)) throw new Rej('malformed_input', `${name} carries an unpaired surrogate and has no UTF-8 encoding`);
  return node.v;
}

async function evaluate(inputNode) {
  if (!inputNode || inputNode.t !== 'o') throw new Rej('malformed_input', 'input is not a JSON object');

  // ── format first: a record labelled something else is not ours to judge (en12) ──
  const fmtNode = member(inputNode, 'format');
  const fmt = fmtNode && fmtNode.t === 's' ? fmtNode.v : undefined;
  if (fmt !== SUPPORTED_FORMAT) throw new Rej('unsupported_format', `format ${JSON.stringify(fmt)} is not ${SUPPORTED_FORMAT}`);

  // ── envelope: exactly format, payload, signature, signer (en35/en37/en39) ──
  for (const [k] of inputNode.e) {
    if (!ENVELOPE_KEYS.includes(k)) throw new Rej('malformed_input', `envelope carries undefined key ${JSON.stringify(k)}`);
  }
  for (const k of ENVELOPE_KEYS) {
    if (!has(inputNode, k)) throw new Rej('malformed_input', `envelope is missing ${k}`);
  }

  // ── payload: exactly the six Receipt fields (en10/en16/en34/en36/en38) ──
  const payloadNode = member(inputNode, 'payload');
  if (!payloadNode || payloadNode.t !== 'o') throw new Rej('malformed_input', 'payload is not a JSON object');
  const names = RECEIPT_FIELDS.map((f) => f.name);
  for (const [k] of payloadNode.e) {
    if (!names.includes(k)) throw new Rej('malformed_input', `payload carries undefined field ${JSON.stringify(k)}`);
  }
  // "the payload is used exactly as transmitted; '' means absence, an omitted key is
  // not filled in as ''" — so every one of the six must be PRESENT. en10 removes the
  // optional `transaction` and still rejects; a runner that defaults it to '' accepts.
  const fields = {};
  for (const f of RECEIPT_FIELDS) {
    const n = member(payloadNode, f.name);
    if (!has(payloadNode, f.name)) throw new Rej('malformed_input', `payload is missing ${f.name}`);
    fields[f.name] = f.type === 'uint256' ? uint256FromToken(n, f.name) : stringField(n, f.name);
  }

  // ── signer shape, before recovery (en28) ──
  // signer_shape: 0x + 40 hex, compared case-insensitively with the recovered
  // address. en28 is 0x + 39 hex; a runner that skips this reports signer_mismatch.
  const signerNode = member(inputNode, 'signer');
  const signerRaw = signerNode && signerNode.t === 's' ? signerNode.v : undefined;
  if (typeof signerRaw !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(signerRaw)) {
    throw new Rej('malformed_input', `signer ${JSON.stringify(signerRaw)} is not 0x + 40 hex digits`);
  }
  const signer = signerRaw.toLowerCase();

  // ── version: well-typed but unsupported is its own reason (en17) ──
  // Decided AFTER the field checks: en26's `1.0` version is malformed_input, not
  // unsupported_version, so the token check must come first.
  if (fields.version !== SUPPORTED_VERSION) {
    throw new Rej('unsupported_version', `Receipt version ${fields.version} is not the profile's version ${SUPPORTED_VERSION}`);
  }

  // ── signature, last ──
  const sigNode = member(inputNode, 'signature');
  const sig = sigNode && sigNode.t === 's' ? sigNode.v : undefined;
  // Lowercase `0x` prefix required: en24 carries `0X` and rejects malformed_signature.
  // Hex digits themselves may be either case.
  if (typeof sig !== 'string' || !/^0x[0-9a-fA-F]{130}$/.test(sig)) {
    throw new Rej('malformed_signature', 'signature is not 0x + 130 hex digits');
  }
  const v = parseInt(sig.slice(130, 132), 16);
  // en20/en21 carry the raw recovery id 0 and 1 rather than 27/28.
  if (v !== 27 && v !== 28) throw new Rej('malformed_signature', `v is ${v}, not 27 or 28`);
  const r = BigInt(`0x${sig.slice(2, 66)}`);
  const s = BigInt(`0x${sig.slice(66, 130)}`);
  if (s === 0n) throw new Rej('malformed_signature', 's is zero');
  if (r === 0n || r >= SECP256K1_N) throw new Rej('malformed_signature', 'r outside [1, n-1]');
  // Malleability is its own declared reason and is decided before recovery: en6 is
  // s' = n - s with v flipped, en23 is s = n/2 + 1, the first high s.
  if (s > HALF_N) throw new Rej('non_canonical_s', 's is above n/2');

  const digest = receiptDigest(fields);
  let got;
  try { got = await secp.recoverAddress({ hash: `0x${digest}`, signature: sig }); }
  catch { throw new Rej('unrecoverable', 'no public key recovers from this signature'); }
  if (!got) throw new Rej('unrecoverable', 'no public key recovers from this signature');
  if (got.toLowerCase() !== signer) {
    throw new Rej('signer_mismatch', `recovers to ${got.toLowerCase()}, signer declares ${signer}`);
  }
  return true;
}

async function run(corpusDir) {
  const man = JSON.parse(fs.readFileSync(path.join(corpusDir, 'crypto', 'EIP712_MANIFEST.json'), 'utf8'));
  assertProfilePins(man);

  // Read the MANIFEST, never a directory listing — and report the difference both
  // ways, so a vector listed-and-absent cannot pass as coverage.
  const listed = man.vectors.map((x) => x.file);
  const dir = path.join(corpusDir, 'crypto', 'eip712_vectors');
  const onDisk = fs.readdirSync(dir).filter((f) => f.endsWith('.json'));
  const missing = listed.filter((f) => !onDisk.includes(f));
  const unlisted = onDisk.filter((f) => !listed.includes(f));

  const rows = [];
  for (const file of listed) {
    const raw = fs.readFileSync(path.join(dir, file), 'utf8');
    const vec = JSON.parse(raw);                                   // envelope only
    // The INPUT is re-read through the token-preserving parser so `1.0` stays `1.0`.
    const inputNode = member(R.parseJson(raw), 'input');
    let got = 'valid', reason = null, detail = null;
    try { await evaluate(inputNode); }
    catch (e) {
      if (e instanceof Rej) { got = 'reject'; reason = e.reason; detail = e.message; }
      // Anything that is not a verdict IS the failure this corpus names.
      else { got = 'error'; reason = 'instrument_failure'; detail = `${e.constructor.name}: ${e.message}`; }
    }
    const expect = vec.expect;
    const expectReason = vec.reject_reason || null;
    rows.push({
      file, kind: vec.kind, expect, expect_reason: expectReason, got, got_reason: reason, detail,
      verdict_agrees: got === expect,
      reason_agrees: got !== 'reject' ? true : reason === expectReason,
      agrees: got === expect && (got !== 'reject' || reason === expectReason),
    });
  }
  return { suite: 'evidence-record-conformance/crypto (EIP-712)', rows, missing, unlisted,
    declared_reasons: man.reject_reasons };
}

/* ── SELF-TEST: primitives against known answers, before any vector is trusted ── */
function selfTest() {
  let pass = 0, fail = 0;
  const ok = (n, c, d) => { if (c) pass++; else { fail++; console.log(`  FAIL ${n}${d ? '  ' + d : ''}`); } };

  ok('keccak256 of the empty string', kecUtf8('') === 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470');
  // The EIP712Domain type hash for exactly {name, version, chainId}.
  ok('domain type string has three members, matching the pinned domain',
    DOMAIN_TYPE === 'EIP712Domain(string name,string version,uint256 chainId)');
  ok('domain separator is 32 bytes', domainSeparator().length === 64);
  ok('domain separator is stable', domainSeparator() === domainSeparator());
  ok('uint word is big-endian and left-padded', uintWord(1n).toString('hex') === '0'.repeat(63) + '1');
  ok('uint word of max uint256 is all ff', uintWord(MAX_UINT256).toString('hex') === 'f'.repeat(64));
  ok('string word is keccak of utf8', strWord('').toString('hex') === kecUtf8(''));

  // Token discipline — the vectors that exist to catch a JSON.parse-based runner.
  const tok = (t) => ({ t: 'n', tok: t });
  ok('`1.0` is not an integer token (en26)', (() => { try { uint256FromToken(tok('1.0'), 'v'); return false; } catch (e) { return e.reason === 'malformed_input'; } })());
  ok('`-1` rejects (en9/en29)', (() => { try { uint256FromToken(tok('-1'), 'v'); return false; } catch (e) { return e.reason === 'malformed_input'; } })());
  ok('2**256 rejects (en25)', (() => { try { uint256FromToken(tok((1n << 256n).toString()), 'v'); return false; } catch (e) { return e.reason === 'malformed_input'; } })());
  ok('2**256-1 accepts', uint256FromToken(tok(MAX_UINT256.toString()), 'v') === MAX_UINT256);
  ok('a boolean is not a number (en30/en31)', (() => { try { uint256FromToken({ t: 'b', v: true }, 'v'); return false; } catch (e) { return e.reason === 'malformed_input'; } })());
  ok('a string is not a number (en8)', (() => { try { uint256FromToken({ t: 's', v: '1' }, 'v'); return false; } catch (e) { return e.reason === 'malformed_input'; } })());
  ok('null is not a string field (en32)', (() => { try { stringField({ t: 'z' }, 'transaction'); return false; } catch (e) { return e.reason === 'malformed_input'; } })());
  ok('a number is not a string field (en33)', (() => { try { stringField(tok('1'), 'payer'); return false; } catch (e) { return e.reason === 'malformed_input'; } })());
  ok('a lone surrogate has no UTF-8 encoding (en19)', (() => { try { stringField({ t: 's', v: '\ud800' }, 'payer'); return false; } catch (e) { return e.reason === 'malformed_input'; } })());
  ok('a paired surrogate is fine', stringField({ t: 's', v: '😀' }, 'payer') === '😀');
  ok('lone-surrogate detector does not false-positive on plain text', !hasLoneSurrogate('0xabc'));

  ok('half-n boundary is below n/2 + 1', HALF_N + 1n > HALF_N);
  console.log(`\neip712-profile self-test: ${pass} passed, ${fail} failed`);
  return { pass, fail };
}

module.exports = { run, evaluate, selfTest, receiptDigest, domainSeparator };

if (require.main === module) {
  if (process.argv.includes('--self-test')) {
    const r = selfTest();
    process.exit(r.fail ? 1 : 0);
  }
  const dir = process.argv[2];
  if (!dir) { console.error('usage: node tersign-eip712-profile.cjs <corpus-dir> [--json]'); process.exit(2); }
  run(dir).then((r) => {
    if (process.argv.includes('--json')) { console.log(JSON.stringify(r, null, 1)); return; }
    for (const x of r.rows) {
      console.log(`  [${x.agrees ? 'AGREE ' : '  DIFF'}] ${x.file.replace('.json', '').padEnd(50)} expect ${x.expect}/${x.expect_reason || '-'}  got ${x.got}/${x.got_reason || '-'}`);
    }
    const dis = r.rows.filter((x) => !x.agrees);
    const exercised = new Set(r.rows.filter((x) => x.expect === 'reject').map((x) => x.expect_reason));
    console.log(`\n${r.suite}`);
    console.log(`  vectors            : ${r.rows.length}`);
    console.log(`  independent AGREE  : ${r.rows.length - dis.length}`);
    console.log(`  DISAGREE           : ${dis.length}`);
    console.log(`  reject reasons     : ${exercised.size} of ${r.declared_reasons.length} declared, exercised`);
    console.log(`  manifest vs disk   : ${r.missing.length} listed-not-present, ${r.unlisted.length} present-not-listed`);
    for (const x of dis) {
      console.log(`\n    ${x.file}\n        expected ${x.expect} / ${x.expect_reason || '-'}\n        ours     ${x.got} / ${x.got_reason || '-'}\n        detail   ${x.detail}`);
    }
    process.exit(dis.length ? 1 : 0);
  }).catch((e) => { console.error(e); process.exit(1); });
}

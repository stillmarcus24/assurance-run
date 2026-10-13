#!/usr/bin/env node
'use strict';
/*
 * tersign-crypto-profile.cjs — an INDEPENDENT runner for the crypto/ counter-signature
 * profile of github.com/tersignhq/evidence-record-conformance (46 vectors at v0.5.6).
 *
 * Same discipline as tersign-reproduction.cjs, which this file reuses for the link
 * recipe and the EIP-191 primitives: `crypto/verify_crypto.py` and
 * `crypto/gen_crypto_vectors.py` were NOT read. Every rule below is implemented from
 * `crypto/MANIFEST.json`'s normative fields — `field_domain`, `link_recipe`,
 * `link_version_rule` and the declared `reject_reasons` — and from the vectors' own
 * inputs.
 *
 * THE SIX DECLARED REASONS, and the order they are decided in. The order is this
 * file's reading: the manifest declares the set, not a precedence, so any vector that
 * turns on precedence is reported as a disagreement rather than resolved by looking
 * at the expected answer.
 *   malformed_input           field_domain violated (digest, signer, seq)
 *   unsupported_link_version  link_version present and not the integer 1
 *   malformed_signature       not 0x + 130 hex, or v outside {27,28}
 *   non_canonical_s           s above the low-s bound (EIP-2 / SEC1 malleability)
 *   unrecoverable             no public key recovers from (hash, r, s, v)
 *   signer_mismatch           recovers, but not to ledger_signer
 *
 * RELATIONSHIP TO crypto-profile/verify_crypto.cjs (2026-09-29). That file was the
 * second independent runner #11 asked for, against the 8 vectors the profile had
 * then, and it vendored its own copy of them. It is path-bound to that vendored
 * directory and does not read a corpus argument, so it cannot run v0.5.6's 46. It
 * stays as the artifact cited on #11 (cn3 is credited in the suite's
 * CONTRIBUTORS.md); this file is the runner for the profile as released.
 *
 *   node tersign-crypto-profile.cjs <path-to-corpus>          # run crypto/vectors
 *   node tersign-crypto-profile.cjs <path-to-corpus> --json
 */
const fs = require('fs');
const path = require('path');
const R = require('./tersign-reproduction.cjs');

const SECP256K1_N = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');
const HALF_N = SECP256K1_N / 2n;

// crypto/MANIFEST.field_domain: the core's identifier_normalization White_Space set.
const WS_CLASS = '\\u0009-\\u000D\\u0020\\u0085\\u00A0\\u1680\\u2000-\\u200A\\u2028\\u2029\\u202F\\u205F\\u3000';
const WS_RE = new RegExp(`^[${WS_CLASS}]+|[${WS_CLASS}]+$`, 'g');
const strip = (s) => (typeof s === 'string' ? s.replace(WS_RE, '') : s);

class Rej extends Error {
  constructor(reason, detail) { super(detail || reason); this.reason = reason; }
}

/** "strip ... and lowercase, then exactly 0x + N hex". */
function fieldHex(v, nybbles, name) {
  if (typeof v !== 'string') throw new Rej('malformed_input', `${name} is not a string`);
  const s = strip(v).toLowerCase();
  if (!new RegExp(`^0x[0-9a-f]{${nybbles}}$`).test(s)) throw new Rej('malformed_input', `${name} is not 0x + ${nybbles} hex`);
  return s;
}

/**
 * "seq: an integer TOKEN in [1, 2**53 - 1]" — the token class is the boundary, so
 * `1.0` is not an integer token even though it is integer-valued (cn29).
 *
 * ⚠️ This takes the raw token node, never a JSON.parse value. The first version of
 * this runner used JSON.parse and read cn29's `1.0` as the number 1 — the precise
 * defect tersign-reproduction.cjs's hand-written parser exists to prevent, and its
 * file header warns about. A verifier built on JSON.parse cannot see this class at
 * all and silently passes the vector written to catch it.
 */
function fieldSeqToken(node) {
  if (!node || node.t !== 'n') throw new Rej('malformed_input', 'seq is not a JSON number token');
  if (!/^(0|[1-9][0-9]*)$/.test(node.tok)) throw new Rej('malformed_input', `seq token ${JSON.stringify(node.tok)} is not an integer form`);
  const v = Number(node.tok);
  if (v < 1 || v > 9007199254740991) throw new Rej('malformed_input', 'seq outside [1, 2^53-1]');
  return v;
}

/** Same token discipline for link_version: `1.0` is not the integer 1 (cn30). */
function assertLinkVersionToken(node) {
  if (node === undefined) return;                       // absent means 1
  if (node.t !== 'n' || !/^(0|[1-9][0-9]*)$/.test(node.tok) || Number(node.tok) !== 1) {
    throw new Rej('unsupported_link_version', `link_version token ${node.t === 'n' ? node.tok : node.t} is not the integer 1`);
  }
}

/** Member lookup on a token-preserving object node. */
const member = (objNode, name) => {
  if (!objNode || objNode.t !== 'o') return undefined;
  const hit = objNode.e.find(([k]) => k === name);
  return hit ? hit[1] : undefined;
};
const plain = (node) => (node === undefined ? undefined : R.toJS ? R.toJS(node) : undefined);

function evaluate(inputNode) {
  // link_version_rule: absent means 1; any other value, token included, is unsupported.
  assertLinkVersionToken(member(inputNode, 'link_version'));
  const artifact = fieldHex(plain(member(inputNode, 'artifact_digest')), 64, 'artifact_digest');
  // "or 32 zero bytes when absent" — an absent key and an explicit null are the
  // genesis case (cp3 pins key-omitted against the null form).
  const prevNode = member(inputNode, 'prev_digest');
  const prevRaw = plain(prevNode);
  const prev = (prevRaw === undefined || prevRaw === null) ? null : fieldHex(prevRaw, 64, 'prev_digest');
  const seq = fieldSeqToken(member(inputNode, 'seq'));
  const signer = fieldHex(plain(member(inputNode, 'ledger_signer')), 40, 'ledger_signer');

  // "countersignature: matched whole and UNNORMALIZED" — no strip, no lowercase.
  const sig = plain(member(inputNode, 'countersignature'));
  if (typeof sig !== 'string' || !/^0x[0-9a-fA-F]{130}$/.test(sig)) throw new Rej('malformed_signature', 'countersignature is not 0x + 130 hex');
  const v = parseInt(sig.slice(130, 132), 16);
  if (v !== 27 && v !== 28) throw new Rej('malformed_signature', `v is ${v}, not 27 or 28`);
  const s = BigInt('0x' + sig.slice(66, 130));
  if (s > HALF_N) throw new Rej('non_canonical_s', 's is above n/2');
  if (s === 0n) throw new Rej('malformed_signature', 's is zero');
  const r = BigInt('0x' + sig.slice(2, 66));
  if (r === 0n || r >= SECP256K1_N) throw new Rej('malformed_signature', 'r outside [1, n-1]');

  const link = R.chainLink(artifact, prev, seq);          // the core recipe, reused
  return R.recoverPersonalSign(Buffer.from(link, 'hex'), sig).then((got) => {
    if (got !== signer) throw new Rej('signer_mismatch', `recovers to ${got}, ledger_signer is ${signer}`);
    return true;
  }, () => { throw new Rej('unrecoverable', 'no public key recovers from this signature'); });
}

async function run(corpusDir) {
  const man = JSON.parse(fs.readFileSync(path.join(corpusDir, 'crypto', 'MANIFEST.json'), 'utf8'));
  // set_rules: read the MANIFEST, not a directory listing.
  const listed = man.vectors.map((v) => v.file);
  const onDisk = fs.readdirSync(path.join(corpusDir, 'crypto', 'vectors')).filter((f) => f.endsWith('.json'));
  const missing = listed.filter((f) => !onDisk.includes(f));
  const unlisted = onDisk.filter((f) => !listed.includes(f));
  const rows = [];
  for (const file of listed) {
    const raw = fs.readFileSync(path.join(corpusDir, 'crypto', 'vectors', file), 'utf8');
    const vec = JSON.parse(raw);                       // envelope only (id/kind/expect)
    // The INPUT is re-read through the token-preserving parser: `1.0` must stay `1.0`.
    const inputNode = member(R.parseJson(raw), 'input');
    let got = 'valid', reason = null, detail = null;
    try { await evaluate(inputNode); }
    catch (e) {
      if (e instanceof Rej) { got = 'reject'; reason = e.reason; detail = e.message; }
      else { got = 'error'; detail = `${e.constructor.name}: ${e.message}`; }
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
  return { suite: 'evidence-record-conformance/crypto', version: man.link_version, rows, missing, unlisted,
    declared_reasons: man.reject_reasons };
}

if (require.main === module) {
  const dir = process.argv[2];
  if (!dir) { console.error('usage: node tersign-crypto-profile.cjs <corpus-dir> [--json]'); process.exit(2); }
  run(dir).then((r) => {
    if (process.argv.includes('--json')) { console.log(JSON.stringify(r, null, 1)); return; }
    for (const x of r.rows) {
      console.log(`  [${x.agrees ? 'AGREE ' : '  DIFF'}] ${x.file.replace('.json', '').padEnd(46)} expect ${x.expect}/${x.expect_reason || '-'}  got ${x.got}/${x.got_reason || '-'}`);
    }
    const dis = r.rows.filter((x) => !x.agrees);
    const exercised = new Set(r.rows.filter((x) => x.expect === 'reject').map((x) => x.expect_reason));
    console.log(`\n${r.suite}  link_version ${r.version}`);
    console.log(`  vectors            : ${r.rows.length}`);
    console.log(`  independent AGREE  : ${r.rows.length - dis.length}`);
    console.log(`  DISAGREE           : ${dis.length}`);
    console.log(`  reject reasons     : ${exercised.size} of ${r.declared_reasons.length} declared, exercised`);
    console.log(`  manifest vs disk   : ${r.missing.length} listed-not-present, ${r.unlisted.length} present-not-listed`);
    for (const x of dis) {
      console.log(`\n    ${x.file}\n        expected ${x.expect} / ${x.expect_reason || '-'}\n        ours     ${x.got} / ${x.got_reason || '-'}\n        detail   ${x.detail}`);
    }
  }).catch((e) => { console.error(e); process.exit(1); });
}
module.exports = { run };

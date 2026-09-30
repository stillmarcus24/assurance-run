#!/usr/bin/env node
/**
 * Independent Node runner for the crypto profile on
 * tersignhq/evidence-record-conformance#11 (@babyblueviper1), who asked for a
 * second independent runner. Same relationship as the core suite, where a Node
 * run of all 69 vectors was cited for Criterion 3 on x402-foundation/tsc#4.
 *
 * INDEPENDENCE, stated precisely:
 *   - implemented from `crypto/README.md`'s four normative rules and the vectors'
 *     own fields. `verify_crypto.py` and `secp256k1_recover.py` were NOT fetched
 *     and NOT read — only MANIFEST.json, README.md and vectors/.
 *   - it is NOT stdlib-pure the way theirs is: keccak256 and the secp256k1
 *     recovery come from viem. So this is a second IMPLEMENTATION in a second
 *     language, not a second stdlib-only proof. Said plainly rather than implied.
 *
 * The four rules, from the README:
 *   1. link = keccak256(artifact_digest || prev_digest (or 32 zero bytes) || seq_uint64_be)
 *   2. 65-byte r||s||v with v in {27,28}
 *   3. low-s, EIP-2: s <= n/2
 *   4. EIP-191 personal_sign recovery over the 32 link bytes == ledger_signer
 *
 * Reject reasons: malformed_signature · non_canonical_s · unrecoverable · signer_mismatch
 */
const fs = require('fs');
const path = require('path');
const { keccak256, recoverAddress, hashMessage } = require('viem');

// secp256k1 group order
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const HALF_N = N / 2n;

const hexToBytes = (h) => Buffer.from(String(h).replace(/^0x/, ''), 'hex');
const bytesToHex = (b) => '0x' + Buffer.from(b).toString('hex');

/** Rule 1 — recompute the link from the vector's OWN fields, never a supplied hash. */
function chainLink({ artifact_digest, prev_digest, seq }) {
  const a = hexToBytes(artifact_digest);
  if (a.length !== 32) throw new Error('artifact_digest is not 32 bytes');
  const p = prev_digest === null || prev_digest === undefined
    ? Buffer.alloc(32) // genesis: 32 zero bytes
    : hexToBytes(prev_digest);
  if (p.length !== 32) throw new Error('prev_digest is not 32 bytes');
  const s = Buffer.alloc(8);
  s.writeBigUInt64BE(BigInt(seq)); // uint64 big-endian
  return keccak256(bytesToHex(Buffer.concat([a, p, s])));
}

async function checkVector(v) {
  const i = v.input;
  let link;
  try { link = chainLink(i); }
  catch (e) { return { verdict: 'reject', reason: 'malformed_signature', note: 'link: ' + e.message }; }

  const sig = hexToBytes(i.countersignature);

  // Rule 2 — shape before anything else, so a truncated signature can never be
  // sliced into something that looks recoverable.
  if (sig.length !== 65) return { verdict: 'reject', reason: 'malformed_signature', link };
  const v27 = sig[64];
  if (v27 !== 27 && v27 !== 28) return { verdict: 'reject', reason: 'malformed_signature', link };

  // Rule 3 — EIP-2 low-s. This is the check that kills the malleated twin, and it
  // must run BEFORE recovery: the malleated form recovers to the same address, so
  // a runner that recovers first and only compares addresses accepts it.
  const sVal = BigInt('0x' + sig.subarray(32, 64).toString('hex'));
  if (sVal === 0n || sVal > HALF_N) return { verdict: 'reject', reason: 'non_canonical_s', link };
  const rVal = BigInt('0x' + sig.subarray(0, 32).toString('hex'));
  if (rVal === 0n || rVal >= N) return { verdict: 'reject', reason: 'malformed_signature', link };

  // Rule 4 — EIP-191 personal_sign recovery over the 32 link bytes
  let recovered;
  try {
    recovered = await recoverAddress({ hash: hashMessage({ raw: link }), signature: bytesToHex(sig) });
  } catch (e) { return { verdict: 'reject', reason: 'unrecoverable', link }; }

  const want = String(i.ledger_signer || '').toLowerCase();
  if (recovered.toLowerCase() !== want) {
    return { verdict: 'reject', reason: 'signer_mismatch', link, recovered };
  }
  return { verdict: 'valid', reason: null, link, recovered };
}

async function main() {
  const dir = process.argv[2] || path.join(__dirname, 'vectors');
  const files = fs.readdirSync(dir).filter((f) => f.endsWith('.json')).sort();
  let agree = 0, disagree = 0, reasonsOk = 0, reasonsChecked = 0;
  const rows = [];

  for (const f of files) {
    const v = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
    const got = await checkVector(v);
    const verdictOk = got.verdict === v.expect;
    let reasonOk = null;
    if (v.expect === 'reject' && v.reject_reason) {
      reasonsChecked++;
      reasonOk = got.reason === v.reject_reason;
      if (reasonOk) reasonsOk++;
    }
    if (verdictOk && reasonOk !== false) agree++; else disagree++;
    rows.push({ id: v.id, expect: v.expect, got: got.verdict,
      expect_reason: v.reject_reason || null, got_reason: got.reason,
      link: got.link, recovered: got.recovered || null,
      ok: verdictOk && reasonOk !== false });
  }

  // A runner that cannot discriminate is not evidence.
  const distinct = new Set(rows.map((r) => `${r.got}:${r.got_reason}`));

  for (const r of rows) {
    console.log(`  ${r.ok ? 'ok  ' : 'FAIL'} ${r.id.padEnd(46)} ${r.got}${r.got_reason ? '/' + r.got_reason : ''}`);
  }
  console.log(`\nvectors            : ${rows.length}`);
  console.log(`verdict agreement  : ${agree}/${rows.length}`);
  console.log(`reject reasons     : ${reasonsOk}/${reasonsChecked} exercised and matching`);
  console.log(`distinct outcomes  : ${distinct.size} (a constant-returning runner cannot pass)`);
  fs.writeFileSync(path.join(__dirname, 'node-run.json'),
    JSON.stringify({ vectors: rows.length, agree, disagree, reasonsOk, reasonsChecked,
      distinct_outcomes: distinct.size, rows }, null, 2) + '\n');
  process.exit(disagree ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(2); });

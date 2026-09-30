#!/usr/bin/env node
/**
 * Ed25519 non-canonical-S malleability test — the adjacent-profile input cited on
 * tersignhq/evidence-record-conformance#11.
 *
 * It was wrong to state that result without shipping this. In a suite whose bar is
 * "recomputable from bytes plus a verifier, no hosted call", a number with no runner
 * is exactly the defect this thread exists to catch.
 *
 * Runs against PUBLIC inputs only — no local files, no keys, so a stranger can
 * reproduce it:
 *   - four published commitment files and their detached signatures
 *   - the public keyring, resolved BY FINGERPRINT (never "the current key")
 *
 * WHAT IT TESTS, and the scope is the point:
 *   the S + L non-canonical encoding form only. It is NOT a claim about every
 *   Ed25519 malleability class (small-order R, cofactor/mixed-order points are not
 *   covered here).
 *
 * WHY THE POSITIVE CONTROL IS FIRST: an earlier version of this test reported "safe"
 * while the ORIGINAL signature also failed to verify — it proved nothing, because the
 * signed message is domain-separated as `domain || 0x00 || ascii(sha256_hex(file))`
 * and I had signed the wrong preimage. A rejection only means something once the
 * genuine signature is shown to verify.
 */
const crypto = require('crypto');

const L = 2n ** 252n + 27742317777372353535851937790883648493n; // ed25519 group order
const BASE = 'https://raw.githubusercontent.com/stillmarcus24/mcpship-registry-attestations/publish-windows-20260926-20260927/results';
const KEYRING = 'https://stillosdigitalholdings.com/notary/keyring';
const WINDOWS = ['2026-09-26T1605Z', '2026-09-27T1605Z', '2026-09-28T1605Z', '2026-09-29T1605Z'];

async function getText(u) {
  const r = await fetch(u, { headers: { accept: 'application/json' } });
  if (!r.ok) throw new Error(`${u} -> HTTP ${r.status}`);
  return await r.text();
}

/** resolve the signing key by fingerprint, not by position in the keyring */
async function keyByFingerprint(fp) {
  const kr = JSON.parse(await getText(KEYRING));
  const k = (kr.keys || []).find((x) => x.fingerprint === fp);
  if (!k) throw new Error(`fingerprint ${fp} not in the public keyring`);
  return { key: crypto.createPublicKey(k.public_key_pem), status: k.status };
}

/** S + L, little-endian. Returns null when it would overflow 32 bytes. */
function malleate(sig) {
  const S = sig.subarray(32, 64);
  let s = 0n;
  for (let i = 31; i >= 0; i--) s = (s << 8n) | BigInt(S[i]);
  const s2 = s + L;
  if (s2 >= 2n ** 256n) return { canonical: s < L, mall: null };
  const out = Buffer.alloc(32);
  let t = s2;
  for (let i = 0; i < 32; i++) { out[i] = Number(t & 0xffn); t >>= 8n; }
  return { canonical: s < L, mall: Buffer.concat([sig.subarray(0, 32), out]) };
}

async function main() {
  let pass = 0, fail = 0;
  for (const w of WINDOWS) {
    const fileText = await getText(`${BASE}/${w}/stillos-commitment.json`);
    const sc = JSON.parse(await getText(`${BASE}/${w}/stillos-commitment.sig.json`));
    const digest = crypto.createHash('sha256').update(Buffer.from(fileText, 'utf8')).digest('hex');
    const digestOk = digest === sc.signed_file_sha256;

    const { key, status } = await keyByFingerprint(sc.key_fingerprint);
    // domain || 0x00 || ascii(sha256_hex) — the zero byte stops two domains
    // colliding by concatenation
    const msg = Buffer.concat([Buffer.from(sc.domain, 'utf8'), Buffer.from([0]),
                               Buffer.from(digest, 'ascii')]);
    const sig = Buffer.from(sc.signature, 'base64');

    const origOk = crypto.verify(null, msg, key, sig);          // POSITIVE CONTROL
    const { canonical, mall } = malleate(sig);
    const mallOk = mall ? crypto.verify(null, msg, key, mall) : null;

    const ok = digestOk && origOk && canonical && mallOk === false;
    if (ok) pass++; else fail++;
    console.log(`  ${ok ? 'ok  ' : 'FAIL'} ${w}  digest=${digestOk} original=${origOk} ` +
      `canonical_S=${canonical} malleated_accepted=${mall ? mallOk : 'n/a(overflow)'} key=${status}`);
  }
  console.log(`\n${pass} passed, ${fail} failed`);
  console.log('scope: S + L non-canonical form only — NOT every Ed25519 malleability class');
  console.log(pass && !fail
    ? 'RESULT: non-canonical S is rejected, so the signature bytes are a unique encoding'
    : 'RESULT: inconclusive or exposed — read the per-row output');
  process.exit(fail ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(2); });

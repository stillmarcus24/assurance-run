#!/usr/bin/env node
/**
 * Signer-set rotation — the second open item in the crypto profile's scope list
 * (tersignhq/evidence-record-conformance#11): *which key was authoritative at which
 * seq*. No vectors existed, so these are authored from a LIVE two-key rotation.
 *
 * Source material, all published and checkable:
 *   registry  https://stillosdigitalholdings.com/notary/keyring
 *             921e3af51250a1f5  retired  2026-06-27T08:39:51.304Z -> 2026-07-31T00:09:13.684Z
 *                               successor_fingerprint 21de066900082465
 *             21de066900082465  active   2026-07-31T00:09:13.684Z -> null
 *   records   969 real receipts under the retired key, 4,611 under the active key
 *   preimage  Ed25519 over ascii(receipt_hash), verified under BOTH keys
 *
 * THE RULE, half-open on purpose:
 *   a signature by key K over a record at time T is authoritative iff
 *     K verifies the signature  AND  K.effective_from <= T < K.effective_until
 *   with effective_until null meaning open-ended.
 *
 * WHY HALF-OPEN IS NORMATIVE AND NOT A STYLE CHOICE: in this live registry the
 * retired key's `effective_until` and the active key's `effective_from` are the SAME
 * INSTANT to the millisecond. Under an inclusive/inclusive reading BOTH keys are
 * authoritative at that instant, so one record could have two authoritative signers.
 * Vector rn3 pins exactly-one. A profile that leaves the interval convention implicit
 * inherits that ambiguity from any real rotation registry.
 *
 * AND ROTATION MUST NOT INVALIDATE HISTORY: rp1 is a real receipt signed by the now
 * retired key, and it must stay valid forever. A verifier that only accepts the
 * currently-active key fails it — that is the most likely wrong implementation.
 */
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const REASONS = Object.freeze({
  SIGNATURE_INVALID: 'signature_invalid',
  NOT_IN_REGISTRY: 'signer_not_in_registry',
  NOT_YET: 'signer_not_yet_authoritative',
  NO_LONGER: 'signer_not_authoritative_at_time',
  SUCCESSOR_UNNAMED: 'successor_not_named_by_predecessor',
});

/** @returns {{verdict:'valid'|'reject', reason:string|null}} */
function check({ registry, fingerprint, receipt_hash, signature, at, claims_successor_of }) {
  const key = registry.find((k) => k.fingerprint === fingerprint);
  if (!key) return { verdict: 'reject', reason: REASONS.NOT_IN_REGISTRY };

  // succession is checked against the PREDECESSOR's own record, never the claimant's
  if (claims_successor_of) {
    const pred = registry.find((k) => k.fingerprint === claims_successor_of);
    if (!pred || pred.successor_fingerprint !== fingerprint) {
      return { verdict: 'reject', reason: REASONS.SUCCESSOR_UNNAMED };
    }
  }

  // cryptography before policy: an unauthoritative-but-valid signature and an
  // authoritative-but-forged one are different failures and must not be conflated
  let sigOk = false;
  try {
    sigOk = crypto.verify(null, Buffer.from(receipt_hash, 'ascii'),
      crypto.createPublicKey(key.public_key_pem), Buffer.from(signature, 'base64'));
  } catch (e) { sigOk = false; }
  if (!sigOk) return { verdict: 'reject', reason: REASONS.SIGNATURE_INVALID };

  const t = Date.parse(at);
  if (t < Date.parse(key.effective_from)) return { verdict: 'reject', reason: REASONS.NOT_YET };
  // half-open: `< effective_until`, never `<=`
  if (key.effective_until !== null && t >= Date.parse(key.effective_until)) {
    return { verdict: 'reject', reason: REASONS.NO_LONGER };
  }
  return { verdict: 'valid', reason: null };
}

/** How many registry keys are authoritative at an instant. Must never exceed 1. */
function authoritativeAt(registry, at) {
  const t = Date.parse(at);
  return registry.filter((k) => t >= Date.parse(k.effective_from) &&
    (k.effective_until === null || t < Date.parse(k.effective_until)));
}

// ---------------------------------------------------------------- mutants
// Plausible wrong implementations. Each must be killed by a named vector, or the
// suite is not discriminating.
const MUTANTS = {
  'accepts-only-the-active-key': (a) => {
    const k = a.registry.find((x) => x.fingerprint === a.fingerprint);
    if (!k || k.status !== 'active') return { verdict: 'reject', reason: REASONS.NO_LONGER };
    return check(a);
  },
  'ignores-time-entirely': (a) => {
    const k = a.registry.find((x) => x.fingerprint === a.fingerprint);
    if (!k) return { verdict: 'reject', reason: REASONS.NOT_IN_REGISTRY };
    return { verdict: 'valid', reason: null };
  },
  'inclusive-interval': (a) => {
    const k = a.registry.find((x) => x.fingerprint === a.fingerprint);
    if (!k) return { verdict: 'reject', reason: REASONS.NOT_IN_REGISTRY };
    const t = Date.parse(a.at);
    if (t < Date.parse(k.effective_from)) return { verdict: 'reject', reason: REASONS.NOT_YET };
    if (k.effective_until !== null && t > Date.parse(k.effective_until)) {
      return { verdict: 'reject', reason: REASONS.NO_LONGER };
    }
    return { verdict: 'valid', reason: null };
  },
  'trusts-the-claimant-on-succession': (a) => check({ ...a, claims_successor_of: null }),
  'policy-before-crypto': (a) => {
    const k = a.registry.find((x) => x.fingerprint === a.fingerprint);
    if (!k) return { verdict: 'reject', reason: REASONS.NOT_IN_REGISTRY };
    const t = Date.parse(a.at);
    if (t < Date.parse(k.effective_from)) return { verdict: 'reject', reason: REASONS.NOT_YET };
    if (k.effective_until !== null && t >= Date.parse(k.effective_until)) {
      return { verdict: 'reject', reason: REASONS.NO_LONGER };
    }
    return { verdict: 'valid', reason: null }; // never checks the signature
  },
};

function main() {
  const V = JSON.parse(fs.readFileSync(path.join(__dirname, 'rotation-vectors.json'), 'utf8'));
  const reg = V.registry;
  let pass = 0, fail = 0;
  const say = (ok, name, extra) => {
    if (ok) { pass++; console.log(`  ok   ${name}`); }
    else { fail++; console.log(`  FAIL ${name}${extra ? '  — ' + extra : ''}`); }
  };

  for (const v of V.vectors) {
    if (v.kind === 'exactly_one_authoritative') {
      const n = authoritativeAt(reg, v.input.at).length;
      say(n === v.expect_count, `${v.id} -> exactly ${v.expect_count} authoritative at the boundary`,
        `got ${n}`);
      continue;
    }
    const got = check({ registry: reg, ...v.input });
    say(got.verdict === v.expect && (got.reason || null) === (v.reject_reason || null),
      `${v.id} -> ${v.expect}${v.reject_reason ? '/' + v.reject_reason : ''}`,
      `got ${got.verdict}${got.reason ? '/' + got.reason : ''}`);
  }

  console.log('\n  mutants (each must be killed by at least one vector):');
  for (const [name, fn] of Object.entries(MUTANTS)) {
    const killers = V.vectors.filter((v) => {
      if (v.kind === 'exactly_one_authoritative') {
        // a mutant with the wrong interval convention must be caught HERE too, not
        // only incidentally by an unrelated vector
        const n = reg.filter((k) => {
          const t = Date.parse(v.input.at);
          const g = fn({ registry: reg, fingerprint: k.fingerprint, receipt_hash: 'x',
            signature: '', at: v.input.at });
          return g.verdict === 'valid' || g.reason === REASONS.SIGNATURE_INVALID;
        }).length;
        return n !== v.expect_count;
      }
      let g; try { g = fn({ registry: reg, ...v.input }); } catch (e) { return true; }
      return g.verdict !== v.expect || (g.reason || null) !== (v.reject_reason || null);
    }).map((v) => v.id);
    say(killers.length > 0, `  ${name} killed by ${killers.join(', ') || 'NOTHING'}`);
  }

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
}

if (require.main === module) main();
module.exports = { check, authoritativeAt, REASONS };

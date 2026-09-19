#!/usr/bin/env node
'use strict';
/**
 * verify-verdict — check a signed live-claim-audit verdict without trusting us.
 *
 *   node verify-verdict.cjs verdicts/<file>.json [path/to/signing.pub]
 *
 * Recomputes the canonical digest from the payload and checks the Ed25519
 * signature against the published public key (`verdicts/signing.pub`). The key
 * is in the repo on purpose: a signed artifact whose key nobody holds is a
 * commitment only its author can check, which is not a commitment.
 *
 * What this proves: the findings were not edited after signing.
 * What it does NOT prove: that the findings were true of the target. That is
 * settled by re-running the audit against the same target, which is the point
 * of publishing the tool alongside the verdict.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const K = require('./kernel.cjs');

const file = process.argv[2];
const pubFile = process.argv[3] || path.join(__dirname, 'verdicts', 'signing.pub');
if (!file) { console.error('usage: verify-verdict.cjs <verdict.json> [signing.pub]'); process.exit(2); }

const v = JSON.parse(fs.readFileSync(file, 'utf8'));
const digest = K.sha256(K.canonical(v.payload));
const digestOk = digest === v.digest;

let sigOk = false, keyErr = null;
try {
  const pub = crypto.createPublicKey(fs.readFileSync(pubFile, 'utf8'));
  sigOk = crypto.verify(null, Buffer.from(digest), pub, Buffer.from(v.signature, 'base64'));
} catch (e) { keyErr = K.classifyFault(e); }

const p = v.payload;
console.log('\n  verdict      ' + file);
console.log('  target       ' + p.target);
console.log('  observed_at  ' + p.observed_at);
console.log('  tool         ' + p.tool + '  kernel ' + p.kernel);
console.log('  digest       ' + (digestOk ? 'MATCH   ' + digest : 'MISMATCH\n               stated  ' + v.digest + '\n               computed ' + digest));
console.log('  signature    ' + (keyErr ? 'NOT CHECKED (' + keyErr.kind + ') — ' + keyErr.detail
  : sigOk ? 'VALID (' + (v.algorithm || 'ed25519') + ')' : 'INVALID'));
console.log('  counts       ' + JSON.stringify(p.counts));
console.log('  not established by this run: ' + p.not_established +
  ' of ' + p.findings.length + ' findings\n');

for (const f of p.findings) {
  if (f.verdict === 'DISAGREE') console.log('  !! ' + f.reason + ' — ' + f.claim);
}
console.log();

// A key we could not load is NOT a failed signature. Reporting "INVALID" for a
// missing file is the same collapse this corpus exists to prohibit.
if (keyErr) process.exit(2);
process.exit(digestOk && sigOk ? 0 : 1);

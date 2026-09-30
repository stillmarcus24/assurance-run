/**
 * A pre-commitment, produced by the SAME seal()/canonicalJson() already running the
 * MCP joint-window series — not a new implementation and not a proposal.
 *
 * Why a runner pre-commitment rather than a result commitment: the open scope items
 * (EIP-712 payload signatures, signer rotation) have no vectors yet, so there is no
 * result to commit to. What CAN be committed now is the verifier's own bytes, which
 * makes "the runner was not tuned to the vectors after seeing them" checkable rather
 * than asserted. Same reason the sweep collects execution provenance BEFORE its walk.
 */
const crypto=require('crypto'), fs=require('fs'), path=require('path');
const { canonicalJson, seal, sha256 } = require('/home/marcus/core/joint_window_sweep.cjs');

const RUNNER='verify_crypto.cjs';
const runnerBytes=fs.readFileSync(path.join(__dirname,RUNNER));
const vectorFiles=fs.readdirSync(path.join(__dirname,'vectors')).filter(f=>f.endsWith('.json')).sort();

const body={
  profile: 'evidence-record-conformance/crypto',
  role: 'independent second runner',
  participant: 'stillos',
  // what is being committed: the verifier bytes, the method, and the vector set it
  // has SEEN. Anything it has not seen is named so a later reveal is checkable.
  runner_file: RUNNER,
  runner_sha256: sha256(runnerBytes),
  language: 'node',
  dependencies_in_verification_path: ['viem'],   // not stdlib-pure; stated, not implied
  method: [
    'link = keccak256(artifact_digest || prev_digest or 32 zero bytes || seq_uint64_be)',
    'signature must be 65 bytes r||s||v with v in {27,28}',
    'low-s (EIP-2) checked BEFORE recovery',
    'EIP-191 personal_sign recovery over the 32 link bytes must equal ledger_signer',
  ],
  vectors_already_seen: vectorFiles,
  vectors_already_seen_sha256: sha256(Buffer.concat(vectorFiles.map(f=>fs.readFileSync(path.join(__dirname,'vectors',f))))),
  scope_not_yet_seen: ['EIP-712 typed-data counter-signatures','signer-set rotation across seq'],
  source_files_never_read: ['crypto/verify_crypto.py','crypto/secp256k1_recover.py'],
  claim: 'when vectors for scope_not_yet_seen are published, a run produced by runner_sha256 (or a declared descendant) was written before those vectors existed',
};

const s=seal(body);
const out={
  commitment_scheme: 'sha256(nonce_hex || canonical_json(record_body))',
  commitment_sha256: s.commitment_sha256,
  record_sha256: s.record_sha256,
  note: 'Publish this digest alone. The record body and nonce are revealed only after every participant has published a commitment.',
};
fs.writeFileSync('precommitment.json', JSON.stringify(out,null,2)+'\n');
fs.writeFileSync('.reveal-private.json', JSON.stringify({nonce:s.nonce, body},null,2)+'\n');

// prove the commitment is sound the same way the series does
const recompute = sha256(Buffer.from(s.nonce + canonicalJson(body),'utf8'));
const tampered  = sha256(Buffer.from(s.nonce + canonicalJson({...body, language:'python'}),'utf8'));
console.log('commitment_sha256 :', s.commitment_sha256);
console.log('record_sha256     :', s.record_sha256);
console.log('recomputes        :', recompute===s.commitment_sha256);
console.log('one edited field breaks it:', tampered!==s.commitment_sha256);
console.log('nonce bytes       :', s.nonce.length/2);

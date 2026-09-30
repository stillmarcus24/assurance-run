// Author the rotation vectors from LIVE material — read, never transcribed.
const fs=require('fs');
const KR='/tmp/kr2.json';
const R='/home/marcus/still-os-consciousness/state/proof-notary/receipts.jsonl';
const kr=JSON.parse(fs.readFileSync(KR,'utf8'));
const reg=kr.keys.map(k=>({fingerprint:k.fingerprint,public_key_pem:k.public_key_pem,status:k.status,
  effective_from:k.effective_from,effective_until:k.effective_until,successor_fingerprint:k.successor_fingerprint}));
const rows=fs.readFileSync(R,'utf8').trim().split('\n').map(l=>{try{return JSON.parse(l)}catch(e){return null}}).filter(Boolean);
const pick=fp=>rows.find(r=>r.notary_fp===fp);
const old=pick('921e3af51250a1f5'), cur=pick('21de066900082465'), tst=pick('fp_test');
const retired=reg.find(k=>k.status==='retired'), active=reg.find(k=>k.status==='active');
const BOUNDARY=retired.effective_until;

const V={
  _spec:'signer-set rotation vectors for the evidence-record crypto profile',
  _why:'Second open item in the crypto profile scope list (tersignhq/evidence-record-conformance#11): which key was authoritative at which seq. No vectors existed.',
  _rule:'valid iff the key verifies the signature AND effective_from <= t < effective_until (half-open; null until = open-ended)',
  _material:'live two-key rotation: 969 real receipts under the retired key, 4611 under the active key; Ed25519 over ascii(receipt_hash)',
  _boundary_finding:`retired.effective_until == active.effective_from == ${BOUNDARY} — identical to the millisecond, so an inclusive reading makes BOTH keys authoritative at that instant`,
  registry:reg,
  vectors:[
   {id:'rp1-retired-key-historical-record-stays-valid',expect:'valid',
    description:'A REAL receipt signed by the now-retired key, at a time inside its window. Rotation must not invalidate history. A verifier that only accepts the active key fails here.',
    input:{fingerprint:old.notary_fp,receipt_hash:old.receipt_hash,signature:old.signature,at:old.ts}},
   {id:'rp2-active-key-inside-window',expect:'valid',
    description:'A REAL receipt signed by the active key, at a time inside its window.',
    input:{fingerprint:cur.notary_fp,receipt_hash:cur.receipt_hash,signature:cur.signature,at:cur.ts}},
   {id:'rn1-retired-key-after-effective-until',expect:'reject',reject_reason:'signer_not_authoritative_at_time',
    description:'The same real retired-key signature, evaluated at a time after its effective_until. The signature is cryptographically fine; the key was no longer authoritative.',
    input:{fingerprint:old.notary_fp,receipt_hash:old.receipt_hash,signature:old.signature,at:'2026-08-15T00:00:00.000Z'}},
   {id:'rn2-active-key-before-effective-from',expect:'reject',reject_reason:'signer_not_yet_authoritative',
    description:'The real active-key signature evaluated before its effective_from. Pins the other side of the interval.',
    input:{fingerprint:cur.notary_fp,receipt_hash:cur.receipt_hash,signature:cur.signature,at:'2026-07-01T00:00:00.000Z'}},
   {id:'rn3-boundary-instant-exactly-one-authoritative',kind:'exactly_one_authoritative',expect_count:1,
    description:`At ${BOUNDARY} the retired key's effective_until and the active key's effective_from are the same instant. Half-open yields exactly one authoritative key; inclusive/inclusive yields two.`,
    input:{at:BOUNDARY}},
   {id:'rn4-signer-absent-from-the-published-registry',expect:'reject',reject_reason:'signer_not_in_registry',
    description:'A REAL production receipt whose notary_fp is not in the published keyring at all (fp_test, 2 rows, carried authoritative:false). A rotation-aware verifier must reject it rather than treat an unknown signer as an old one.',
    input:{fingerprint:tst.notary_fp,receipt_hash:tst.receipt_hash,signature:tst.signature,at:tst.ts}},
   {id:'rn6-retired-key-AT-the-boundary-instant',expect:'reject',reject_reason:'signer_not_authoritative_at_time',
    description:'The real retired-key signature evaluated at EXACTLY effective_until. Half-open rejects it; an inclusive reading accepts it. This is the vector that kills the inclusive-interval implementation through the normal check path rather than incidentally.',
    input:{fingerprint:old.notary_fp,receipt_hash:old.receipt_hash,signature:old.signature,at:BOUNDARY}},
   {id:'rn7-active-key-AT-the-boundary-instant',expect:'valid',
    description:'The mirror of rn6: at exactly that instant the ACTIVE key IS authoritative, because effective_from is inclusive. rn6 and rn7 together pin the convention as [from, until) rather than merely asserting it.',
    input:{fingerprint:cur.notary_fp,receipt_hash:cur.receipt_hash,signature:cur.signature,at:BOUNDARY}},
   {id:'rn5-successor-not-named-by-predecessor',expect:'reject',reject_reason:'successor_not_named_by_predecessor',
    description:'The retired key claiming to be the successor of the active key. Succession must be read from the predecessor\'s own record, never from the claimant.',
    input:{fingerprint:retired.fingerprint,receipt_hash:old.receipt_hash,signature:old.signature,at:old.ts,
           claims_successor_of:active.fingerprint}},
  ],
};
fs.writeFileSync('rotation-vectors.json',JSON.stringify(V,null,2)+'\n');
console.log(V.vectors.length,'vectors written');
console.log('boundary:',BOUNDARY);

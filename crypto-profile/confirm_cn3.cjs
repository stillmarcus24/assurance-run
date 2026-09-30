// Independently confirm babyblueviper1's central claim: the malleated signature
// recovers to the SAME ledger signer, so an address-only verifier accepts it and
// one link admits two distinct signature byte strings.
const fs=require('fs');
const { keccak256, recoverAddress, hashMessage } = require('viem');
const N=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const hb=h=>Buffer.from(String(h).replace(/^0x/,''),'hex');
const bh=b=>'0x'+Buffer.from(b).toString('hex');
function link({artifact_digest,prev_digest,seq}){
  const s=Buffer.alloc(8); s.writeBigUInt64BE(BigInt(seq));
  return keccak256(bh(Buffer.concat([hb(artifact_digest),
    prev_digest==null?Buffer.alloc(32):hb(prev_digest), s])));
}
(async()=>{
 const cp1=JSON.parse(fs.readFileSync('vectors/cp1-live-genesis-link-countersignature.json','utf8')).input;
 const cn3=JSON.parse(fs.readFileSync('vectors/cn3-high-s-malleated-live-signature.json','utf8')).input;
 const L1=link(cp1), L3=link(cn3);
 console.log('cp1 link == cn3 link (same link, two signatures):', L1===L3);
 console.log('link:',L1);
 const a1=await recoverAddress({hash:hashMessage({raw:L1}),signature:cp1.countersignature});
 const a3=await recoverAddress({hash:hashMessage({raw:L3}),signature:cn3.countersignature});
 console.log();
 console.log('cp1 recovers to        :',a1);
 console.log('pinned ledger_signer   :',cp1.ledger_signer);
 console.log('MATCH                  :',a1.toLowerCase()===cp1.ledger_signer.toLowerCase());
 console.log();
 console.log('cn3 (malleated) recovers to:',a3);
 console.log('SAME SIGNER as cp1         :',a3.toLowerCase()===a1.toLowerCase());
 console.log('signature bytes differ     :',cp1.countersignature!==cn3.countersignature);
 const s1=BigInt('0x'+hb(cp1.countersignature).subarray(32,64).toString('hex'));
 const s3=BigInt('0x'+hb(cn3.countersignature).subarray(32,64).toString('hex'));
 console.log();
 console.log('cp1 s low-s (s <= n/2) :', s1<=N/2n);
 console.log('cn3 s low-s            :', s3<=N/2n);
 console.log('s1 + s3 == n           :', s1+s3===N, ' <- confirms s3 = n - s1');
 console.log('v flipped              :', hb(cp1.countersignature)[64], '->', hb(cn3.countersignature)[64]);
 console.log();
 console.log(a3.toLowerCase()===a1.toLowerCase()
  ? 'CONFIRMED: an address-only verifier accepts BOTH byte strings for one link.'
  : 'NOT CONFIRMED');
})();

// Sign the pre-commitment using the SAME signer module and domain-separation scheme
// the joint-window series uses. The key is resolved by the existing loader, not by
// path guessing, and the fingerprint must resolve in the PUBLIC keyring.
const crypto=require('crypto'), fs=require('fs');
const signer=require('/home/marcus/core/notary_recovery_signer.cjs');
const DOMAIN='evidence-record-conformance/crypto/v1/precommitment';
const bytes=fs.readFileSync('precommitment.json');
const digest=crypto.createHash('sha256').update(bytes).digest('hex');
// domain || 0x00 || ascii(sha256_hex) — zero byte so domains cannot collide by concat
const msg=Buffer.concat([Buffer.from(DOMAIN,'utf8'),Buffer.from([0]),Buffer.from(digest,'ascii')]);
const { privateKey, notary_fp } = signer.loadPrivateKey();
const sig=crypto.sign(null,msg,privateKey);
const pub=crypto.createPublicKey(privateKey);
const selfOk=crypto.verify(null,msg,pub,sig);
// a signature under the wrong domain must NOT verify — proves separation is real
const wrong=Buffer.concat([Buffer.from('mcpship-stillos-joint-window/v1/commitment','utf8'),Buffer.from([0]),Buffer.from(digest,'ascii')]);
const crossOk=crypto.verify(null,wrong,pub,sig);
fs.writeFileSync('precommitment.sig.json', JSON.stringify({
  alg:'ed25519', signed_file:'precommitment.json', signed_file_sha256:digest,
  domain:DOMAIN, key_fingerprint:notary_fp,
  signing_keys_url:'https://stillosdigitalholdings.com/notary/keyring',
  signature:sig.toString('base64'),
  proves:'the holder of this key produced these exact bytes — NOT that the claim inside is true'
},null,2)+'\n');
console.log('fingerprint          :',notary_fp);
console.log('self-verifies        :',selfOk);
console.log('cross-domain replay  :',crossOk,'(must be false)');

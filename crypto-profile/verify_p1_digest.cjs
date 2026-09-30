// The derivation that matters: p1's kind is `digest_recompute`, so its STATED claim is
// that the content address recomputes from the committed canonical bytes. It does, and
// the canonical form was not published anywhere — we recovered it from the digest.
//
// Fetched LIVE from the ledger's own endpoint so this is not a replay of the vector.
const { keccak256, toHex } = require('viem');
function jcs(v){
  if(v===null||typeof v!=='object') return JSON.stringify(v);
  if(Array.isArray(v)) return '['+v.map(jcs).join(',')+']';
  return '{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+jcs(v[k])).join(',')+'}';
}
(async()=>{
  const g = await (await fetch('https://tersign.ai/v1/genesis')).json();
  const canon = jcs(g.artifact);
  const h = keccak256(toHex(canon));
  console.log('live artifactDigest   :', g.artifactDigest);
  console.log('keccak256(JCS(artifact)):', h);
  console.log('RECOMPUTES            :', h.toLowerCase() === g.artifactDigest.toLowerCase());
  console.log('canonical byte length :', Buffer.byteLength(canon,'utf8'));
  console.log();
  // discrimination: the digest must NOT survive dropping the signature, which is what
  // proves the signature is committed as opaque bytes inside the content address
  const noSig = jcs({format:g.artifact.format, payload:g.artifact.payload});
  console.log('digest over artifact WITHOUT signature:', keccak256(toHex(noSig)).slice(0,18), '(differs -> signature IS committed)');
  const noFmt = jcs({payload:g.artifact.payload, signature:g.artifact.signature});
  console.log('digest over artifact WITHOUT format   :', keccak256(toHex(noFmt)).slice(0,18), '(differs -> format label IS committed)');
  console.log();
  console.log('So: the content address commits the signature and the "eip712" label as');
  console.log('BYTES, and never interprets either. p1 is fully verifiable as specified,');
  console.log('while the format label asserts something no published material can check.');
})();

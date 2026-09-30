// Use the KNOWN digest as an oracle. p1 is kind=digest_recompute/expect=valid, so
// 0xe5874f1f... must be keccak256 over some canonical serialisation of published bytes.
// Find that form and the signing preimage follows from it.
const { keccak256, toHex } = require('viem');
const TARGET='0xe5874f1ffe87f0a6dd9eb157730f67b86ee4538b125fe30fcc4e165213dd3fc4';
const artifact={format:'eip712',payload:{issuedAt:1783761710,network:'eip155:8453',
 payer:'0x36f82906859E5B0bd076069f8cdfAea355358b14',
 resourceUrl:'https://tersign-ledger.kevinn-zhang.workers.dev/v1/receipts/genesis/demo',
 transaction:'',version:1},
 signature:'0x88e3f596dc8e6e5f2aeac45b45eac4484c09e2f58a2b787c73469e5927706b18341c362491ecdc0df8764831b07f499210523eb11200bacf340869f50a4c46e81b'};

// JCS-style canonical JSON: keys sorted by code point, no whitespace
function jcs(v){
  if(v===null||typeof v!=='object') return JSON.stringify(v);
  if(Array.isArray(v)) return '['+v.map(jcs).join(',')+']';
  return '{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+jcs(v[k])).join(',')+'}';
}
const cands={};
cands['jcs(whole artifact)']            = jcs(artifact);
cands['jcs(payload only)']              = jcs(artifact.payload);
cands['jcs({payload,signature})']       = jcs({payload:artifact.payload,signature:artifact.signature});
cands['jcs({format,payload})']          = jcs({format:artifact.format,payload:artifact.payload});
cands['JSON.stringify(artifact)']       = JSON.stringify(artifact);
cands['JSON.stringify(payload)']        = JSON.stringify(artifact.payload);
cands['jcs(artifact)+newline']          = jcs(artifact)+'\n';
cands['jcs(payload)+newline']           = jcs(artifact.payload)+'\n';
// field-order-as-published (insertion order) rather than sorted
const ins=(o)=>'{'+Object.entries(o).map(([k,v])=>JSON.stringify(k)+':'+(typeof v==='object'&&v!==null?ins(v):JSON.stringify(v))).join(',')+'}';
cands['insertion-order(artifact)']      = ins(artifact);
cands['insertion-order(payload)']       = ins(artifact.payload);

let hit=null;
for(const [label,s] of Object.entries(cands)){
  const h=keccak256(toHex(s));
  if(h.toLowerCase()===TARGET.toLowerCase()){ hit=label; }
  console.log((h.toLowerCase()===TARGET.toLowerCase()?'MATCH  ':'       ')+label.padEnd(30)+h.slice(0,18));
}
console.log('\n'+(hit?`DERIVED: the canonical form is ${hit}`:'no match yet among these forms'));

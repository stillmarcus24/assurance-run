// Don't guess the construction — recover the address for many preimages and see who
// appears. A construction that yields an address occurring elsewhere in their
// published data identifies itself.
const { keccak256, toHex, recoverAddress, hashMessage, recoverTypedDataAddress } = require('viem');
const P={issuedAt:1783761710,network:'eip155:8453',payer:'0x36f82906859E5B0bd076069f8cdfAea355358b14',
 resourceUrl:'https://tersign-ledger.kevinn-zhang.workers.dev/v1/receipts/genesis/demo',transaction:'',version:1};
const SIG='0x88e3f596dc8e6e5f2aeac45b45eac4484c09e2f58a2b787c73469e5927706b18341c362491ecdc0df8764831b07f499210523eb11200bacf340869f50a4c46e81b';
const ART={format:'eip712',payload:P,signature:SIG};
const DIGEST='0xe5874f1ffe87f0a6dd9eb157730f67b86ee4538b125fe30fcc4e165213dd3fc4';
function jcs(v){if(v===null||typeof v!=='object')return JSON.stringify(v);
 if(Array.isArray(v))return '['+v.map(jcs).join(',')+']';
 return '{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+jcs(v[k])).join(',')+'}';}
const KNOWN={
 '0x36f82906859e5b0bd076069f8cdfaea355358b14':'payer (published)',
 '0x9d38ba84730271eb27ac9bd4bd2620c08db4fda6':'ledger_signer (published)',
};
(async()=>{
 const cands=[];
 const add=(l,h)=>cands.push([l,h]);
 add('personal_sign(jcs(payload))', hashMessage(jcs(P)));
 add('personal_sign(JSON(payload))', hashMessage(JSON.stringify(P)));
 add('personal_sign(jcs(artifact-without-sig))', hashMessage(jcs({format:'eip712',payload:P})));
 add('personal_sign(digest hex string)', hashMessage(DIGEST));
 add('personal_sign(digest raw 32B)', hashMessage({raw:DIGEST}));
 add('raw keccak(jcs(payload))', keccak256(toHex(jcs(P))));
 add('raw keccak(JSON(payload))', keccak256(toHex(JSON.stringify(P))));
 add('raw digest itself', DIGEST);
 add('personal_sign(resourceUrl)', hashMessage(P.resourceUrl));
 const out={};
 for(const [label,h] of cands){
   try{ const a=(await recoverAddress({hash:h,signature:SIG})).toLowerCase();
        out[label]=a; }catch(e){ out[label]='<unrecoverable>'; }
 }
 // EIP-712 with the USDC domain (x402 exact scheme signs against the token contract)
 const usdc='0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
 for(const [dn,dv,vc] of [['USD Coin','2',usdc],['tersign','1',undefined],['x402','1',undefined]]){
   for(const pt of ['Receipt','PaymentPayload','Payment']){
     const types={[pt]:[{name:'issuedAt',type:'uint256'},{name:'network',type:'string'},
       {name:'payer',type:'address'},{name:'resourceUrl',type:'string'},
       {name:'transaction',type:'string'},{name:'version',type:'uint256'}]};
     const domain=vc?{name:dn,version:dv,chainId:8453,verifyingContract:vc}:{name:dn,version:dv,chainId:8453};
     try{ const a=(await recoverTypedDataAddress({domain,types,primaryType:pt,
            message:{...P,issuedAt:BigInt(P.issuedAt),version:BigInt(P.version)},signature:SIG})).toLowerCase();
          out[`eip712 ${dn}/${dv}${vc?'+vc':''} ${pt}`]=a; }catch(e){}
   }
 }
 const hits=[];
 for(const [l,a] of Object.entries(out)){
   const k=KNOWN[a];
   console.log((k?'HIT  ':'     ')+l.padEnd(42)+a+(k?'  <- '+k:''));
   if(k) hits.push(l);
 }
 console.log('\ndistinct addresses recovered:',new Set(Object.values(out)).size);
 console.log(hits.length?`IDENTIFIED: ${hits.join(', ')}`:'no construction recovers to a published address');
})();

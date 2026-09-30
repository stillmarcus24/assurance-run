// Can a second implementer verify p1's EIP-712 payload signature from PUBLISHED
// material alone? The domain and type definitions appear nowhere, so try the
// plausible constructions and see whether any recovers to the published payer.
const { recoverTypedDataAddress } = require('viem');
const P={issuedAt:1783761710n,network:'eip155:8453',payer:'0x36f82906859E5B0bd076069f8cdfAea355358b14',
  resourceUrl:'https://tersign-ledger.kevinn-zhang.workers.dev/v1/receipts/genesis/demo',transaction:'',version:1n};
const SIG='0x88e3f596dc8e6e5f2aeac45b45eac4484c09e2f58a2b787c73469e5927706b18341c362491ecdc0df8764831b07f499210523eb11200bacf340869f50a4c46e81b';
const WANT=P.payer.toLowerCase();
const LEDGER='0x9d38ba84730271eb27ac9bd4bd2620c08db4fda6';

const names=['tersign','Tersign','tersign-ledger','x402','Receipt','tersign.ai'];
const versions=['1','0','1.0','v1'];
const chainIds=[8453,1,0];
const typeNames=['Receipt','Payment','PaymentPayload','Payload','Offer','ExactPayment'];
// field orders: as-published (alphabetical) and a payment-natural order
const orders=[
  ['issuedAt','network','payer','resourceUrl','transaction','version'],
  ['payer','resourceUrl','network','issuedAt','transaction','version'],
  ['version','network','payer','resourceUrl','issuedAt','transaction'],
];
const tmap={issuedAt:'uint256',network:'string',payer:'address',resourceUrl:'string',transaction:'string',version:'uint256'};
const tmapAlt={issuedAt:'uint64',network:'string',payer:'address',resourceUrl:'string',transaction:'string',version:'uint8'};

(async()=>{
 let tried=0, hits=[];
 for(const name of names) for(const version of versions) for(const chainId of chainIds)
 for(const tn of typeNames) for(const ord of orders) for(const tm of [tmap,tmapAlt]){
   for(const withChain of [true,false]){
     const domain = withChain ? {name,version,chainId} : {name,version};
     const types={[tn]: ord.map(f=>({name:f,type:tm[f]}))};
     const message={}; for(const f of ord) message[f]=P[f];
     tried++;
     try{
       const a=await recoverTypedDataAddress({domain,types,primaryType:tn,message,signature:SIG});
       const al=a.toLowerCase();
       if(al===WANT||al===LEDGER) hits.push({who:al===WANT?'PAYER':'LEDGER',name,version,chainId:withChain?chainId:null,primaryType:tn,order:ord.join(','),types:tm===tmap?'uint256':'uint64/uint8'});
     }catch(e){}
   }
 }
 console.log('constructions tried:',tried);
 console.log('recovered to the published payer or ledger signer:',hits.length);
 hits.forEach(h=>console.log('  ',JSON.stringify(h)));
 if(!hits.length) console.log('\nNONE. The payload signature is NOT verifiable from published material.');
})();

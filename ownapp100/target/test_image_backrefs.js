import fs from 'fs';
const p='C:/Users/pasha/OneDrive/Desktop/STANDOFF_1_0_DUMP_WORK/ownapp100/target/libunity.runtime.current.so';
const b=fs.readFileSync(p);
const maps=[
{s:0x6fe303e000n,e:0x6fe839a000n,o:0n},
{s:0x6fe839d000n,e:0x6fee8c1000n,o:0x535b000n},
{s:0x6fee8c4000n,e:0x6feef42000n,o:0xb87e000n},
{s:0x6feef45000n,e:0x6fef4ab000n,o:0xbefb000n}
];
function fo(a){a=BigInt(a);for(const m of maps)if(a>=m.s&&a<m.e)return Number(m.o+a-m.s);return -1}
function addr(x){for(const m of maps){let n=BigInt(x);if(n>=m.o&&n<m.o+BigInt(Number(m.e-m.s)))return m.s+(n-m.o)}return null}
function str(off){let i=off;while(i<b.length&&b[i]>=32&&b[i]<127)i++;return b.toString('ascii',off,i)}
const dll=[];
for(let i=0;i+4<b.length;i++){if(b[i]!==46||b[i+1]!==100||b[i+2]!==108||b[i+3]!==108)continue;let j=i;while(j>0&&b[j-1]>=32&&b[j-1]<127&&i-j<160)j--;let s=str(j),a=addr(j);if(a&&s.endsWith('.dll'))dll.push({s,a})}
const set=new Map(dll.map(x=>[x.a.toString(),x]));
const hits=[];
for(const m of maps.filter(x=>x.o>=0)){
 let start=Number(m.o),end=Math.min(b.length,start+Number(m.e-m.s));
 for(let o=start;o+136<=end;o+=8){
   const q=[];for(let k=0;k<17;k++)q.push(b.readBigUInt64LE(o+k*8));
   const n=set.get(q[0].toString());if(!n||!q[2])continue;
   const q2fo=fo(q[2]); if(q2fo<0||q2fo+8>b.length)continue;
   const back=b.readBigUInt64LE(q2fo);
   const q8=q[8], q8fo=q8?fo(q8):-1;
   hits.push({o,n:n.s,back,addr:addr(BigInt(o)),q,q8fo});
   if(back===addr(BigInt(o)))console.log('BACKREF',n.s,'rec=0x'+addr(BigInt(o)).toString(16),'assembly=0x'+q[2].toString(16),'q8=0x'+q8.toString(16));
 }
}
console.log('TOTAL',hits.length,'backref candidates',hits.filter(x=>x.back===x.addr).length);

import fs from 'fs';
const b=fs.readFileSync('C:/Users/pasha/OneDrive/Desktop/STANDOFF_1_0_DUMP_WORK/ownapp100/target/libunity.runtime.current.so');
const maps=[
{s:0x6fe303e000n,o:0n,e:0x6fe839a000n},
{s:0x6fe839d000n,o:0x535b000n,e:0x6fee8c1000n},
{s:0x6fee8c4000n,o:0xb87e000n,e:0x6feef42000n},
{s:0x6feef45000n,o:0xbefb000n,e:0x6fef4ab000n}
];
function raddr(fo){for(const m of maps){const x=BigInt(fo);if(x>=m.o&&x<m.o+BigInt(Number(m.e-m.s)))return m.s+x-m.o;}return 0n;}
function fof(a){const x=BigInt(a);for(const m of maps)if(x>=m.s&&x<m.e)return Number(m.o+x-m.s);return -1;}
function readu(fo){return b.readBigUInt64LE(fo);}
function ascii(fo){let i=fo;while(i<b.length&&b[i]>=32&&b[i]<127)i++;return b.toString('ascii',fo,i);}
const dll=[];
for(let i=0;i<0x535b000;i++){if(b[i]===46&&b[i+1]===100&&b[i+2]===108&&b[i+3]===108){let j=i;while(j>0&&b[j-1]>=32&&b[j-1]<127&&i-j<160)j--;let s=ascii(j);if(s.endsWith('.dll'))dll.push({a:raddr(j),s,fo:j});}}
const byAddr=new Map(dll.map(x=>[x.a.toString(),x]));
let found=0;
const start=0xb87e000,end=0xbefb000;
for(let fo=start;fo+88<end;fo+=8){
 const n=byAddr.get(readu(fo).toString()); if(!n)continue;
 const a=raddr(fo), q2=readu(fo+16), q2fo=fof(q2);
 if(q2fo<0)continue;
 const back=readu(q2fo);
 if(back===a){
   console.log('IMAGE_BACKREF name='+n.s+' rec=0x'+a.toString(16)+' fo=0x'+fo.toString(16)+' q2=0x'+q2.toString(16));
   for(let i=0;i<11;i++)console.log('q'+i+'=0x'+readu(fo+i*8).toString(16));
   found++;
 }
}
console.log('FOUND='+found);

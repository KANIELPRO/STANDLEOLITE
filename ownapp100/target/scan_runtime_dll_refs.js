const fs=require('fs');
const p='C:/Users/pasha/OneDrive/Desktop/STANDOFF_1_0_DUMP_WORK/ownapp100/target/libunity.runtime.current.so';
const b=fs.readFileSync(p);
const maps=[
 {s:0x6fe303e000n,e:0x6fe839a000n,o:0x0n,k:'ro'},
 {s:0x6fe839d000n,e:0x6fee8c1000n,o:0x535b000n,k:'rx'},
 {s:0x6fee8c4000n,e:0x6feef42000n,o:0xb87e000n,k:'ro'},
 {s:0x6feef45000n,e:0x6fef4ab000n,o:0xbefb000n,k:'rw'}
];
function runtimeAddr(fo){
 for(const m of maps)if(BigInt(fo)>=m.o&&BigInt(fo)<m.o+BigInt(Number(m.e-m.s)))return m.s+(BigInt(fo)-m.o);
 return null;
}
function fileOff(addr){
 const a=BigInt(addr);for(const m of maps)if(a>=m.s&&a<m.e)return Number(m.o+(a-m.s));return -1;
}
function strAt(fo){
 let i=fo;while(i<b.length&&b[i]>=0x20&&b[i]<0x7f)i++;
 if(i-fo<4)return null;return b.toString('ascii',fo,i);
}
const strs=[];const seen=new Set();
for(let i=0;i+4<b.length;i++){
 if(b[i]!==0x2e||b[i+1]!==0x64||b[i+2]!==0x6c||b[i+3]!==0x6c)continue;
 let j=i;while(j>0&&b[j-1]>=0x20&&b[j-1]<0x7f&&i-j<160)j--;
 const s=strAt(j);const a=runtimeAddr(j);
 if(s&&a&&s.endsWith('.dll')&&!s.includes('/')&&!s.includes(' ')){
  const key=s+'@'+a.toString(16);if(!seen.has(key)){seen.add(key);strs.push({s,a,fo:j});}
 }
}
console.log('DLL_STRINGS',strs.length);
for(const x of strs.slice(0,300))console.log('DLL',x.s,'addr=0x'+x.a.toString(16),'fo=0x'+x.fo.toString(16));
const targets=new Map(strs.map(x=>[x.a.toString(),x]));
const refs=[];
for(const m of maps){
 if(m.k==='rx')continue;
 let start=Number(m.o),end=Math.min(b.length,start+Number(m.e-m.s));
 for(let fo=start;fo+8<=end;fo+=8){
  const v=b.readBigUInt64LE(fo);
  const x=targets.get(v.toString());
  if(!x)continue;
  refs.push({fo,v,x});
 }
}
console.log('REFS',refs.length);
function owned(a){const x=BigInt(a);for(const m of maps)if(x>=m.s&&x<m.e)return m;return null;}
function ascii(fo){let i=fo;while(i<b.length&&b[i]>=0x20&&b[i]<0x7f)i++;return i>fo?b.toString('ascii',fo,i):'';}
function inspect(fo){
 if(fo+17*8>b.length)return;
 const q=[];for(let i=0;i<17;i++)q.push(b.readBigUInt64LE(fo+i*8));
 const namefo=fileOff(q[0]);const name=namefo>=0?ascii(namefo):'';
 if(!name.endsWith('.dll'))return;
 if(!q[2]||q[1]>20000000||q[3]>5000000||q[6]>5000000||q[8]>5000000||q[10]>5000000)return;
 const arr=owned(q[2]);if(!arr)return;
 console.log('MODULE_CAND fo=0x'+fo.toString(16),'addr=0x'+(runtimeAddr(fo)||0n).toString(16),'name='+name);
 for(let i=0;i<17;i++)console.log(' q'+i+'=0x'+q[i].toString(16));
}
for(const r of refs.slice(0,60)){
 const q=[];for(let i=0;i<17;i++)q.push(b.readBigUInt64LE(r.fo+i*8));
 console.log('REF_DETAIL',r.x.s,'fo=0x'+r.fo.toString(16),'addr=0x'+(runtimeAddr(r.fo)||0n).toString(16));
 console.log(q.map((v,i)=>' q'+i+'=0x'+v.toString(16)).join(' '));
 inspect(r.fo);
}

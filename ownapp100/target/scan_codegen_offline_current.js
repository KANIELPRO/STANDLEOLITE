const fs = require('fs');

const root = 'C:/Users/pasha/OneDrive/Desktop/STANDOFF_1_0_DUMP_WORK/ownapp100/target';
const file = fs.readFileSync(root + '/libunity.runtime.current.so');

const base = 0x6fe303e000n;
const ranges = [
  {s:0x6fe303e000n,e:0x6fe839a000n,o:0x0n,k:'ro'},
  {s:0x6fe839d000n,e:0x6fee8c1000n,o:0x535b000n,k:'rx'},
  {s:0x6fee8c4000n,e:0x6feef42000n,o:0xb87e000n,k:'ro'},
  {s:0x6feef45000n,e:0x6fef4ab000n,o:0xbefb000n,k:'rw'}
];
function rangeOf(p) {
  for (const r of ranges) if (p >= r.s && p < r.e)
    return {r, fo:Number(p-r.s+r.o)};
  return null;
}
function ptr(x) { return x >= 0x100000000n && x < 0x8000000000n; }
function count(x,max) { return x <= BigInt(max) && (x >> 32n) === 0n; }
function asciiAt(p) {
  const z = rangeOf(p); if (!z) return null;
  let out='';
  for (let i=0;i<160 && z.fo+i<file.length;i++) {
    const c=file[z.fo+i];
    if (c < 0x20 || c >= 0x7f) break;
    out += String.fromCharCode(c);
  }
  return out.length >= 4 ? out : null;
}
function owned(p,kinds) {
  const z=rangeOf(p);
  return z && kinds.includes(z.r.k);
}
const hits=[];
const rw = ranges.find(r=>r.k==='rw');
const startFo = Number(rw.o), endFo = Math.min(file.length, Number(rw.o + (rw.e-rw.s)));
for(let fo=startFo; fo+136<=endFo; fo+=8) {
  const q = [];
  for(let i=0;i<17;i++) q.push(file.readBigUInt64LE(fo+i*8));
  const name = asciiAt(q[0]);
  if(!name || !name.endsWith('.dll')) continue;
  if(!count(q[1],10000000) || !ptr(q[2])) continue;
  if(!owned(q[2],['rx'])) continue;
  if(!count(q[3],2000000)) continue;
  if(q[4] && !owned(q[4],['rx','ro','rw'])) continue;
  if(q[5] && !owned(q[5],['ro','rw'])) continue;
  if(!count(q[6],2000000)) continue;
  if(q[7] && !owned(q[7],['ro','rw'])) continue;
  if(!count(q[8],2000000)) continue;
  if(q[9] && !owned(q[9],['ro','rw'])) continue;
  if(!count(q[10],2000000)) continue;
  if(q[11] && !owned(q[11],['ro','rw'])) continue;
  if(q[12] && !owned(q[12],['ro','rw'])) continue;
  if(q[13] && !owned(q[13],['rx'])) continue;
  if(q[14] && !owned(q[14],['ro','rw'])) continue;
  if(q[15] && !owned(q[15],['ro','rw'])) continue;
  if(q[16] && !owned(q[16],['ro','rw'])) continue;
  hits.push({fo,name,q});
}
console.log('HITS',hits.length);
for(const h of hits.slice(0,200)){
  console.log('MODULE_FO=0x'+h.fo.toString(16)+' NAME='+h.name);
  h.q.forEach((v,i)=>console.log(' q'+i+'=0x'+v.toString(16)));
}
console.log('ELF_SIZE',file.length.toString(16));
console.log('LOAD_BASE',base.toString(16));

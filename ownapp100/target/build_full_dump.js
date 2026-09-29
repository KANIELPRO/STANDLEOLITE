const fs=require('fs');
const path='C:/Users/pasha/OneDrive/Desktop/STANDOFF_1_0_DUMP_WORK/ownapp100';
const base=path+'/libunity.so';
const live=path+'/target/live/';
const out=path+'/target/libunity.full.runtime.dump.so';
const orig=fs.readFileSync(base);
const d=Buffer.from(orig);
const segs=[
 ['libunity.map0.bin',0x00000000],
 ['libunity.text.bin',0x0535b000],
 ['libunity.rodata.bin',0x0b87e000],
 ['libunity.data.bin',0x0befb000]
];
for(const [f,off] of segs){
 const b=fs.readFileSync(live+f);
 const n=Math.min(b.length,d.length-off);
 b.copy(d,off,0,n);
 console.log(f,'bytes',b.length,'patched',n,'fileoff=0x'+off.toString(16));
}
fs.writeFileSync(out,d);
const raw0=fs.readFileSync(live+'libunity.map0.large.bin');
fs.writeFileSync(path+'/target/libunity.runtime.map0.full.bin',raw0.subarray(0,orig.length));
function hex(buf){return [...buf.subarray(0,16)].map(x=>x.toString(16).padStart(2,'0')).join(' ')}
console.log('orig',orig.length,hex(orig));
console.log('dump',d.length,hex(d));
console.log('raw0',raw0.length,'trimmed',orig.length);
let diff=0,first=-1;for(let i=0;i<orig.length;i++){if(orig[i]!==raw0[i]){diff++;if(first<0)first=i}}console.log('orig_vs_raw0 diff',diff,'first',first>=0?'0x'+first.toString(16):'-');
console.log('out',out,fs.statSync(out).size);

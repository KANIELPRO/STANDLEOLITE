const fs=require('fs'),path=require('path');
const d='C:/Users/pasha/OneDrive/Desktop/STANDOFF_1_0_DUMP_WORK/ownapp100/target/showhits';
const defs=[['showhit-6df3b9e000-6e00000000.bin',0x6df3b9e000n],['showhit-6f4ec08000-6f53f64000.bin',0x6f4ec08000n],['showhit-6eb0000000-6eb0400000.bin',0x6eb0000000n],['showhit-6ed0000000-6ed0c00000.bin',0x6ed0000000n],['showhit-6ef0000000-6ef4000000.bin',0x6ef0000000n],['showhit-6f00000000-6f00400000.bin',0x6f00000000n],['rw2.bin',0x6e00000000n],['rw5.bin',0x6f5ab0f000n]];
const ms=defs.map(([f,s])=>({f,s,b:fs.readFileSync(path.join(d,f))}));
const targets=[0x6f5af03c38n,0x6f5af9cd28n,0x6f5afea400n,0x6f5afdd1e8n,0x6f5aebd860n,0x6f5af8ab90n];
for(const t of targets){const pat=Buffer.alloc(8);pat.writeBigUInt64LE(t);console.log('TARGET 0x'+t.toString(16));for(const m of ms){let k=0,c=0;while((k=m.b.indexOf(pat,k))>=0&&c<50){console.log(' '+m.f+' @0x'+(m.s+BigInt(k)).toString(16));k+=8;c++}}}

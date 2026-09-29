const fs=require('fs'),path=require('path');
const d='C:/Users/pasha/OneDrive/Desktop/STANDOFF_1_0_DUMP_WORK/ownapp100/target/showhits';
const defs=[['showhit-6df3b9e000-6e00000000.bin',0x6df3b9e000n],['showhit-6f4ec08000-6f53f64000.bin',0x6f4ec08000n],['showhit-6eb0000000-6eb0400000.bin',0x6eb0000000n],['showhit-6ed0000000-6ed0c00000.bin',0x6ed0000000n],['showhit-6ef0000000-6ef4000000.bin',0x6ef0000000n],['showhit-6f00000000-6f00400000.bin',0x6f00000000n],['rw2.bin',0x6e00000000n],['rw5.bin',0x6f5ab0f000n]];
const ms=defs.map(([f,s])=>({f,s,b:fs.readFileSync(path.join(d,f))}));
const ex=[0x6f53f67000n,0x6f5a48b000n], any=[0x6df3b9e000n,0x6e10000000n];
let found=[];
for(const m of ms){let run=0,start=0;for(let o=0;o+8<=m.b.length;o+=8){const v=m.b.readBigUInt64LE(o);const ok=v>=ex[0]&&v<ex[1]&&(v&1n)===0n;if(ok){if(!run)start=o;run++}else{if(run>=12)found.push({f:m.f,addr:m.s+BigInt(start),len:run,first:m.b.readBigUInt64LE(start),last:m.b.readBigUInt64LE(o-8)});run=0}}if(run>=12)found.push({f:m.f,addr:m.s+BigInt(start),len:run,first:m.b.readBigUInt64LE(start),last:m.b.readBigUInt64LE(m.b.length-8)})}
found.sort((a,b)=>b.len-a.len);console.log('runs',found.length);for(const x of found.slice(0,100))console.log(x.f+' @0x'+x.addr.toString(16)+' len='+x.len+' first=0x'+x.first.toString(16)+' last=0x'+x.last.toString(16));
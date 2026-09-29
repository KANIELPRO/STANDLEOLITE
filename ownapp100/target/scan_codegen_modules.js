const fs=require('fs'),path=require('path');
const d='C:/Users/pasha/OneDrive/Desktop/STANDOFF_1_0_DUMP_WORK/ownapp100/target/showhits';
const defs=[['showhit-6df3b9e000-6e00000000.bin',0x6df3b9e000n,0x6e00000000n],['showhit-6e8be00000-6e8d000000.bin',0x6e8be00000n,0x6e8d000000n],['showhit-6eb0000000-6eb0400000.bin',0x6eb0000000n,0x6eb0400000n],['showhit-6ed0000000-6ed0c00000.bin',0x6ed0000000n,0x6ed0c00000n],['showhit-6ef0000000-6ef4000000.bin',0x6ef0000000n,0x6ef4000000n],['showhit-6f00000000-6f00400000.bin',0x6f00000000n,0x6f00400000n],['showhit-6f4ec08000-6f53f64000.bin',0x6f4ec08000n,0x6f53f64000n],['showhit-6ffe795000-6ffe7f2000.bin',0x6ffe795000n,0x6ffe7f2000n],['rw2.bin',0x6e00000000n,0x6e00200000n],['rw5.bin',0x6f5ab0f000n,0x6f5b075000n]];
const ms=defs.map(([f,s,e])=>({f,s,e,b:fs.readFileSync(path.join(d,f))}));
const ranges=ms.map(m=>[m.s,m.e]).concat([[0x6f53f67000n,0x6f5a48b000n],[0x6f5a48e000n,0x6f5ab0c000n]]);
const im=v=>ranges.some(([s,e])=>v>=s&&v<e);
function owner(v){for(const m of ms)if(v>=m.s&&v<m.e)return [m,Number(v-m.s)];return null}
function str(v){const z=owner(v);if(!z)return '';const[m,o]=z;if(o<0||o>=m.b.length)return '';let e=o;while(e<m.b.length&&e<o+160&&m.b[e]>=0x20&&m.b[e]<0x7f)e++;return m.b.toString('ascii',o,e)}
let total=0;
for(const m of ms)for(let o=0;o+136<=m.b.length;o+=8){
 const q=Array.from({length:17},(_,i)=>m.b.readBigUInt64LE(o+i*8)),s=str(q[0]);
 const nz=v=>v===0n||im(v);
 if(!s||!s.endsWith('.dll'))continue;
 if(q[1]<1n||q[1]>2000000n||!im(q[2]))continue;
 if(q[3]>100000n||!nz(q[4])||q[5]>2000000n||!nz(q[6])||q[7]>2000000n||!nz(q[7])||q[8]>2000000n||!nz(q[9])||q[10]>2000000n||!nz(q[11])||!nz(q[12])||!nz(q[13])||!nz(q[14])||q[15]>100000n||!nz(q[16]))continue;
 console.log('MODULE '+m.f+' @0x'+(m.s+BigInt(o)).toString(16)+' name='+s+' q='+q.map(v=>'0x'+v.toString(16)).join(' ')); total++;
 if(total>=200)process.exit(0);
}
console.log('TOTAL',total);
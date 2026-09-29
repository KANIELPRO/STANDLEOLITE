const fs=require('fs');
const rw=fs.readFileSync('C:/Users/pasha/OneDrive/Desktop/STANDOFF_1_0_DUMP_WORK/ownapp100/target/showhits/rw5.bin');
const ro=fs.readFileSync('C:/Users/pasha/OneDrive/Desktop/STANDOFF_1_0_DUMP_WORK/ownapp100/target/showhits/ro-late.bin');
const rwb=0x6f5ab0f000n, rob=0x6f5a48e000n, ra=0x6f5ab28790n;
function inro(v){return v>=rob&&v<rob+BigInt(ro.length)}
function inrw(v){return v>=rwb&&v<rwb+BigInt(rw.length)}
function at(buf,base,v){return Number(v-base)}
function qro(v){return ro.readBigUInt64LE(at(ro,rob,v))}
function sro(v){if(!inro(v))return'';let o=at(ro,rob,v),e=o;while(e<ro.length&&e<o+256&&ro[e]>=0x20&&ro[e]<0x7f)e++;return ro.toString('ascii',o,e)}
console.log('array at',ra.toString(16),'rw offset',ra-rwb);
let entries=[];
for(let i=0;i<2000;i++){let o=Number(ra-rwb)+i*8;if(o+8>rw.length)break;let v=rw.readBigUInt64LE(o);if(!inro(v))break;entries.push(v)}
console.log('array_count',entries.length);
for(let i=0;i<entries.length;i++){
 const a=entries[i]; let vals=[];for(let j=0;j<18;j++)vals.push(qro(a+BigInt(j*8)));
 const name=sro(vals[0]);
 console.log(i+' @0x'+a.toString(16)+' name='+name+' q='+vals.map(v=>'0x'+v.toString(16)).join(' '));
}

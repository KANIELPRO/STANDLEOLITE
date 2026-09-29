const fs=require('fs');
const b=fs.readFileSync('C:/Users/pasha/OneDrive/Desktop/STANDOFF_1_0_DUMP_WORK/ownapp100/target/data.unity3d');
let o=0;
function c(){while(o<b.length&&b[o]!==0)o++;o++;return 0}
function u32(){const x=b.readUInt32BE(o);o+=4;return x}
function u64(){const x=b.readBigUInt64BE(o);o+=8;return x}
c();const ver=u32();c();c();const total=u64(),ic=u32(),iu=u32(),flags=u32();
while(o%16)o++;
const dataOff=o+ic;
console.log('ver',ver,'total',total.toString(),'ic',ic,'iu',iu,'flags',flags.toString(16),'dataOff',dataOff);
const info=b.subarray(o,o+ic);
console.log('info head',info.subarray(0,64).toString('hex'));
let p=16,bc=info.readUInt32BE(p);p+=4;console.log('blocks',bc);
for(let i=0;i<10;i++){let us=info.readUInt32BE(p),cs=info.readUInt32BE(p+4),fl=info.readUInt16BE(p+8);console.log(i,'us',us,'cs',cs,'fl',fl.toString(16));p+=10}
console.log('data block head',b.subarray(dataOff,dataOff+64).toString('hex'));

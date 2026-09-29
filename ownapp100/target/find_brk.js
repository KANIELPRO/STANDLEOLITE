const fs=require('fs');
const b=fs.readFileSync('C:/Users/pasha/OneDrive/Desktop/STANDOFF_1_0_DUMP_WORK/ownapp100/libunity.so');
const pat=Buffer.from([0,0,0x20,0xd4]); const s=0x535b940, e=s+0x6523640;
let k=b.indexOf(pat,s);
while(k>=0&&k<e){console.log('fileoff=0x'+k.toString(16)+' runtime=0x'+(0x6f53440000n+0x535f940n+BigInt(k-s)).toString(16));break}
if(k<0||k>=e)console.log('none');
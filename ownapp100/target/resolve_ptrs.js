const fs=require('fs');
const b=fs.readFileSync('C:/Users/pasha/OneDrive/Desktop/STANDOFF_1_0_DUMP_WORK/ownapp100/target/showhits/rw5.bin');
const base=0x6f5ab0f000n;
for(const v of [0x6f5afea2d8n,0x6f5afea2d0n,0x6f5afee580n,0x6f5a782808n]){
 if(v<base||v>=base+BigInt(b.length)){console.log(v.toString(16),'outside');continue;}
 let o=Number(v-base),e=o;
 while(e<b.length&&e<o+160&&b[e]>=32&&b[e]<127)e++;
 console.log(v.toString(16),b.toString('ascii',o,e));
 console.log(b.subarray(o,Math.min(b.length,o+48)).toString('hex'));
}
const fs=require('fs');
const b=fs.readFileSync('C:/Users/pasha/OneDrive/Desktop/STANDOFF_1_0_DUMP_WORK/ownapp100/target/libunity.full.runtime.dump.so');
const base=0x6f53440000n;
const segs=[[0n,0x535b938n,'R'],[0x535f940n,0x535f940n+0x6523640n,'X'],[0xb886f80n,0xb886f80n+0x67d080n,'RELRO'],[0xbf07f60n,0xbf07f60n+0x8ac708n,'RW']];
const im=v=>segs.some(x=>v>=base+x[0]&&v<base+x[1]);
const own=v=>segs.find(x=>v>=base+x[0]&&v<base+x[1]);
function refsTo(v){const p=Buffer.alloc(8);p.writeBigUInt64LE(v);const out=[];let k=0;while((k=b.indexOf(p,k))>=0){out.push(k);k+=8}return out}
function strAt(v){const s=own(v);if(!s)return'';const o=Number(v-base);let e=o;while(e<b.length&&e<o+256&&b[e]>=0x20&&b[e]<0x7f)e++;return b.toString('ascii',o,e)}
function score(q){
 let s=0;
 if(q[1]>0n&&q[1]<3000000n)s+=3;
 if(im(q[2]))s+=6;
 if(q[3]<3000000n)s+=2;
 if(im(q[4]))s+=2;
 if(im(q[5]))s+=2;
 if(q[6]<3000000n)s+=2;
 if(im(q[7]))s+=2;
 if(q[8]<3000000n)s+=2;
 if(im(q[9]))s+=2;
 if(q[10]<3000000n)s+=2;
 if(im(q[11]))s+=2;
 if(q[12]===0n||im(q[12]))s++;
 if(q[13]===0n||im(q[13]))s++;
 if(q[14]===0n||im(q[14]))s++;
 if(q[15]===0n||im(q[15]))s++;
 if(q[16]===0n||im(q[16]))s++;
 return s;
}
for(const name of ['mscorlib.dll','Assembly-CSharp.dll','Gameplay.Bomb.dll','Axlebolt.Standoff.dll']){
 const pat=Buffer.from(name);let k=0,strings=[];
 while((k=b.indexOf(pat,k))>=0){strings.push(base+BigInt(k));k+=pat.length}
 console.log('\nNAME',name,'strings',strings.length);
 for(const st of strings.slice(0,80)){
   const rs=refsTo(st);
   for(const ro of rs.slice(0,1000)){
     if(ro+136>b.length)continue;
     const q=Array.from({length:17},(_,i)=>b.readBigUInt64LE(ro+i*8));
     const sc=score(q);
     if(sc>=12) console.log('CAND score='+sc+' @0x'+(base+BigInt(ro)).toString(16)+' str=0x'+st.toString(16)+' map='+own(base+BigInt(ro))[2]+' q='+q.map(v=>'0x'+v.toString(16)).join(' '));
   }
 }
}

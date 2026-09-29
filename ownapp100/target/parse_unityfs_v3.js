const fs=require('fs');
const lz4=require('C:/Users/pasha/OneDrive/Desktop/STANDOFF_1_0_DUMP_WORK/ownapp100/target/node_modules/lz4js');
const root='C:/Users/pasha/OneDrive/Desktop/STANDOFF_1_0_DUMP_WORK/ownapp100/target/';
for(const fn of ['apk-data.unity3d','data.unity3d']){
 const b=fs.readFileSync(root+fn);let o=0;
 const cstr=()=>{let s=o;while(b[o])o++;let x=b.toString('utf8',s,o);o++;return x};
 const u32=()=>{let x=b.readUInt32BE(o);o+=4;return x};
 const i64=()=>{let x=b.readBigInt64BE(o);o+=8;return x};
 const sig=cstr(),ver=u32(),player=cstr(),eng=cstr(),size=i64(),cs=u32(),us=u32(),flags=u32(),hdr=o;
 const infoOff=(flags&0x40)?Number(size)-cs:hdr;
 const ib=b.subarray(infoOff,infoOff+cs), info=Buffer.alloc(us);
 if((flags&0x3f)===0)ib.copy(info);else lz4.decompressBlock(ib,info,0,ib.length,0);
 let p=16,bc=info.readUInt32BE(p);p+=4;let blocks=[];
 for(let i=0;i<bc;i++){let bus=info.readUInt32BE(p),bcs=info.readUInt32BE(p+4),bf=info.readUInt16BE(p+8);blocks.push({us:bus,cs:bcs,fl:bf});p+=10}
 const nc=info.readUInt32BE(p);p+=4;let nodes=[];
 for(let i=0;i<nc;i++){let no=info.readBigUInt64BE(p),sz=info.readBigUInt64BE(p+8),fl=info.readUInt32BE(p+16);p+=20;let e=info.indexOf(0,p);let name=info.toString('utf8',p,e);p=e+1;nodes.push({off:no,size:sz,fl,name})}
 console.log('\nFILE',fn,'size',size.toString(),'flags=0x'+flags.toString(16),'comp',flags&63,'infoOff',infoOff,'blocks',bc,'nodes',nc);
 for(const n of nodes)console.log(n.off.toString(),n.size.toString(),n.fl.toString(16),n.name);
 fs.writeFileSync(root+fn+'.nodes.json',JSON.stringify(nodes.map(n=>({...n,off:n.off.toString(),size:n.size.toString()})),null,2));
}
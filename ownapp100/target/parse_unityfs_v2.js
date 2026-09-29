const fs=require('fs');
const files=['apk-data.unity3d','data.unity3d'];
const root='C:/Users/pasha/OneDrive/Desktop/STANDOFF_1_0_DUMP_WORK/ownapp100/target/';
function lz4(src,expected){let out=Buffer.alloc(expected),i=0,w=0;while(i<src.length){let t=src[i++],ll=t>>>4;if(ll===15){let x;do{x=src[i++];ll+=x}while(x===255)}if(i+ll>src.length)throw Error('literal overflow');src.copy(out,w,i,i+ll);i+=ll;w+=ll;if(i>=src.length)break;let off=src[i]|(src[i+1]<<8);i+=2;if(!off||off>w)throw Error('bad offset');let ml=t&15;if(ml===15){let x;do{x=src[i++];ml+=x}while(x===255)}ml+=4;for(let j=0;j<ml;j++)out[w+j]=out[w-off+j];w+=ml}if(w!==expected)throw Error('lz4 size '+w+' '+expected);return out}
for(const fn of files){const b=fs.readFileSync(root+fn);let o=0;
 const cstr=()=>{let s=o;while(b[o])o++;const z=b.toString('utf8',s,o);o++;return z};
 const u32=()=>{const x=b.readUInt32BE(o);o+=4;return x};
 const i64=()=>{const x=b.readBigInt64BE(o);o+=8;return x};
 const sig=cstr(),ver=u32(),player=cstr(),eng=cstr(),fileSize=i64(),cbs=u32(),ubs=u32(),flags=u32(),headerEnd=o;
 const infoOff=(flags&0x40)?(Number(fileSize)-cbs):headerEnd;
 const ib=b.subarray(infoOff,infoOff+cbs);
 const compType=flags&0x3f;
 let info=compType===0?ib:lz4(ib,ubs);
 let p=16;const blockCount=info.readUInt32BE(p);p+=4;let blocks=[];for(let i=0;i<blockCount;i++){const us=info.readUInt32BE(p),cs=info.readUInt32BE(p+4),fl=info.readUInt16BE(p+8);blocks.push({us,cs,fl});p+=10}
 const nodeCount=info.readUInt32BE(p);p+=4;let nodes=[];for(let i=0;i<nodeCount;i++){const off=info.readBigUInt64BE(p),sz=info.readBigUInt64BE(p+8),fl=info.readUInt32BE(p+16);p+=20;const e=info.indexOf(0,p);const name=info.toString('utf8',p,e);p=e+1;nodes.push({off,size:sz,flags:fl,name})}
 console.log('\nFILE',fn,'sig',sig,'ver',ver,'player',player,'eng',eng,'size',fileSize.toString(),'cbs',cbs,'ubs',ubs,'flags=0x'+flags.toString(16),'comp',compType,'header',headerEnd,'infoOff',infoOff,'blocks',blockCount,'nodes',nodeCount);
 for(const n of nodes)if(/metadata|managed|assembly|unity|resource|global|Game|\.dat/i.test(n.name))console.log(n.off.toString(),n.size.toString(),n.flags.toString(16),n.name);
}
const net=require('net');const c=net.createConnection(5039,'127.0.0.1');let b=Buffer.alloc(0);
function cs(s){let n=0;for(const x of Buffer.from(s))n=(n+x)&255;return n.toString(16).padStart(2,'0')}
function req(s,t=7000){return new Promise((res,rej)=>{let z=setTimeout(()=>rej(Error('timeout '+s)),t);function f(){while(b.length&&b[0]!==36)b=b.subarray(1);let h=b.indexOf(35,1);if(h<0||b.length<h+3)return;let body=b.subarray(1,h).toString();b=b.subarray(h+3);clearTimeout(z);c.write('+');res(body)}c.on('data',d=>{b=Buffer.concat([b,d]);f()});c.write('$'+s+'#'+cs(s))})}
function le(v){let x=BigInt(v),s='';for(let i=0;i<8;i++){s+=(x&255n).toString(16).padStart(2,'0');x>>=8n}return s}
async function pr(n,v){const x=await req('P'+n.toString(16)+'='+le(v));if(x!=='OK')throw Error('P'+n+':'+x)}
async function gr(n){const x=await req('p'+n.toString(16));let a='';for(let i=x.length;i>0;i-=2)a+=x.slice(i-2,i);return BigInt('0x'+a)}
c.on('connect',async()=>{try{
const save={};for(const n of [0,1,2,3,4,5,30,32])save[n]=await gr(n);
const brk=0x1n;await pr(0,0n);await pr(1,0x4000n);await pr(2,7n);await pr(3,0x22n);await pr(4,0xffffffffffffffffn);await pr(5,0n);await pr(30,brk);await pr(32,0x780a71d150n);
console.log('continue='+await req('c',7000));const mem=await gr(0);console.log('mem=0x'+mem.toString(16));
for(const n of [0,1,2,3,4,5,30,32])await pr(n,save[n]);console.log('detach='+await req('D'));c.end();
}catch(e){console.error(e);c.end()}});
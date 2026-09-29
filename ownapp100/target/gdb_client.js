const net=require('net');
const c=net.createConnection(5039,'127.0.0.1');
let buf=Buffer.alloc(0);
function csum(s){let n=0;for(let i=0;i<s.length;i++)n=(n+s.charCodeAt(i))&255;return n.toString(16).padStart(2,'0')}
function pkt(s){return '$'+s+'#'+csum(s)}
function send(s){return new Promise((res,rej)=>{let timer=setTimeout(()=>rej(Error('timeout')),5000);function on(){let i=buf.indexOf(35);if(i<0)return;let j=i+2;if(buf[0]!==36){buf=buf.subarray(buf.indexOf(36)>=0?buf.indexOf(36):buf.length);return}if(j>=buf.length)return;const body=buf.toString('ascii',1,i);const got=buf.subarray(i+1,j).toString('ascii');buf=buf.subarray(j);clearTimeout(timer);res({body,ok:got.toLowerCase()===csum(body)});};c.on('data',d=>{buf=Buffer.concat([buf,d]);on()});c.write(pkt(s));})}
c.on('connect',async()=>{try{
 console.log('connected'); console.log('qSupported',await send('qSupported')); console.log('stop',await send('?')); const g=await send('g'); console.log('glen',g.body.length,'g',g.body.slice(0,600)); c.end();
}catch(e){console.error(e);c.end();}});

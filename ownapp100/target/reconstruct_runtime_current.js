const fs = require('fs');
const crypto = require('crypto');

const root = 'C:/Users/pasha/OneDrive/Desktop/STANDOFF_1_0_DUMP_WORK/ownapp100';
const stat = root + '/libunity.so';
const out = root + '/target/libunity.runtime.current.so';

const segments = [
  ['target/live2/libunity.whole-current.bin', 0x00000000],
  ['target/live2/libunity.map0.current.bin', 0x00000000],
  ['target/live2/libunity.text.current.bin', 0x0535b000],
  ['target/live2/libunity.rodata.current.bin', 0x0b87e000],
  ['target/live2/libunity.data.current.bin', 0x0befb000]
];

fs.copyFileSync(stat, out);
const fd = fs.openSync(out, 'r+');
const fileSize = fs.statSync(stat).size;

for (const [rel, off] of segments) {
  const p = root + '/' + rel;
  const data = fs.readFileSync(p);
  const n = Math.min(data.length, fileSize - off);
  if (n > 0) fs.writeSync(fd, data, 0, n, off);
}
fs.closeSync(fd);

const buf = fs.readFileSync(out);
console.log('OUTPUT', out);
console.log('SIZE', buf.length);
console.log('SHA256', crypto.createHash('sha256').update(buf).digest('hex'));

function hashSlice(path, off, len) {
  const fd = fs.openSync(path, 'r');
  const b = Buffer.allocUnsafe(len);
  fs.readSync(fd, b, 0, len, off);
  fs.closeSync(fd);
  return crypto.createHash('sha256').update(b).digest('hex');
}function check(rel, off) {
  const p = root + '/' + rel;
  const b = fs.readFileSync(p);
  const n = Math.min(b.length, fileSize - off);
  const a = buf.subarray(off, off + n);
  const h1 = crypto.createHash('sha256').update(a).digest('hex');
  const h2 = crypto.createHash('sha256').update(b.subarray(0, n)).digest('hex');
  console.log('CHECK', rel, 'offset=0x'+off.toString(16),
              'len=0x'+n.toString(16), 'match='+String(h1===h2));
}
check('target/live2/libunity.whole-current.bin', 0);
check('target/live2/libunity.map0.current.bin', 0);
check('target/live2/libunity.text.current.bin', 0x0535b000);
check('target/live2/libunity.rodata.current.bin', 0x0b87e000);
check('target/live2/libunity.data.current.bin', 0x0befb000);

// Print ELF LOAD mappings.
const u16 = o => buf.readUInt16LE(o);
const u32 = o => buf.readUInt32LE(o);
const u64 = o => Number(buf.readBigUInt64LE(o));
const phoff = u64(32), entsz = u16(54), phnum = u16(56);
console.log('ELF', buf.subarray(0,4).toString('ascii'), 'class='+buf[4],
            'machine=0x'+u16(18).toString(16), 'phnum='+phnum);
for (let i=0;i<phnum;i++) {
  const o = phoff + i*entsz;
  if (u32(o) !== 1) continue;
  console.log('LOAD', i,
    'off=0x'+u64(o+8).toString(16),
    'vaddr=0x'+u64(o+16).toString(16),
    'filesz=0x'+u64(o+32).toString(16),
    'memsz=0x'+u64(o+40).toString(16),
    'flags=0x'+u32(o+4).toString(16));
}
function findAscii(needle) {
  const n = Buffer.from(needle, 'ascii');
  const hits = [];
  for (let i=0;i<=buf.length-n.length;i++) {
    let ok=true;
    for(let j=0;j<n.length;j++) if(buf[i+j]!==n[j]) {ok=false;break;}
    if(ok) hits.push(i);
  }
  return hits;
}
for (const s of ['Assembly-CSharp.dll','Axlebolt.Standoff.Game.dll',
                 'Gameplay.Bomb.dll','global-metadata.dat']) {
  console.log('STRING', s, findAscii(s).slice(0,20).map(x=>'0x'+x.toString(16)));
}

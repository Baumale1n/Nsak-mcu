import struct,zipfile,io,glob,os
DELTA=0x9e3779b9;ROUNDS=32
def u32(x):return x&0xffffffff
def rd(b,o):return struct.unpack_from('<I',b,o)[0]
def tea_db(y,z,k):
    s=u32(DELTA*ROUNDS)
    for _ in range(ROUNDS):
        z=u32(z-(u32(u32((y<<4)&0xffffffff)+k[2])^u32(y+s)^u32((y>>5)+k[3])))
        y=u32(y-(u32(u32((z<<4)&0xffffffff)+k[0])^u32(z+s)^u32((z>>5)+k[1])))
        s=u32(s-DELTA)
    return y,z
def rot(k):
    b=bytearray(struct.pack('<4I',*k))
    for i in range(16):b[i]=(b[i]+i)&0xff
    return list(struct.unpack('<4I',bytes(b)))
DEF=list(struct.unpack('<4I',bytes.fromhex('fe801cb2d1ef41a6a41731f5a06824f0')))
def dec(enc):
    k=DEF[:];lo=hi=0;proc=0;out=bytearray(len(enc))
    for i in range(0,len(enc)-len(enc)%8,8):
        if proc==1024:k=rot(k);proc=0
        c0=rd(enc,i);c1=rd(enc,i+4);d0,d1=tea_db(c0,c1,k)
        struct.pack_into('<I',out,i,u32(d0^lo));struct.pack_into('<I',out,i+4,u32(d1^hi));lo=c0;hi=c1;proc+=8
    return bytes(out)
K=open('/Users/<user>/.claude/jobs/2abbd798/tmp/kasai/mcu/MCU.dec.bin','rb').read()
def mp(a,b):
    n=min(len(a),len(b))
    return 100*sum(1 for i in range(n) if a[i]==b[i])/n if n else 0
def body_from_zip(zb):
    try:z=zipfile.ZipFile(io.BytesIO(zb))
    except:return None
    for n in z.namelist():
        bn=n.split('/')[-1]
        if bn=='FIRM.bin.enc':
            data=z.read(n)
            return dec(data)[:-4] if len(data)%8==0 else None
        if bn=='FIRM.bin': return z.read(n)
    return None
print("MCU body len:",len(K))
rows=[]
for zp in sorted(glob.glob('deploy/firmware-repo/g3/mcu/*.zip')+glob.glob('apps/n-sak/public/firmware/g3/mcu/*.zip')):
    b=body_from_zip(open(zp,'rb').read())
    if b: rows.append((mp(K,b),len(b),os.path.basename(zp)))
print("\n=== MCU Compats / N-SAK MCU CFW vs kasai ===")
seen=set()
for pct,ln,name in sorted(rows,reverse=True):
    if name in seen: continue
    seen.add(name)
    print(f"  {pct:6.2f}%  len={ln:6d}  Δ{len(K)-ln:+5d}  {name}")
# captured SHU MCU
print("\n=== captured SHU packages (MCU) ===")
for zp in glob.glob('captures/**/firmware-package-g3.zip',recursive=True):
    try:z=zipfile.ZipFile(zp)
    except:continue
    for n in z.namelist():
        if n.endswith('.zip') and 'mcu' in n.lower():
            b=body_from_zip(z.read(n))
            if b: print(f"  {mp(K,b):6.2f}%  len={len(b):6d}  Δ{len(K)-len(b):+5d}  {os.path.basename(zp)} :: {n}")

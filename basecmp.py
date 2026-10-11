import struct,zipfile,io,glob,os
DELTA=0x9e3779b9; ROUNDS=32
def u32(x):return x&0xffffffff
def rd(b,o):return struct.unpack_from('<I',b,o)[0]
def tea_dec_block(y,z,k):
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
        c0=rd(enc,i);c1=rd(enc,i+4)
        d0,d1=tea_dec_block(c0,c1,k)
        struct.pack_into('<I',out,i,u32(d0^lo));struct.pack_into('<I',out,i+4,u32(d1^hi))
        lo=c0;hi=c1;proc+=8
    return bytes(out)

K=open('/Users/<user>/.claude/jobs/2abbd798/tmp/kasai/FIRM.dec.bin','rb').read()
def matchpct(a,b):
    n=min(len(a),len(b))
    if n==0:return 0
    return 100*sum(1 for i in range(n) if a[i]==b[i])/n

def get_vcu_body(zbytes):
    try: z=zipfile.ZipFile(io.BytesIO(zbytes))
    except: return None
    names=z.namelist()
    # direct FIRM
    for n in names:
        bn=n.split('/')[-1]
        if bn=='FIRM.bin.enc': return dec(z.read(n))[:-4] if len(z.read(n))%8==0 else None
        if bn=='FIRM.bin': return z.read(n)
    return None

def get_vcu_from_pkg(zbytes):
    # nested firmware-package: look for a VCU subdir zip or FIRM
    try: z=zipfile.ZipFile(io.BytesIO(zbytes))
    except: return {}
    out={}
    for n in z.namelist():
        low=n.lower()
        if n.endswith('/'): continue
        data=z.read(n)
        bn=n.split('/')[-1]
        if bn in ('FIRM.bin.enc','FIRM.bin') and ('vcu' in low or 'VCU' in n):
            body=dec(data)[:-4] if (bn.endswith('.enc') and len(data)%8==0) else (data if bn=='FIRM.bin' else None)
            if body: out[n]=body
        elif bn.endswith('.zip') and ('vcu' in low):
            b=get_vcu_body(data)
            if b: out[n]=b
    return out

print("size(kasai body)=",len(K))
print("\n=== SHU/N-SAK VCU Compat zips vs kasai ===")
rows=[]
for zp in sorted(glob.glob('deploy/firmware-repo/g3/vcu/*.zip')):
    try: body=get_vcu_body(open(zp,'rb').read())
    except Exception as e: body=None
    if body is None: 
        print(f"  {os.path.basename(zp):40s} (no VCU FIRM / not 8-aligned)"); continue
    rows.append((matchpct(K,body),len(body),os.path.basename(zp)))
for pct,ln,name in sorted(rows,reverse=True):
    print(f"  {pct:6.2f}%  len={ln:6d}  Δlen={len(K)-ln:+5d}  {name}")

print("\n=== captured SHU packages (real SHU-distributed) ===")
for zp in glob.glob('captures/**/firmware-package-g3.zip',recursive=True):
    got=get_vcu_from_pkg(open(zp,'rb').read())
    for n,body in got.items():
        print(f"  {matchpct(K,body):6.2f}%  len={len(body):6d}  Δ{len(K)-len(body):+5d}  {zp} :: {n}")

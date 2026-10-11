import struct
DELTA=0x9e3779b9
ROUNDS=32
def u32(x): return x & 0xffffffff
def rd(b,o): return struct.unpack_from('<I',b,o)[0]

def tea_dec_block(y,z,k):
    s=u32(DELTA*ROUNDS)
    for _ in range(ROUNDS):
        z=u32(z-(u32(u32((y<<4)&0xffffffff)+k[2])^u32(y+s)^u32((y>>5)+k[3])))
        y=u32(y-(u32(u32((z<<4)&0xffffffff)+k[0])^u32(z+s)^u32((z>>5)+k[1])))
        s=u32(s-DELTA)
    return y,z
def xtea_dec_block(v0,v1,k):
    s=u32(DELTA*ROUNDS)
    for _ in range(ROUNDS):
        v1=u32(v1-(u32(u32(((v0<<4)&0xffffffff)^(v0>>5))+v0)^u32(s+k[(s>>11)&3])))
        s=u32(s-DELTA)
        v0=u32(v0-(u32(u32(((v1<<4)&0xffffffff)^(v1>>5))+v1)^u32(s+k[s&3])))
    return v0,v1
def keywords(kb): return list(struct.unpack('<4I',kb))
def rotate(k):
    b=bytearray(struct.pack('<4I',*k))
    for i in range(16): b[i]=(b[i]+i)&0xff
    return list(struct.unpack('<4I',bytes(b)))

def decrypt(enc,kb,algo,rot=True):
    k=keywords(kb); ivlo=0;ivhi=0;proc=0
    out=bytearray(len(enc))
    for i in range(0,len(enc),8):
        if rot and proc==1024:
            k=rotate(k); proc=0
        c0=rd(enc,i);c1=rd(enc,i+4)
        if algo=='tea': d0,d1=tea_dec_block(c0,c1,k)
        else: d0,d1=xtea_dec_block(c0,c1,k)
        struct.pack_into('<I',out,i,u32(d0^ivlo))
        struct.pack_into('<I',out,i+4,u32(d1^ivhi))
        ivlo=c0;ivhi=c1;proc+=8
    return bytes(out)

enc=open('/Users/<user>/.claude/jobs/2abbd798/tmp/kasai/FIRM.bin.enc','rb').read()
DEFAULT=bytes.fromhex('fe801cb2d1ef41a6a41731f5a06824f0')
cand=[('DEFAULT',DEFAULT)]
for s in ['iqm30rm46aqiaiki','lO3r3l6O2Qv0R4s1','xvi7p85a8cyq2m4k','qph82deg14trplsb']:
    cand.append((s,s.encode()[:16].ljust(16,b'\0')))

def looks_like_vt(d):
    sp=rd(d,0); rv=rd(d,4)
    ok_sp=(sp & 0x2FFE0000)==0x20000000
    ok_rv=(0x08000000<=rv<0x08020000) and (rv&1)==1
    return ok_sp,ok_rv,sp,rv

for algo in ('tea','xtea'):
    for rot in (True,False):
        for name,kb in cand:
            try:
                d=decrypt(enc,kb,algo,rot)
            except Exception as e:
                print(algo,rot,name,'ERR',e);continue
            ok_sp,ok_rv,sp,rv=looks_like_vt(d)
            if ok_sp:
                print(f">>> HIT algo={algo} rot={rot} key={name}: SP=0x{sp:08x} RV=0x{rv:08x} rv_ok={ok_rv}")
print("--- word0/word1 with DEFAULT (no key, both algos, block0 only) ---")
for algo in ('tea','xtea'):
    d=decrypt(enc[:8],DEFAULT,algo,False)
    print(algo,'block0:',d.hex(),'SP=0x%08x RV=0x%08x'%(rd(d,0),rd(d,4)))

# ---- FULL decrypt + checksum + keyslot + reference compare ----
def tea_checksum(data):
    s=0
    for i in range(0,len(data),4): s=u32(s+rd(data,i))
    swp=u32(((s>>16)&0xffff)|((s&0xffff)<<16))
    return u32(swp^0xffffffff)

full=decrypt(enc,DEFAULT,'tea',True)
body=full[:-4]; cksum=rd(full,len(full)-4)
print("\n=== FULL DECRYPT (TEA, DEFAULT, rot) ===")
print("total %d, body %d, trailing checksum=0x%08x, computed(body)=0x%08x, MATCH=%s"%(
    len(full),len(body),cksum,tea_checksum(body),tea_checksum(body)==cksum))
open('/Users/<user>/.claude/jobs/2abbd798/tmp/kasai/FIRM.dec.bin','wb').write(body)
print("keyslot @0x420 (22B K_X legacy):", body[0x420:0x420+22].hex())
print("  as ascii:", ''.join(chr(c) if 32<=c<127 else '.' for c in body[0x420:0x420+22]))
print("keyslot @0x440 (16B XTEA):", body[0x440:0x440+16].hex())
print("  as ascii:", ''.join(chr(c) if 32<=c<127 else '.' for c in body[0x440:0x440+16]))
print("marker  @0x20 (32B):", body[0x20:0x40].hex())
print("  as ascii:", ''.join(chr(c) if 32<=c<127 else '.' for c in body[0x20:0x40]))

import os
refs={}
base='/Users/<user>/DEV_Env/ninebot-fws/apps/n-sak/public/firmware/g3'
for name,path in [('3.9.8_cfw','plaincfw/vcu_3.9.8.bin'),('1.6.2_stock','plainpre163/vcu_1.6.2.bin'),('1.6.3_stock','plain163/vcu_1.6.3.bin')]:
    fp=os.path.join(base,path)
    if os.path.exists(fp): refs[name]=open(fp,'rb').read()
print("\n=== reference sizes ===")
print("kasai body:",len(body))
for n,r in refs.items(): print(f"  {n}: {len(r)}")
def diffcount(a,b):
    n=min(len(a),len(b)); d=sum(1 for i in range(n) if a[i]!=b[i]); return d,n
print("\n=== byte-diff kasai vs refs (over common prefix) ===")
for n,r in refs.items():
    d,common=diffcount(body,r)
    print(f"  {n}: {d} differing bytes of {common} ({100*d/common:.1f}%)  |Δlen|={abs(len(body)-len(r))}")

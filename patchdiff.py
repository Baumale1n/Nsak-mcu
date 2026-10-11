import struct,zipfile,io,glob
from capstone import *
DELTA=0x9e3779b9;ROUNDS=32
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
        c0=rd(enc,i);c1=rd(enc,i+4);d0,d1=tea_dec_block(c0,c1,k)
        struct.pack_into('<I',out,i,u32(d0^lo));struct.pack_into('<I',out,i+4,u32(d1^hi));lo=c0;hi=c1;proc+=8
    return bytes(out)

zp='deploy/firmware-repo/g3/vcu/1.5.15 (Compat).zip'
z=zipfile.ZipFile(zp)
enc=[z.read(n) for n in z.namelist() if n.split('/')[-1]=='FIRM.bin.enc'][0]
S=dec(enc)[:-4]  # SHU 1.5.15 body
K=open('/Users/<user>/.claude/jobs/2abbd798/tmp/kasai/FIRM.dec.bin','rb').read()
assert len(S)==len(K),(len(S),len(K))

diffs=[i for i in range(len(K)) if K[i]!=S[i]]
print("total differing bytes: %d / %d (%.3f%%)"%(len(diffs),len(K),100*len(diffs)/len(K)))
# group into regions (gap<=12)
regions=[]
for i in diffs:
    if regions and i-regions[-1][1]<=12: regions[-1][1]=i
    else: regions.append([i,i])
print("differing regions: %d"%len(regions))
BASE=0x08001000
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB)
def show(off,ln,buf,tag):
    print(f"   {tag}: ", ' '.join('%02x'%b for b in buf[off:off+ln]))
for a,b in regions:
    ln=b-a+1
    fa=max(0,a-2); fl=ln+ (a-fa) + 3
    flash=BASE+a
    print(f"\n--- region file 0x{a:05x}..0x{b:05x} (flash 0x{flash:08x}, {ln} B) ---")
    show(fa,fl,S,'SHU 1.5.15')
    show(fa,fl,K,'kasai     ')
    # if it's in code (not the marker/key/SN data areas), disasm both
    if not (0x400<=a<0x460) and a>0x200:
        # align to even for thumb
        da=fa & ~1
        print("   SHU disasm:")
        for ins in list(md.disasm(S[da:da+max(8,fl+4)],BASE+da))[:5]:
            print("     0x%08x %-7s %s"%(ins.address,ins.mnemonic,ins.op_str))
        print("   kasai disasm:")
        for ins in list(md.disasm(K[da:da+max(8,fl+4)],BASE+da))[:5]:
            print("     0x%08x %-7s %s"%(ins.address,ins.mnemonic,ins.op_str))

import struct,zipfile,glob,os
from capstone import *
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
def bodyz(zp):
    z=zipfile.ZipFile(zp)
    for n in z.namelist():
        if n.split('/')[-1]=='FIRM.bin.enc': return dec(z.read(n))[:-4]
    return None
def find(name):
    for zp in glob.glob('deploy/firmware-repo/g3/mcu/*.zip')+glob.glob('apps/n-sak/public/firmware/g3/mcu/*.zip'):
        if os.path.basename(zp)==name: return bodyz(zp)
    return None
K=open('/Users/<user>/.claude/jobs/2abbd798/tmp/kasai/mcu/MCU.dec.bin','rb').read()
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB);BASE=0x08001000
for ref in ('N-SAK MCU CFW 2.4.0.zip','N-SAK MCU CFW 2.3.3.zip'):
    S=find(ref)
    if S is None: print("MISSING",ref);continue
    print(f"\n########## kasai MCU vs {ref} (len {len(S)} vs {len(K)}) ##########")
    if len(S)!=len(K):
        print("  (different length; showing aligned-prefix diff)")
    n=min(len(S),len(K))
    diffs=[i for i in range(n) if K[i]!=S[i]]
    print("  differing bytes over common %d: %d (%.3f%%)"%(n,len(diffs),100*len(diffs)/n))
    regions=[]
    for i in diffs:
        if regions and i-regions[-1][1]<=12: regions[-1][1]=i
        else: regions.append([i,i])
    print("  regions:",len(regions))
    for a,b in regions:
        ln=b-a+1;fa=max(0,a-2);fl=ln+(a-fa)+3
        print(f"   -- 0x{a:05x}..0x{b:05x} (flash 0x{BASE+a:08x}, {ln}B) --")
        print("      %s:"%ref[:18],' '.join('%02x'%x for x in S[fa:fa+fl]))
        print("      kasai            :",' '.join('%02x'%x for x in K[fa:fa+fl]))
        if a>0x460 or a<0x400:
            da=fa&~1
            sd=list(md.disasm(S[da:da+max(8,fl+4)],BASE+da))[:4]
            kd=list(md.disasm(K[da:da+max(8,fl+4)],BASE+da))[:4]
            print("      ref  :", '  '.join("%s %s"%(i.mnemonic,i.op_str) for i in sd))
            print("      kasai:", '  '.join("%s %s"%(i.mnemonic,i.op_str) for i in kd))
        else:
            print("      ascii ref/kasai @0x400:",''.join(chr(c) if 32<=c<127 else '.' for c in S[0x400:0x420]),"/",''.join(chr(c) if 32<=c<127 else '.' for c in K[0x400:0x420]))

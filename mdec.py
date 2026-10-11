import struct
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
def xtea_db(v0,v1,k):
    s=u32(DELTA*ROUNDS)
    for _ in range(ROUNDS):
        v1=u32(v1-(u32(u32(((v0<<4)&0xffffffff)^(v0>>5))+v0)^u32(s+k[(s>>11)&3])))
        s=u32(s-DELTA)
        v0=u32(v0-(u32(u32(((v1<<4)&0xffffffff)^(v1>>5))+v1)^u32(s+k[s&3])))
    return v0,v1
def rot(k):
    b=bytearray(struct.pack('<4I',*k))
    for i in range(16):b[i]=(b[i]+i)&0xff
    return list(struct.unpack('<4I',bytes(b)))
DEF=list(struct.unpack('<4I',bytes.fromhex('fe801cb2d1ef41a6a41731f5a06824f0')))
def dec(enc,algo):
    k=DEF[:];lo=hi=0;proc=0;out=bytearray(len(enc))
    for i in range(0,len(enc)-len(enc)%8,8):
        if proc==1024:k=rot(k);proc=0
        c0=rd(enc,i);c1=rd(enc,i+4)
        d0,d1=(tea_db if algo=='tea' else xtea_db)(c0,c1,k)
        struct.pack_into('<I',out,i,u32(d0^lo));struct.pack_into('<I',out,i+4,u32(d1^hi));lo=c0;hi=c1;proc+=8
    return bytes(out)
def cksum(data):
    s=0
    for i in range(0,len(data)-len(data)%4,4):s=u32(s+rd(data,i))
    return u32(u32(((s>>16)&0xffff)|((s&0xffff)<<16))^0xffffffff)

enc=open('/Users/<user>/.claude/jobs/2abbd798/tmp/kasai/mcu/MCU.bin.enc','rb').read()
for algo in ('tea','xtea'):
    d=dec(enc,algo)
    sp=rd(d,0);rv=rd(d,4)
    ok=(sp&0x2FFE0000)==0x20000000 and 0x08000000<=rv<0x08020000 and rv&1
    body=d[:-4];tc=rd(d,len(d)-4)
    print(f"{algo}: SP=0x{sp:08x} RV=0x{rv:08x} VT_ok={ok} checksum_match={cksum(body)==tc}")
    if ok:
        open('/Users/<user>/.claude/jobs/2abbd798/tmp/kasai/mcu/MCU.dec.bin','wb').write(body)
        print("  -> wrote MCU.dec.bin (%d bytes)"%len(body))
        print("  keyslot 0x420(22):",body[0x420:0x436].hex())
        print("  marker 0x400(32):",body[0x400:0x420].hex(),"|",''.join(chr(c) if 32<=c<127 else '.' for c in body[0x400:0x420]))

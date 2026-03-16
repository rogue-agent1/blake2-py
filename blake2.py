import hashlib
SIGMA=[[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],[14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3],
       [11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4],[7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8],
       [9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13],[2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9],
       [12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11],[13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10],
       [6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5],[10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0]]
IV=[0x6A09E667,0xBB67AE85,0x3C6EF372,0xA54FF53A,0x510E527F,0x9B05688C,0x1F83D9AB,0x5BE0CD19]
M32=0xFFFFFFFF
def G(v,a,b,c,d,x,y):
    v[a]=(v[a]+v[b]+x)&M32; v[d]=((v[d]^v[a])>>16|((v[d]^v[a])<<16))&M32
    v[c]=(v[c]+v[d])&M32; v[b]=((v[b]^v[c])>>12|((v[b]^v[c])<<20))&M32
    v[a]=(v[a]+v[b]+y)&M32; v[d]=((v[d]^v[a])>>8|((v[d]^v[a])<<24))&M32
    v[c]=(v[c]+v[d])&M32; v[b]=((v[b]^v[c])>>7|((v[b]^v[c])<<25))&M32
def blake2s(msg,digest_size=32):
    import struct
    if isinstance(msg,str): msg=msg.encode()
    h=list(IV); h[0]^=0x01010000^digest_size
    msg=bytearray(msg); t=0
    while len(msg)>64:
        block=msg[:64]; msg=msg[64:]; t+=64
        m=list(struct.unpack('<16I',bytes(block)))
        v=list(h)+list(IV); v[12]^=t&M32; v[13]^=(t>>32)&M32
        for i in range(10):
            s=SIGMA[i]
            G(v,0,4,8,12,m[s[0]],m[s[1]]); G(v,1,5,9,13,m[s[2]],m[s[3]])
            G(v,2,6,10,14,m[s[4]],m[s[5]]); G(v,3,7,11,15,m[s[6]],m[s[7]])
            G(v,0,5,10,15,m[s[8]],m[s[9]]); G(v,1,6,11,12,m[s[10]],m[s[11]])
            G(v,2,7,8,13,m[s[12]],m[s[13]]); G(v,3,4,9,14,m[s[14]],m[s[15]])
        for i in range(8): h[i]^=v[i]^v[i+8]
    block=bytes(msg)+b'\x00'*(64-len(msg)); t+=len(msg)
    m=list(struct.unpack('<16I',block))
    v=list(h)+list(IV); v[12]^=t&M32; v[14]^=M32
    for i in range(10):
        s=SIGMA[i]
        G(v,0,4,8,12,m[s[0]],m[s[1]]); G(v,1,5,9,13,m[s[2]],m[s[3]])
        G(v,2,6,10,14,m[s[4]],m[s[5]]); G(v,3,7,11,15,m[s[6]],m[s[7]])
        G(v,0,5,10,15,m[s[8]],m[s[9]]); G(v,1,6,11,12,m[s[10]],m[s[11]])
        G(v,2,7,8,13,m[s[12]],m[s[13]]); G(v,3,4,9,14,m[s[14]],m[s[15]])
    for i in range(8): h[i]^=v[i]^v[i+8]
    return struct.pack('<8I',*h)[:digest_size].hex()
if __name__=="__main__":
    for t in ["","hello","abc"]:
        mine=blake2s(t); ref=hashlib.blake2s(t.encode()).hexdigest()
        assert mine==ref, f"FAIL: {mine} vs {ref}"
        print(f"OK blake2s({t!r})={mine[:24]}...")
    print("All tests passed!")

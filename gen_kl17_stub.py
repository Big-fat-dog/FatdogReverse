#!/usr/bin/env python3
# 临时：生成 KL17 的 4 段密文常量 + 校验解码 + HMAC 链路 + SUM_HASH。用完删除。
import hashlib, hmac

MARK = b"Fatdog_reclaim"
assert len(MARK) == 14, len(MARK)
# 4 段："Fatd"(0:4) "og_r"(4:8) "ecl"(8:11) "aim"(11:14)
SEGS = [MARK[0:4], MARK[4:8], MARK[8:11], MARK[11:14]]
ROTS = [1, 3, 2, 4]
KEYS = [
    [0x3C, 0x5A, 0x21, 0x7E],
    [0x5A, 0x3C, 0x7E, 0x21],
    [0x21, 0x7E, 0x3C, 0x5A],
    [0x7E, 0x21, 0x5A, 0x3C],
]

def rol8(b, n):
    return ((b << n) | (b >> (8 - n))) & 0xFF
def ror8(b, n):
    return ((b >> n) | (b << (8 - n))) & 0xFF

enc_all = []
print("/* KL17 marker 段常量（类抽取：4 段散布不同函数，各段 rot+xor 不同） */")
for i, (seg, rot, key) in enumerate(zip(SEGS, ROTS, KEYS)):
    enc = []
    for j, ch in enumerate(seg):
        d = rol8(ch, rot)
        enc.append(d ^ key[j % 4])
    enc_all.append(bytes(enc))
    arr = ", ".join("0x%02x" % x for x in enc)
    print("static const unsigned char ENC_%d[%d] = {%s};  /* rot=%d, seg=%r */" % (i, len(enc), arr, rot, seg.decode()))

# 校验解码
rec = b""
for i, (rot, key) in enumerate(zip(ROTS, KEYS)):
    seg = enc_all[i]
    out = bytearray()
    for j, st in enumerate(seg):
        b = st ^ key[j % 4]
        out.append(ror8(b, rot))
    rec += bytes(out)
print("DECODE RECONSTRUCTED:", rec, "MATCH:", rec == MARK)

# HMAC 链路：KEY = SHA256(MARK + "kl17")[:32]
KEY = hashlib.sha256(MARK + b"kl17").digest()
TS = 1787013761
def sign(page, ts):
    msg = ("page=%d&ts=%d" % (page, ts)).encode()
    return hmac.new(KEY, msg, hashlib.sha256).hexdigest()
print("KL17 KEY(hex) =", KEY.hex())
print("sample_sign(page=1,ts=%d) = %s" % (TS, sign(1, TS)))
# 诱饵
DECOY = b"Fatdog_reclaims"
KEYD = hashlib.sha256(DECOY + b"kl17").digest()
def signD(page, ts):
    msg = ("page=%d&ts=%d" % (page, ts)).encode()
    return hmac.new(KEYD, msg, hashlib.sha256).hexdigest()
print("decoy_sign(page=1)   =", signD(1, TS), "DIFFER:", signD(1, TS) != sign(1, TS))

# 服务端取数与 SUM_HASH
SEED = 20260117
import random
rng = random.Random(SEED)
nums = [rng.randint(1, 100) for _ in range(1000)]
s = sum(nums)
print("KL17 SEED=%d  sum=%d  SUM_HASH=%s" % (SEED, s, hashlib.sha256(str(s).encode()).hexdigest()))

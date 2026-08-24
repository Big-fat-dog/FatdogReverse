#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gen_kl10.py —— 「万象归一」so 生成器（魔改 SHA256 变体 + 魔改 AES 综合卷）

产出 app/jni/m5.c（libm5.so）：
  - 双层叠加签名：sign = hex( 魔改AES-128-ECB( aes_key, 魔改SHA256(payload) ) )
      * 第一层 SHA256 变体：K 表/压缩轮与标准一致，但初始 IV 整组替换为
        sha256("<标记>|"iv")（32B -> 8 个大端字），且消息填充边界从标准 56 改为 48
        （0x80 后补零至偏移 48，8 字节大端位长写在 48..55）——同输入摘要必然不同。
      * 第二层 AES-128：S 盒/行移位/列混合结构可认，但 MixColumns 系数
        {2,3} 对调为 {3,2}。
    payload 形如 "page=N&ts=T"（零填充到 32 字节）。
  - 密钥运行时派生：sha_iv = sha256(<标记>|"iv")；aes_key = sha256(<标记>|"key")[:16]；
    真标记 Fatdog_eclipse 以 UTF-16 码元非 static 非 const 全局藏匿。
  - 明文诱饵标记 Fatdog_ellipse（eclipse 一字之差）+ DECOY_BLOB（诱饵钥加密的假载荷）。
  - 导出面：JNI 两入口（分层暴露便于观察）+ m5_decoy_seal + 两个噪声函数。

自测：
  1) 标准路径（标准 IV + 标准 56 填充）与 hashlib.sha256 对拍；
  2) 标准 AES（MixColumns {2,3}）过 FIPS-197 官方向量；
  3) 魔改路径输出确定、且两层各自与标准结果不同；
  4) S 盒为字节排列校验。

用法：python gen_kl10.py   （在项目根目录执行）
"""

import hashlib
import sys

# ---------------- AES ----------------

SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]

RCON_STD = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


def xt(a):
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1)


def gmul(a, b):
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        a = xt(a)
        b >>= 1
    return r


def key_expand(key):
    rk = [bytearray(key)]
    for i in range(1, 11):
        prev = rk[-1]
        cur = bytearray(16)
        t = [SBOX[prev[13]], SBOX[prev[14]], SBOX[prev[15]], SBOX[prev[12]]]
        t[0] ^= RCON_STD[i - 1]
        for j in range(4):
            cur[j] = prev[j] ^ t[j]
        for j in range(4, 16):
            cur[j] = prev[j] ^ cur[j - 4]
        rk.append(cur)
    return rk


def enc_block(blk, rk, mix_swap=False):
    """mix_swap=False 标准 MixColumns{2,3}；True 时对调为 {3,2}"""
    s = bytearray(blk)

    def ark(k):
        for i in range(16):
            s[i] ^= k[i]

    def shift():
        t = s[1]
        s[1], s[5], s[9], s[13] = s[5], s[9], s[13], t
        s[2], s[10] = s[10], s[2]
        s[6], s[14] = s[14], s[6]
        t = s[3]
        s[3], s[7], s[11], s[15] = s[15], s[3], s[7], s[11]

    def mix():
        c0, c1 = (3, 2) if mix_swap else (2, 3)
        for c in range(4):
            a0, a1, a2, a3 = s[4*c], s[4*c+1], s[4*c+2], s[4*c+3]
            s[4*c+0] = gmul(a0, c0) ^ gmul(a1, c1) ^ a2 ^ a3
            s[4*c+1] = a0 ^ gmul(a1, c0) ^ gmul(a2, c1) ^ a3
            s[4*c+2] = a0 ^ a1 ^ gmul(a2, c0) ^ gmul(a3, c1)
            s[4*c+3] = gmul(a0, c1) ^ a1 ^ a2 ^ gmul(a3, c0)

    ark(rk[0])
    for r in range(1, 10):
        for i in range(16):
            s[i] = SBOX[s[i]]
        shift()
        mix()
        ark(rk[r])
    for i in range(16):
        s[i] = SBOX[s[i]]
    shift()
    ark(rk[10])
    return bytes(s)


def ecb_encrypt(key16, data, mix_swap=False):
    rk = key_expand(key16)
    return b"".join(enc_block(data[i:i + 16], rk, mix_swap)
                    for i in range(0, len(data), 16))


# ---------------- SHA-256 变体 ----------------

_K_HEX = (
    "428a2f9871374491b5c0fbcfe9b5dba53956c25b59f111f1923f82a4ab1c5ed5"
    "d807aa9812835b01243185be550c7dc372be5d7480deb1fe9bdc06a7c19bf174"
    "e49b69c1efbe47860fc19dc6240ca1cc2de92c6f4a7484aa5cb0a9dc76f988da"
    "983e5152a831c66db00327c8bf597fc7c6e00bf3d5a7914706ca635114292967"
    "27b70a852e1b21384d2c6dfc53380d13650a7354766a0abb81c2c92e92722c85"
    "a2bfe8a1a81a664bc24b8b70c76c51a3d192e819d6990624f40e3585106aa070"
    "19a4c1161e376c082748774c34b0bcb5391c0cb34ed8aa4a5b9cca4f682e6ff3"
    "748f82ee78a5636f84c878148cc7020890befffaa4506cebbef9a3f7c67178f2")
_K_W = [int(_K_HEX[i * 8:(i + 1) * 8], 16) for i in range(64)]
_STD_IV = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
           0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]
_M = 0xFFFFFFFF


def _r(x, n):
    return ((x >> n) | (x << (32 - n))) & _M


def sha_var(data: bytes, iv_words=None, boundary=56) -> bytes:
    """boundary=56 即标准填充；48 为本关魔改（长度域前移）。iv_words 缺省标准 IV。"""
    h = list(_STD_IV if iv_words is None else iv_words)
    msg = bytearray(data)
    ml = len(msg) * 8
    msg.append(0x80)
    while len(msg) % 64 != boundary:
        msg.append(0)
    msg += ml.to_bytes(8, "big")
    for off in range(0, len(msg), 64):
        w = [int.from_bytes(msg[off + i * 4:off + i * 4 + 4], "big") for i in range(16)]
        for i in range(16, 64):
            s0 = _r(w[i - 15], 7) ^ _r(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = _r(w[i - 2], 17) ^ _r(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w.append((w[i - 16] + s0 + w[i - 7] + s1) & _M)
        a, b, c, d, e, f, g, hh = h
        for i in range(64):
            S1 = _r(e, 6) ^ _r(e, 11) ^ _r(e, 25)
            ch = (e & f) ^ ((~e & _M) & g)
            t1 = (hh + S1 + ch + _K_W[i] + w[i]) & _M
            S0 = _r(a, 2) ^ _r(a, 13) ^ _r(a, 22)
            mj = (a & b) ^ (a & c) ^ (b & c)
            t2 = (S0 + mj) & _M
            ne = (d + t1) & _M
            hh, g, f, e = g, f, e, ne
            d, c, b, a = c, b, a, (t1 + t2) & _M
        h = [(x + y) & _M for x, y in zip(h, [a, b, c, d, e, f, g, hh])]
    return b"".join(x.to_bytes(4, "big") for x in h)


def pad(b):
    n = (len(b) + 15) // 16 * 16
    return b + b"\x00" * (n - len(b))


# ---------------- 自测 ----------------

def self_test():
    ok = True

    # 0) S 盒排列校验
    if sorted(SBOX) != list(range(256)):
        print("[selftest] FAIL sbox")
        ok = False

    # 1) 标准 SHA-256 与 hashlib 对拍（多组输入含跨块）
    for msg in (b"", b"abc", b"page=1&ts=1787013761", b"x" * 200):
        got = sha_var(msg).hex()
        ref = hashlib.sha256(msg).hexdigest()
        if got != ref:
            print("[selftest] FAIL std sha:", msg[:20])
            ok = False
    print("[selftest] std sha256 matches hashlib")

    # 2) 标准 AES FIPS-197 向量
    vec_key = bytes(range(16))
    vec_pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    want = "69c4e0d86a7b0430d8cdb78070b4c55a"
    got = ecb_encrypt(vec_key, vec_pt).hex()
    print("[selftest] FIPS-197 encrypt:", got)
    if got != want:
        print("[selftest] FAIL aes vector")
        ok = False

    # 3) 魔改两层各自偏离标准
    marker = b"Fatdog_eclipse"
    iv_words = [int.from_bytes(hashlib.sha256(marker + b"|iv").digest()[4*i:4*i+4], "big")
                for i in range(8)]
    pt = b"page=1&ts=1787013761"
    dg_mod = sha_var(pt, iv_words, boundary=48)
    dg_std = hashlib.sha256(pt).digest()
    print("[selftest] mod sha differs :", dg_mod.hex() != dg_std.hex())
    if dg_mod == dg_std:
        ok = False
    aes_key = hashlib.sha256(marker + b"|key").digest()[:16]
    sg_mod = ecb_encrypt(aes_key, pad(dg_mod), mix_swap=True)
    sg_std = ecb_encrypt(vec_key, pad(dg_mod), mix_swap=False)
    print("[selftest] mod aes differs :", sg_mod[:8].hex(), "!=", sg_std[:8].hex())
    if sg_mod == sg_std:
        ok = False

    if not ok:
        sys.exit("self-test FAILED, refuse to emit C")


# ---------------- 关卡素材 ----------------

MARKER = "Fatdog_eclipse"               # 真标记（UTF-16 藏匿）
DECOY_MARKER = "Fatdog_ellipse"         # 明文诱饵标记（eclipse 一字之差）
DECOY_PAYLOAD = "page=21&ts=1700000000"

IV_WORDS = [int.from_bytes(hashlib.sha256(MARKER.encode() + b"|iv").digest()[4*i:4*i+4], "big")
            for i in range(8)]
AES_KEY = hashlib.sha256(MARKER.encode() + b"|key").digest()[:16]
DECOY_KEY = hashlib.sha256(DECOY_MARKER.encode() + b"|key").digest()[:16]


def core_digest(page, ts):
    return sha_var(f"page={page}&ts={ts}".encode(), IV_WORDS, boundary=48)


def core_sign(page, ts):
    return ecb_encrypt(AES_KEY, pad(core_digest(page, ts)), mix_swap=True)


DECOY_BLOB = ecb_encrypt(DECOY_KEY, pad(DECOY_PAYLOAD.encode()), mix_swap=True)


# ---------------- C 代码生成 ----------------

def fmt_bytes(data, perline=12, indent="        "):
    rows = []
    for i in range(0, len(data), perline):
        chunk = data[i:i + perline]
        rows.append(indent + ",".join("0x%02x" % v for v in chunk) + ",")
    return "\n".join(rows)


def fmt_units(units, perline=8, indent="        "):
    rows = []
    for i in range(0, len(units), perline):
        chunk = units[i:i + perline]
        rows.append(indent + ", ".join("0x%04x" % u for u in chunk) + ",")
    return "\n".join(rows)


C_TEMPLATE = r"""/* libm5.so ——「万象归一」（由 gen_kl10.py 生成，勿手改）
 * 双层叠加签名：sign = hex( 魔改AES-128-ECB( aes_key, 魔改SHA256(payload) ) )
 *   第一层 SHA256 变体：K 表与压缩轮全标准（认骨架看 K 表 428a2f98…），
 *     但初始 IV 整组换血为派生值，且消息填充边界从 56 前移到 48（多补一轮压缩）。
 *   第二层 AES-128：S 盒/轮结构全标准（认骨架看 S 盒 63 7c 77 7b…），
 *     但 MixColumns 系数 {2,3} 对调为 {3,2}。
 * 密钥运行时派生：iv = sha256(<标记>|"iv")；aes_key = sha256(<标记>|"key")[:16]。
 * 真标记 UTF-16 码元藏匿（strings 盲区）；明文诱饵 Fatdog_ellipse 一字之差。
 */
#include <string.h>
#include <stdio.h>

#ifndef M5_HOST_TEST
#include <jni.h>
#endif

static const unsigned char SBOX[256] = {
@SBOX@
};

/* 真标记 UTF-16 码元：非 static 非 const 全局，防止编译器常量折叠进指令流 */
unsigned short MARK[@MARKLEN@] = {
@MARKER@
};

/* 明文诱饵标记：非 static 保证落盘，strings 一眼可见，一字之差 */
const char DECOY_MARK[] = "@DECOY@";

/* 假密文：用诱饵标记派生的钥加密的一段“像样”假载荷 */
static const unsigned char DECOY_BLOB[32] = {
@DBLOB@
};

/* ---------- SHA-256 变体（自定义 IV + 48 边界填充；消息 <48 字节单块足够） ---------- */

static const unsigned int K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static unsigned int m5_rotr(unsigned int x, int n) { return (x >> n) | (x << (32 - n)); }

/* 变体摘要：h[] 由派生 IV 装载；填充边界 BOUNDARY=48（长度域在 48..55） */
#define M5_BOUNDARY 48

static void m5_sha_block(unsigned int h[8], const unsigned char p[64]) {
    unsigned int w[64];
    unsigned int a,b,c,d,e,f,g,hh,t1,t2,S0,S1,mj;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = ((unsigned int)p[4*i]<<24)|((unsigned int)p[4*i+1]<<16)
             | ((unsigned int)p[4*i+2]<<8)|(unsigned int)p[4*i+3];
    for (i = 16; i < 64; i++) {
        unsigned int s0 = m5_rotr(w[i-15],7) ^ m5_rotr(w[i-15],18) ^ (w[i-15]>>3);
        unsigned int s1 = m5_rotr(w[i-2],17) ^ m5_rotr(w[i-2],19) ^ (w[i-2]>>10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a=h[0];b=h[1];c=h[2];d=h[3];e=h[4];f=h[5];g=h[6];hh=h[7];
    for (i = 0; i < 64; i++) {
        S1 = m5_rotr(e,6)^m5_rotr(e,11)^m5_rotr(e,25);
        t1 = hh + S1 + ((e&f)^((~e)&g)) + K256[i] + w[i];
        S0 = m5_rotr(a,2)^m5_rotr(a,13)^m5_rotr(a,22);
        mj = (a&b)^(a&c)^(b&c);
        t2 = S0 + mj;
        hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
}

static void m5_derive(const char *suffix, unsigned char *out, int outlen);
static void m5_std_sha(const unsigned char *msg, unsigned int len, unsigned char out[32]);

static void m5_sha_variant(const unsigned char *msg, unsigned int len, unsigned char out[32]) {
    unsigned char h_bytes[32];
    unsigned int h[8];
    unsigned char tail[128];
    unsigned long long bits = (unsigned long long)len * 8ULL;
    int i;
    /* 初始 IV 来自运行时派生（明文字面量会被 strings 一把梭） */
    m5_derive("|iv", h_bytes, 32);
    for (i = 0; i < 8; i++)
        h[i] = ((unsigned int)h_bytes[4*i]<<24)|((unsigned int)h_bytes[4*i+1]<<16)
             | ((unsigned int)h_bytes[4*i+2]<<8)|(unsigned int)h_bytes[4*i+3];
    if (len > M5_BOUNDARY - 1) len = M5_BOUNDARY - 1; /* 派生场景恒短消息，钳制即可 */
    memset(tail, 0, sizeof(tail));
    memcpy(tail, msg, len);
    tail[len] = 0x80;
    for (i = 0; i < 8; i++)
        tail[M5_BOUNDARY + i] = (unsigned char)((bits >> (8 * (7 - i))) & 0xFF);
    m5_sha_block(h, tail);
    for (i = 0; i < 8; i++) {
        out[4*i]   = (unsigned char)(h[i]>>24);
        out[4*i+1] = (unsigned char)(h[i]>>16);
        out[4*i+2] = (unsigned char)(h[i]>>8);
        out[4*i+3] = (unsigned char)(h[i]);
    }
}

/* ---------- 魔改 AES-128 加密（MixColumns {2,3} -> {3,2}） ---------- */

static const unsigned char RCON_TAB[10] = {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

static void m5_ark(unsigned char s[16], const unsigned char k[16]) {
    int i; for (i = 0; i < 16; i++) s[i] ^= k[i];
}

static void m5_key_expand(const unsigned char *key, unsigned char rk[11][16]) {
    int i, j;
    unsigned char t[4];
    memcpy(rk[0], key, 16);
    for (i = 1; i <= 10; i++) {
        const unsigned char *p = rk[i-1];
        unsigned char *c = rk[i];
        t[0] = SBOX[p[13]] ^ RCON_TAB[i-1];
        t[1] = SBOX[p[14]];
        t[2] = SBOX[p[15]];
        t[3] = SBOX[p[12]];
        for (j = 0; j < 4; j++) c[j] = p[j] ^ t[j];
        for (j = 4; j < 16; j++) c[j] = p[j] ^ c[j-4];
    }
}


static unsigned char m5_xt(unsigned char a) {
    return (unsigned char)((a & 0x80) ? ((a << 1) ^ 0x1B) : (a << 1));
}

static unsigned char m5_gmul(unsigned char a, unsigned char b) {
    unsigned char r = 0;
    while (b) {
        if (b & 1) r ^= a;
        a = m5_xt(a);
        b >>= 1;
    }
    return r;
}

static void m5_mix(unsigned char s[16]) {
    /* 本关魔改点：系数 {2,3} 对调为 {3,2} */
    int c;
    for (c = 0; c < 4; c++) {
        unsigned char a0=s[4*c],a1=s[4*c+1],a2=s[4*c+2],a3=s[4*c+3];
        s[4*c+0] = m5_gmul(a0,3)^m5_gmul(a1,2)^a2^a3;
        s[4*c+1] = a0^m5_gmul(a1,3)^m5_gmul(a2,2)^a3;
        s[4*c+2] = a0^a1^m5_gmul(a2,3)^m5_gmul(a3,2);
        s[4*c+3] = m5_gmul(a0,2)^a1^a2^m5_gmul(a3,3);
    }
}

static void m5_shift(unsigned char s[16]) {
    unsigned char t;
    t = s[1];  s[1] = s[5];  s[5] = s[9];  s[9] = s[13]; s[13] = t;
    t = s[2];  s[2] = s[10]; s[10] = t;
    t = s[6];  s[6] = s[14]; s[14] = t;
    t = s[3];  s[3] = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = t;
}


static void m5_enc_block(const unsigned char *in, unsigned char *out,
                         unsigned char rk[11][16]) {
    unsigned char s[16];
    int r, i;
    memcpy(s, in, 16);
    m5_ark(s, rk[0]);
    for (r = 1; r <= 9; r++) {
        for (i = 0; i < 16; i++) s[i] = SBOX[s[i]];
        m5_shift(s);
        m5_mix(s);
        m5_ark(s, rk[r]);
    }
    for (i = 0; i < 16; i++) s[i] = SBOX[s[i]];
    m5_shift(s);
    m5_ark(s, rk[10]);
    memcpy(out, s, 16);
}

/* 标记运行时拼装 + 派生 */
static void m5_derive(const char *suffix, unsigned char *out, int outlen) {
    char mk[32];
    char msg[48];
    unsigned char dg[32];
    int i, n = sizeof(MARK) / sizeof(unsigned short);
    int slen = (int)strlen(suffix);
    /* 用标准 SHA-256（标准 IV + 标准 56 填充）做密钥派生 */
    for (i = 0; i < n; i++) mk[i] = (char)(MARK[i] & 0xFF);
    mk[n] = 0;
    memcpy(msg, mk, (size_t)n);
    memcpy(msg + n, suffix, (size_t)slen);
    m5_std_sha((const unsigned char *)msg, (unsigned int)(n + slen), dg);
    memcpy(out, dg, (size_t)outlen);
}

/* 标准 SHA-256（仅用于密钥派生；签名第一层用的是上面的变体） */
static void m5_std_sha(const unsigned char *msg, unsigned int len, unsigned char out[32]) {
    unsigned int h[8];
    unsigned int off, rem, tlen, i;
    unsigned char tail[128];
    unsigned long long bits = (unsigned long long)len * 8ULL;
    h[0]=0x6a09e667;h[1]=0xbb67ae85;h[2]=0x3c6ef372;h[3]=0xa54ff53a;
    h[4]=0x510e527f;h[5]=0x9b05688c;h[6]=0x1f83d9ab;h[7]=0x5be0cd19;
    for (off = 0; off + 64 <= len; off += 64)
        m5_sha_block(h, msg + off);
    rem = len - off;
    memset(tail, 0, sizeof(tail));
    memcpy(tail, msg + off, rem);
    tail[rem] = 0x80;
    tlen = (rem + 9 <= 64) ? 64 : 128;
    for (i = 0; i < 8; i++)
        tail[tlen - 1 - i] = (unsigned char)((bits >> (8 * i)) & 0xFF);
    m5_sha_block(h, tail);
    if (tlen == 128) m5_sha_block(h, tail + 64);
    for (i = 0; i < 8; i++) {
        out[4*i]   = (unsigned char)(h[i]>>24);
        out[4*i+1] = (unsigned char)(h[i]>>16);
        out[4*i+2] = (unsigned char)(h[i]>>8);
        out[4*i+3] = (unsigned char)(h[i]);
    }
}

/* ---------- hex 工具 ---------- */

static void m5_hex_encode(const unsigned char *d, int n, char *out) {
    static const char *HEX = "0123456789abcdef";
    int i;
    for (i = 0; i < n; i++) {
        out[2*i]   = HEX[d[i] >> 4];
        out[2*i+1] = HEX[d[i] & 0xF];
    }
    out[2*n] = 0;
}

/* ---------- 业务核心 ---------- */

/* 第一层：魔改 SHA256("page=N&ts=T") -> hex */
static void m5_core_digest(int page, long long ts, char hex[65]) {
    char payload[32];
    unsigned char dg[32];
    int n;
    n = snprintf(payload, sizeof(payload), "page=%d&ts=%lld", page, ts);
    if (n < 0) n = 0;
    if (n > 31) n = 31;
    payload[n] = 0;
    m5_sha_variant((const unsigned char *)payload, (unsigned int)n, dg);
    m5_hex_encode(dg, 32, hex);
}

/* 第二层：魔改 AES-ECB(aes_key, digest 32B) -> hex */
static void m5_core_aes(const unsigned char dg32[32], char hex[65]) {
    unsigned char key[16], rk[11][16], ct[32];
    int i;
    m5_derive("|key", key, 16);
    m5_key_expand(key, rk);
    for (i = 0; i < 32; i += 16)
        m5_enc_block(dg32 + i, ct + i, rk);
    m5_hex_encode(ct, 32, hex);
}

/* ---------- 导出面 ---------- */

const char *m5_decoy_seal(void) {
    static char hex[65];
    m5_hex_encode(DECOY_BLOB, 32, hex);
    return hex;
}

static volatile unsigned int m5_sink;

int m5_fold(unsigned int x) {
    unsigned int v = x;
    int i;
    for (i = 0; i < 4; i++) v = (v ^ (v << 3)) + 0x9E3779B9U;
    m5_sink = v;
    return (int)(v & 0xFFFF);
}

unsigned int m5_spin(unsigned int x, int n) {
    unsigned int v = (n & 31) ? ((x << (n & 31)) | (x >> (32 - (n & 31)))) : x;
    m5_sink = v ^ m5_sink;
    return v;
}

#ifndef M5_HOST_TEST

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Ws_nativeDigest(JNIEnv *env, jclass clazz, jint page, jlong ts) {
    char hex[65];
    (void)clazz;
    m5_core_digest((int)page, (long long)ts, hex);
    return (*env)->NewStringUTF(env, hex);
}

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Ws_nativeSign(JNIEnv *env, jclass clazz, jstring digestHex) {
    char hex[65];
    unsigned char dg[32];
    const char *e;
    int i;
    (void)clazz;
    if (!digestHex) return (*env)->NewStringUTF(env, "ERR_INPUT");
    e = (*env)->GetStringUTFChars(env, digestHex, NULL);
    if (!e) return (*env)->NewStringUTF(env, "ERR_UTF");
    for (i = 0; i < 32; i++) {
        char c1 = e[2*i], c2 = e[2*i+1];
        int hi = (c1<='9')?(c1-'0'):(c1-'a'+10);
        int lo = (c2<='9')?(c2-'0'):(c2-'a'+10);
        dg[i] = (unsigned char)((hi<<4)|lo);
    }
    (*env)->ReleaseStringUTFChars(env, digestHex, e);
    m5_core_aes(dg, hex);
    return (*env)->NewStringUTF(env, hex);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm;(void)reserved;
    return JNI_VERSION_1_6;
}

#endif /* !M5_HOST_TEST */

#ifdef M5_HOST_TEST
/* 主机自测：cc -DM5_HOST_TEST -o m5test m5.c && ./m5test */
int main(void) {
    char dig[65], sign[65];
    m5_core_digest(1, 1787013761LL, dig);
    printf("sample_digest = %s\n", dig);
    /* 复用 nativeSign 的解析路径 */
    {
        unsigned char dg[32];
        char sign2[65];
        int i;
        for (i = 0; i < 32; i++) {
            char c1 = dig[2*i], c2 = dig[2*i+1];
            int hi = (c1<='9')?(c1-'0'):(c1-'a'+10);
            int lo = (c2<='9')?(c2-'0'):(c2-'a'+10);
            dg[i] = (unsigned char)((hi<<4)|lo);
        }
        m5_core_aes(dg, sign2);
        printf("sample_sign   = %s\n", sign2);
    }
    (void)sign;
    return 0;
}
#endif
"""


def main():
    self_test()

    csrc = C_TEMPLATE
    csrc = csrc.replace("@SBOX@", fmt_bytes(bytes(SBOX)))
    csrc = csrc.replace("@MARKLEN@", str(len(MARKER)))
    csrc = csrc.replace("@MARKER@", fmt_units([ord(ch) for ch in MARKER]))
    csrc = csrc.replace("@DECOY@", DECOY_MARKER)
    csrc = csrc.replace("@DBLOB@", fmt_bytes(DECOY_BLOB))

    out_path = "app/jni/m5.c"
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(csrc)

    sample_page, sample_ts = 1, 1787013761
    dig = core_digest(sample_page, sample_ts).hex()
    sign = core_sign(sample_page, sample_ts).hex()
    print()
    print("[emit] %s (%d lines)" % (out_path, csrc.count("\n") + 1))
    print("[info] marker       =", MARKER, "(UTF-16 hidden)")
    print("[info] decoy mark   =", DECOY_MARKER, "(plain strings-visible)")
    print("[info] iv           =", b"".join(w.to_bytes(4, 'big') for w in IV_WORDS).hex())
    print("[info] aes_key      =", AES_KEY.hex())
    print("[info] decoy_key    =", DECOY_KEY.hex())
    print("[info] decoy_blob   =", DECOY_BLOB.hex())
    print("[check] decoy is mod-aes of fake payload:",
          ecb_encrypt(DECOY_KEY, pad(DECOY_PAYLOAD.encode()), mix_swap=True).hex())
    print("[sample] page=%d ts=%d" % (sample_page, sample_ts))
    print("[sample] digest =", dig)
    print("[sample] sign   =", sign)


if __name__ == "__main__":
    main()

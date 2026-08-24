#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gen_kl8.py —— 「幽泉之眼」so 生成器（魔改 SM4 · CK 尾部换血）

产出 app/jni/m3.c（libm3.so）：
  - 手写 SM4：FK 不变、S 盒不变（d690e9fe 可认骨架），但轮常量 CK 的
    最后 8 个值（CK[24..31]）被替换为自定义常量 → 第 25~32 轮的轮密钥编排
    全部偏移，标准 SM4 解不开本关密文。
    自定义值来自 sha256("Fatdog_unravel|ck") 前 32 字节（8 个大端字），可复算。
  - 密钥运行时派生：sm4_key = sha256(<标记>|"sm4")[:16]，mac = sha256(<标记>|"mac")；
    真标记 Fatdog_unravel 以 UTF-16 码元非 static 非 const 全局藏匿（strings 盲区）。
  - 明文诱饵标记 Fatdog_travel（unravel 一字之差，用它派生钥的请求一律 403）
    + DECOY_BLOB（诱饵钥加密的"像样"假载荷）。
  - 导出面克制低调：JNI 两个真入口 + m3_decoy_seal + 两个噪声函数。

自测：
  1) 标准 CK 下过 GB/T 32907 官方向量
     （key=pt=0123456789abcdeffedcba9876543210 -> 681edf34d206965e86b3e94f536e4246）；
  2) 换血 CK 下加解密回环一致，且输出与标准 SM4 不同；
  3) S 盒每行均为 0..255 的字节排列、标准 CK 与公式 (4i+j)*7 mod 256 一致。

用法：python gen_kl8.py   （在项目根目录执行）
"""

import hashlib
import hmac as py_hmac
import sys

# ---------------- 标准 SM4 常量 ----------------

SBOX = [
    0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
    0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
    0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
    0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
    0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
    0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
    0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
    0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
    0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
    0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
    0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
    0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
    0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
    0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
    0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
    0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48,
]

FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]

M32 = 0xFFFFFFFF


def make_ck():
    ck = []
    for i in range(32):
        w = 0
        for j in range(4):
            w |= (((4 * i + j) * 7) % 256) << (24 - 8 * j)
        ck.append(w)
    return ck


CK_STD = make_ck()


def rotl(x, n):
    return ((x << n) | (x >> (32 - n))) & M32


def tau(a):
    return ((SBOX[(a >> 24) & 0xFF] << 24) | (SBOX[(a >> 16) & 0xFF] << 16)
            | (SBOX[(a >> 8) & 0xFF] << 8) | SBOX[a & 0xFF])


def t_enc(x):
    b = tau(x)
    return b ^ rotl(b, 2) ^ rotl(b, 10) ^ rotl(b, 18) ^ rotl(b, 24)


def t_key(x):
    b = tau(x)
    return b ^ rotl(b, 13) ^ rotl(b, 23)


def key_expand(key16, ck_tab):
    k = [int.from_bytes(key16[4 * i:4 * i + 4], "big") for i in range(4)]
    k = [k[i] ^ FK[i] for i in range(4)]
    rk = []
    for i in range(32):
        v = k[i] ^ t_key(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ ck_tab[i])
        k.append(v)
        rk.append(v)
    return rk


def crypt_block(blk, rk, decrypt):
    x = [int.from_bytes(blk[4 * i:4 * i + 4], "big") for i in range(4)]
    for i in range(32):
        r = (31 - i) if decrypt else i
        x.append(x[i] ^ t_enc(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ rk[r]))
    out = b"".join(x[35 - i].to_bytes(4, "big") for i in range(4))
    return out


def ecb_crypt(key16, data, ck_tab, decrypt=False):
    rk = key_expand(key16, ck_tab)
    return b"".join(crypt_block(data[i:i + 16], rk, decrypt)
                    for i in range(0, len(data), 16))


# ---------------- 自测 ----------------

def self_test():
    ok = True

    # 0) 结构校验：S 盒是字节排列；标准 CK 与公式一致
    if sorted(SBOX) != list(range(256)):
        print("[selftest] FAIL sbox not a permutation")
        ok = False

    # 1) GB/T 32907 官方向量（标准 CK）
    vec = bytes.fromhex("0123456789abcdeffedcba9876543210")
    want = "681edf34d206965e86b3e94f536e4246"
    got = ecb_crypt(vec, vec, CK_STD).hex()
    print("[selftest] GB/T 32907 encrypt:", got)
    if got != want:
        print("[selftest] FAIL standard vector")
        ok = False
    back = ecb_crypt(vec, bytes.fromhex(got), CK_STD, decrypt=True)
    if back != vec:
        print("[selftest] FAIL standard roundtrip")
        ok = False

    # 2) 换血 CK 回环 + 与标准差异
    marker = b"Fatdog_unravel"
    ck_mod = list(CK_STD)
    seed_words = hashlib.sha256(marker + b"|ck").digest()
    for i in range(8):
        ck_mod[24 + i] = int.from_bytes(seed_words[4 * i:4 * i + 4], "big")
    pt = pad(b"page=1&ts=1787013761")
    k = bytes(range(16))
    c_mod = ecb_crypt(k, pt, ck_mod)
    c_std = ecb_crypt(k, pt, CK_STD)
    print("[selftest] modified roundtrip :", ecb_crypt(k, c_mod, ck_mod, decrypt=True) == pt)
    if ecb_crypt(k, c_mod, ck_mod, decrypt=True) != pt:
        print("[selftest] FAIL modified roundtrip")
        ok = False
    if c_mod == c_std:
        print("[selftest] FAIL modified output identical to standard")
        ok = False
    print("[selftest] mod vs std differ  :", c_mod[:8].hex(), "!=", c_std[:8].hex())
    print("[selftest] replaced CK[24..31]:", " ".join("%08x" % v for v in ck_mod[24:]))

    if not ok:
        sys.exit("self-test FAILED, refuse to emit C")


def pad(b):
    n = (len(b) + 15) // 16 * 16
    return b + b"\x00" * (n - len(b))


# ---------------- 关卡素材 ----------------

MARKER = "Fatdog_unravel"               # 真标记（UTF-16 藏匿）
DECOY_MARKER = "Fatdog_travel"          # 明文诱饵标记（unravel 一字之差）
DECOY_PAYLOAD = "page=9&ts=1700000000"  # 用假钥解出来会看到的“像样”假载荷

SM4_KEY = hashlib.sha256(MARKER.encode() + b"|sm4").digest()[:16]
MAC_KEY = hashlib.sha256(MARKER.encode() + b"|mac").digest()
DECOY_KEY = hashlib.sha256(DECOY_MARKER.encode() + b"|sm4").digest()[:16]

CK_MOD = list(CK_STD)
_seed = hashlib.sha256(MARKER.encode() + b"|ck").digest()
for _i in range(8):
    CK_MOD[24 + _i] = int.from_bytes(_seed[4 * _i:4 * _i + 4], "big")

DECOY_BLOB = ecb_crypt(DECOY_KEY, pad(DECOY_PAYLOAD.encode()), CK_MOD)


def core_enc(page, ts):
    return ecb_crypt(SM4_KEY, pad(f"page={page}&ts={ts}".encode()), CK_MOD)


def core_sign(enc_hex):
    return py_hmac.new(MAC_KEY, enc_hex.encode(), hashlib.sha256).hexdigest()


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


def fmt_words(words, perline=4, indent="        "):
    rows = []
    for i in range(0, len(words), perline):
        chunk = words[i:i + perline]
        rows.append(indent + ", ".join("0x%08x" % w for w in chunk) + ",")
    return "\n".join(rows)


C_TEMPLATE = r"""/* libm3.so ——「幽泉之眼」（由 gen_kl8.py 生成，勿手改）
 * 手写 SM4：FK 与 S 盒均为标准——认骨架足够（S 盒开头 d6 90 e9 fe，
 * FK 开头 a3b1bac6）；但轮常量 CK 的最后 8 个值（idx24..31）被换过血，
 * 因此第 25~32 轮的轮密钥全部跑偏，标准 SM4 解不开本关密文。
 *
 * 密钥全部运行时派生：
 *   sm4_key = sha256(<标记>|"sm4") 前 16 字节
 *   mac     = sha256(<标记>|"mac") 全 32 字节
 * 真标记存成 UTF-16 码元数组（非 static 非 const 全局），默认 strings 不显示；
 * 另有一个明文诱饵标记与一段假密文等着粗心的猎物。
 */
#include <string.h>
#include <stdio.h>

#ifndef M3_HOST_TEST
#include <jni.h>
#endif

static const unsigned char SBOX[256] = {
@SBOX@
};

/* 标准系统参数 */
static const unsigned int FK[4] = {0xa3b1bac6,0x56aa3350,0x677d9197,0xb27022dc};

/* 轮常量 CK：前 24 个标准（=(4i+j)*7 mod 256 规律）；最后 8 个被换血（本关魔改点） */
static const unsigned int CK[32] = {
@CKMOD@
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

/* ---------- SHA-256 / HMAC-SHA256（紧凑实现，供派生/签名复用） ---------- */

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

static unsigned int m3_rotr(unsigned int x, int n) { return (x >> n) | (x << (32 - n)); }

static void m3_sha_block(unsigned int h[8], const unsigned char p[64]) {
    unsigned int w[64];
    unsigned int a,b,c,d,e,f,g,hh,t1,t2,S0,S1,mj;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = ((unsigned int)p[4*i]<<24)|((unsigned int)p[4*i+1]<<16)
             | ((unsigned int)p[4*i+2]<<8)|(unsigned int)p[4*i+3];
    for (i = 16; i < 64; i++) {
        unsigned int s0 = m3_rotr(w[i-15],7) ^ m3_rotr(w[i-15],18) ^ (w[i-15]>>3);
        unsigned int s1 = m3_rotr(w[i-2],17) ^ m3_rotr(w[i-2],19) ^ (w[i-2]>>10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a=h[0];b=h[1];c=h[2];d=h[3];e=h[4];f=h[5];g=h[6];hh=h[7];
    for (i = 0; i < 64; i++) {
        S1 = m3_rotr(e,6)^m3_rotr(e,11)^m3_rotr(e,25);
        t1 = hh + S1 + ((e&f)^((~e)&g)) + K256[i] + w[i];
        S0 = m3_rotr(a,2)^m3_rotr(a,13)^m3_rotr(a,22);
        mj = (a&b)^(a&c)^(b&c);
        t2 = S0 + mj;
        hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
}

static void m3_sha256(const unsigned char *msg, unsigned int len, unsigned char out[32]) {
    unsigned int h[8];
    unsigned int off, rem, tlen, i;
    unsigned char tail[128];
    unsigned long long bits = (unsigned long long)len * 8ULL;
    h[0]=0x6a09e667;h[1]=0xbb67ae85;h[2]=0x3c6ef372;h[3]=0xa54ff53a;
    h[4]=0x510e527f;h[5]=0x9b05688c;h[6]=0x1f83d9ab;h[7]=0x5be0cd19;
    for (off = 0; off + 64 <= len; off += 64)
        m3_sha_block(h, msg + off);
    rem = len - off;
    memset(tail, 0, sizeof(tail));
    memcpy(tail, msg + off, rem);
    tail[rem] = 0x80;
    tlen = (rem + 9 <= 64) ? 64 : 128;
    for (i = 0; i < 8; i++)
        tail[tlen - 1 - i] = (unsigned char)((bits >> (8 * i)) & 0xFF);
    m3_sha_block(h, tail);
    if (tlen == 128) m3_sha_block(h, tail + 64);
    for (i = 0; i < 8; i++) {
        out[4*i]   = (unsigned char)(h[i]>>24);
        out[4*i+1] = (unsigned char)(h[i]>>16);
        out[4*i+2] = (unsigned char)(h[i]>>8);
        out[4*i+3] = (unsigned char)(h[i]);
    }
}

static void m3_hmac_sha256(const unsigned char *key, unsigned int klen,
                           const unsigned char *msg, unsigned int mlen,
                           unsigned char out[32]) {
    unsigned char k0[64], ipad[64], opad[64], ih[32], buf[192];
    unsigned int i;
    memset(k0, 0, sizeof(k0));
    if (klen > 64) m3_sha256(key, klen, k0);
    else memcpy(k0, key, klen);
    for (i = 0; i < 64; i++) { ipad[i] = k0[i] ^ 0x36; opad[i] = k0[i] ^ 0x5c; }
    if (mlen > 120) mlen = 120;
    memcpy(buf, ipad, 64);
    memcpy(buf + 64, msg, mlen);
    m3_sha256(buf, 64 + mlen, ih);
    memcpy(buf, opad, 64);
    memcpy(buf + 64, ih, 32);
    m3_sha256(buf, 96, out);
}

/* ---------- 魔改 SM4 核心 ---------- */

static unsigned int m3_rotl(unsigned int x, int n) {
    return n ? ((x << n) | (x >> (32 - n))) : x;
}

static unsigned int m3_tau(unsigned int a) {
    return ((unsigned int)SBOX[(a >> 24) & 0xFF] << 24)
         | ((unsigned int)SBOX[(a >> 16) & 0xFF] << 16)
         | ((unsigned int)SBOX[(a >> 8) & 0xFF] << 8)
         | (unsigned int)SBOX[a & 0xFF];
}

static unsigned int m3_t_enc(unsigned int x) {
    unsigned int b = m3_tau(x);
    return b ^ m3_rotl(b, 2) ^ m3_rotl(b, 10) ^ m3_rotl(b, 18) ^ m3_rotl(b, 24);
}

static unsigned int m3_t_key(unsigned int x) {
    unsigned int b = m3_tau(x);
    return b ^ m3_rotl(b, 13) ^ m3_rotl(b, 23);
}

static void m3_key_expand(const unsigned char key[16], unsigned int rk[32]) {
    unsigned int k[36];
    int i;
    for (i = 0; i < 4; i++)
        k[i] = ((unsigned int)key[4*i]<<24)|((unsigned int)key[4*i+1]<<16)
             | ((unsigned int)key[4*i+2]<<8)|(unsigned int)key[4*i+3];
    for (i = 0; i < 4; i++) k[i] ^= FK[i];
    for (i = 0; i < 32; i++) {
        k[4+i] = k[i] ^ m3_t_key(k[i+1] ^ k[i+2] ^ k[i+3] ^ CK[i]);
        rk[i] = k[4+i];
    }
}

static void m3_crypt_block(const unsigned char in[16], unsigned char out[16],
                           const unsigned int rk[32], int decrypt) {
    unsigned int x[36];
    int i, r;
    for (i = 0; i < 4; i++)
        x[i] = ((unsigned int)in[4*i]<<24)|((unsigned int)in[4*i+1]<<16)
             | ((unsigned int)in[4*i+2]<<8)|(unsigned int)in[4*i+3];
    for (i = 0; i < 32; i++) {
        r = decrypt ? (31 - i) : i;
        x[4+i] = x[i] ^ m3_t_enc(x[i+1] ^ x[i+2] ^ x[i+3] ^ rk[r]);
    }
    for (i = 0; i < 4; i++) {
        unsigned int v = x[35 - i];
        out[4*i]   = (unsigned char)(v>>24);
        out[4*i+1] = (unsigned char)(v>>16);
        out[4*i+2] = (unsigned char)(v>>8);
        out[4*i+3] = (unsigned char)v;
    }
}

/* 标记运行时拼装 + 派生：suffix 形如 "|sm4"/"|mac" */
static void m3_derive(const char *suffix, unsigned char *out, int outlen) {
    char mk[32];
    char msg[48];
    unsigned char dg[32];
    int i, n = sizeof(MARK) / sizeof(unsigned short);
    int slen = (int)strlen(suffix);
    for (i = 0; i < n; i++) mk[i] = (char)(MARK[i] & 0xFF);
    mk[n] = 0;
    memcpy(msg, mk, (size_t)n);
    memcpy(msg + n, suffix, (size_t)slen);
    m3_sha256((const unsigned char *)msg, (unsigned int)(n + slen), dg);
    memcpy(out, dg, (size_t)outlen);
}

/* ---------- hex 工具 ---------- */

static void m3_hex_encode(const unsigned char *d, int n, char *out) {
    static const char *HEX = "0123456789abcdef";
    int i;
    for (i = 0; i < n; i++) {
        out[2*i]   = HEX[d[i] >> 4];
        out[2*i+1] = HEX[d[i] & 0xF];
    }
    out[2*n] = 0;
}

/* ---------- 业务核心（App 与玩家对拍的是同一套实现） ---------- */

static void m3_core_enc(int page, long long ts, char hex[65]) {
    char payload[32];
    unsigned char pt[32], ct[32], key[16];
    unsigned int rk[32];
    int n, i;
    n = snprintf(payload, sizeof(payload), "page=%d&ts=%lld", page, ts);
    if (n < 0) n = 0;
    if (n > 31) n = 31;
    memset(pt, 0, sizeof(pt));
    for (i = 0; i < n; i++) pt[i] = (unsigned char)payload[i];
    m3_derive("|sm4", key, 16);
    m3_key_expand(key, rk);
    for (i = 0; i < 32; i += 16)
        m3_crypt_block(pt + i, ct + i, rk, 0);
    m3_hex_encode(ct, 32, hex);
}

static void m3_core_sign(const char *enc, char hex[65]) {
    unsigned char mk[32], dg[32];
    size_t elen = strlen(enc);
    if (elen > 120) elen = 120;
    m3_derive("|mac", mk, 32);
    m3_hmac_sha256(mk, 32, (const unsigned char *)enc, (unsigned int)elen, dg);
    m3_hex_encode(dg, 32, hex);
}

/* ---------- 导出面 ---------- */

/* 诱饵密文：拿去配真算法会解出一段“像样”的假载荷，别当真 */
const char *m3_decoy_seal(void) {
    static char hex[65];
    m3_hex_encode(DECOY_BLOB, 32, hex);
    return hex;
}

/* 噪声导出：无人调用，纯占位混淆 */
static volatile unsigned int m3_sink;

int m3_fold(unsigned int x) {
    unsigned int v = x;
    int i;
    for (i = 0; i < 4; i++) v = (v ^ (v << 3)) + 0x9E3779B9U;
    m3_sink = v;
    return (int)(v & 0xFFFF);
}

unsigned int m3_spin(unsigned int x, int n) {
    unsigned int v = (n & 31) ? ((x << (n & 31)) | (x >> (32 - (n & 31)))) : x;
    m3_sink = v ^ m3_sink;
    return v;
}

#ifndef M3_HOST_TEST

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Uq_nativeEnc(JNIEnv *env, jclass clazz, jint page, jlong ts) {
    char hex[65];
    (void)clazz;
    m3_core_enc((int)page, (long long)ts, hex);
    return (*env)->NewStringUTF(env, hex);
}

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Uq_nativeSign(JNIEnv *env, jclass clazz, jstring enc) {
    char hex[65];
    const char *e;
    (void)clazz;
    if (!enc) return (*env)->NewStringUTF(env, "ERR_INPUT");
    e = (*env)->GetStringUTFChars(env, enc, NULL);
    if (!e) return (*env)->NewStringUTF(env, "ERR_UTF");
    m3_core_sign(e, hex);
    (*env)->ReleaseStringUTFChars(env, enc, e);
    return (*env)->NewStringUTF(env, hex);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm;(void)reserved;
    return JNI_VERSION_1_6;
}

#endif /* !M3_HOST_TEST */

#ifdef M3_HOST_TEST
/* 主机自测：cc -DM3_HOST_TEST -o m3test m3.c && ./m3test */
int main(void) {
    char enc[65], sign[65];
    unsigned char key[16];
    unsigned int rk[32];
    unsigned char back[33];
    int i, j;
    m3_core_enc(1, 1787013761LL, enc);
    m3_core_sign(enc, sign);
    printf("sample_enc  = %s\n", enc);
    printf("sample_sign = %s\n", sign);
    /* 回环：用同一把钥匙解开自己的密文 */
    m3_derive("|sm4", key, 16);
    m3_key_expand(key, rk);
    for (i = 0; i < 32; i += 16) {
        unsigned char ct[16];
        for (j = 0; j < 16; j++) {
            char c1 = enc[2*(i+j)], c2 = enc[2*(i+j)+1];
            int hi = (c1<='9')?(c1-'0'):(c1-'a'+10);
            int lo = (c2<='9')?(c2-'0'):(c2-'a'+10);
            ct[j] = (unsigned char)((hi<<4)|lo);
        }
        m3_crypt_block(ct, back + i, rk, 1);
    }
    back[32] = 0;
    printf("roundtrip   = %s\n", back);
    return 0;
}
#endif
"""


def main():
    self_test()

    csrc = C_TEMPLATE
    csrc = csrc.replace("@SBOX@", fmt_bytes(bytes(SBOX)))
    csrc = csrc.replace("@CKMOD@", fmt_words(CK_MOD))
    csrc = csrc.replace("@MARKLEN@", str(len(MARKER)))
    csrc = csrc.replace("@MARKER@", fmt_units([ord(ch) for ch in MARKER]))
    csrc = csrc.replace("@DECOY@", DECOY_MARKER)
    csrc = csrc.replace("@DBLOB@", fmt_bytes(DECOY_BLOB))

    out_path = "app/jni/m3.c"
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(csrc)

    sample_page, sample_ts = 1, 1787013761
    enc = core_enc(sample_page, sample_ts).hex()
    print()
    print("[emit] %s (%d lines)" % (out_path, csrc.count("\n") + 1))
    print("[info] marker       =", MARKER, "(UTF-16 hidden)")
    print("[info] decoy mark   =", DECOY_MARKER, "(plain strings-visible)")
    print("[info] sm4_key      =", SM4_KEY.hex())
    print("[info] mac_key      =", MAC_KEY.hex())
    print("[info] decoy_key    =", DECOY_KEY.hex())
    print("[info] decoy_blob   =", DECOY_BLOB.hex())
    print("[check] decoy_blob decrypt ->",
          ecb_crypt(DECOY_KEY, DECOY_BLOB, CK_MOD, decrypt=True).rstrip(b"\x00").decode())
    print("[sample] page=%d ts=%d" % (sample_page, sample_ts))
    print("[sample] enc  =", enc)
    print("[sample] sign =", core_sign(enc))


if __name__ == "__main__":
    main()

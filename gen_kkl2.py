#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gen_kkl2.py —— 「万剑冢」（KKL2）so 生成器 + 业务 DEX 整体加密烘焙
（C++17 · 二代壳：DEX 整体加密 · 内存加载不落盘 · AES-128-CBC + MD5）

产出 app/jni/kkl2.cpp（libkkl2.so）：
  - 导出表只有 JNI_OnLoad，两个 native 经 RegisterNatives 动态绑定：
      nativeUnseal(byte[] enc) -> byte[]   解密 assets 里的业务 DEX 密文
      nativeDeriveSeal()       -> byte[]   取数签名 seal（16B，MD5 派生）
  - 加密链：plain → 偶数下标镜像交换（std::swap）→ AES-128-CBC(PKCS7)。
      密钥 key = MD5(真标记 + salt)      （16B，AES-128 key）
      IV      = MD5(真标记 + iv_salt)    （16B，CBC 初始向量）
    两者全由 MD5 派生（本关哈希只用 MD5，不用 HMAC）。
  - salt 拆两段用 std::string 运行时拼装（STL 教学点）。
  - 真标记 Fatdog_tense（UTF-16 码元藏 .data）；明文诱饵 yT4!pW8@kR2# 躺 .rodata，
    用它拼出的 key/IV 解不开密文、验签恒 403。

取数：sign = MD5( hex(key) + "page=N&ts=T" )（MD5 古典摘要，非 HMAC）。

--bake 模式（构建期调用）：
  python gen_kkl2.py --bake build/kkl2dex/dex/classes.dex
  → AES-128-CBC 加密业务 dex 写 app/assets/kkl2/echoes_of_blades.bin（二进制密文），
    并伪造诱饵壳 app/assets/kkl2/classes_decoy.dex（真壳形状假内容）。

自测（默认模式）：FIPS-197 AES-128 向量 + 加解密回环 + 派生与 hashlib 一致 +
  诱饵钥不匹配 + 签名向量稳定。

本脚本内联纯 Python AES（不依赖 pycryptodome），保证构建环境无关。
"""
import hashlib
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
APP = os.path.join(HERE, 'app')

MARKER = "Fatdog_tense"      # 真标记：参与 key/IV 派生（so 内 UTF-16 藏匿）
DECOY = "yT4!pW8@kR2#"       # 诱饵标记：明文可见，派生出的 key/IV 解不开密文
SALT_HEAD = "|kkl2_"         # salt 拆两段：SALT_HEAD + SALT_TAIL（STL 拼装）
SALT_TAIL = "swordfield"
IV_SALT = "|kkl2_cbc_iv"     # IV 派生用的 salt
ASSET_DIR = "kkl2"
ASSET_REAL = "echoes_of_blades.bin"      # AES-128-CBC 密文（剑冢深埋）
ASSET_DECOY = "classes_decoy.dex"        # 诱饵壳：真壳形状、假内容

# 服务端数字（与 server.py KKL2 区块一致）
PAGES_KKL2 = 100
PER_PAGE_KKL2 = 10
SEED_KKL2 = 20260909

# =========================================================================
# 纯 Python AES-128（ECB 块 + CBC 模式 + PKCS7）—— 用于烘焙/自测，免第三方依赖
# =========================================================================
SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]
INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


def _xtime(a):
    a <<= 1
    if a & 0x100:
        a ^= 0x11b
    return a & 0xFF


def _gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        a = _xtime(a)
        b >>= 1
    return p & 0xFF


def _expand_key(key):
    """返回 11 个轮密钥（每个 16 字节）；w 为 176 字节扁平密钥表，按轮切。"""
    assert len(key) == 16
    w = list(key)
    for i in range(4, 44):
        t = w[(i - 1) * 4:(i - 1) * 4 + 4]
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [SBOX[x] for x in t]
            t[0] ^= RCON[i // 4 - 1]
        w += [w[(i - 4) * 4 + j] ^ t[j] for j in range(4)]
    return [w[r * 16:(r + 1) * 16] for r in range(11)]


def _add_round_key(st, rk16):
    # st / rk16 均为 16 字节 list（列主序：索引 i 对应 行=i%4, 列=i//4）
    return [st[i] ^ rk16[i] for i in range(16)]


def _shift_rows(st, inv=False):
    out = [0] * 16
    for c in range(4):
        for r in range(4):
            # 正向：行 r 左移 r → 取 old[(c+r)%4]；逆向：右移 r → 取 old[(c-r)%4]
            src = (c + r) % 4 if not inv else (c - r) % 4
            out[c * 4 + r] = st[src * 4 + r]
    return out


def _mix_columns(st, inv=False):
    out = [0] * 16
    m = [14, 11, 13, 9] if inv else [2, 3, 1, 1]
    for c in range(4):
        col = st[c * 4:c * 4 + 4]
        for r in range(4):
            out[c * 4 + r] = (_gmul(col[0], m[(0 - r) % 4]) ^ _gmul(col[1], m[(1 - r) % 4])
                              ^ _gmul(col[2], m[(2 - r) % 4]) ^ _gmul(col[3], m[(3 - r) % 4]))
    return out


def aes_encrypt_block(block, rk):
    st = _add_round_key(list(block), rk[0])
    for rnd in range(1, 10):
        st = [SBOX[x] for x in st]
        st = _shift_rows(st, inv=False)
        st = _mix_columns(st, inv=False)
        st = _add_round_key(st, rk[rnd])
    st = [SBOX[x] for x in st]
    st = _shift_rows(st, inv=False)
    st = _add_round_key(st, rk[10])
    return bytes(st)


def aes_decrypt_block(block, rk):
    st = _add_round_key(list(block), rk[10])
    for rnd in range(9, 0, -1):
        st = _shift_rows(st, inv=True)
        st = [INV_SBOX[x] for x in st]
        st = _add_round_key(st, rk[rnd])
        st = _mix_columns(st, inv=True)
    st = _shift_rows(st, inv=True)
    st = [INV_SBOX[x] for x in st]
    st = _add_round_key(st, rk[0])
    return bytes(st)


def _pkcs7_pad(data):
    n = 16 - (len(data) % 16)
    return data + bytes([n]) * n


def _pkcs7_unpad(data):
    if not data:
        return data
    p = data[-1]
    if p < 1 or p > 16 or p > len(data):
        return data
    if data[-p:] != bytes([p]) * p:
        return data
    return data[:-p]


def aes_cbc_encrypt(key, iv, plain):
    rk = _expand_key(key)
    data = _pkcs7_pad(plain)
    out = bytearray()
    prev = iv
    for off in range(0, len(data), 16):
        blk = bytes(a ^ b for a, b in zip(data[off:off + 16], prev))
        ct = aes_encrypt_block(blk, rk)
        out += ct
        prev = ct
    return bytes(out)


def aes_cbc_decrypt(key, iv, cipher):
    assert len(cipher) % 16 == 0, 'cipher length must be multiple of 16'
    rk = _expand_key(key)
    out = bytearray()
    prev = iv
    for off in range(0, len(cipher), 16):
        blk = cipher[off:off + 16]
        dec = aes_decrypt_block(blk, rk)
        out += bytes(a ^ b for a, b in zip(dec, prev))
        prev = blk
    return bytes(out)


# =========================================================================
# 密钥派生 / 混淆层 / 加密管线
# =========================================================================
def derive_key():
    """AES-128 密钥 = MD5('Fatdog_tense' + '|kkl2_swordfield')（三方一致：so / server / 本脚本）。"""
    return hashlib.md5((MARKER + SALT_HEAD + SALT_TAIL).encode()).digest()


def derive_iv():
    """CBC IV = MD5('Fatdog_tense' + '|kkl2_cbc_iv')。"""
    return hashlib.md5((MARKER + IV_SALT).encode()).digest()


def mirror_swap(buf):
    """偶数下标与镜像位交换（自对合：再调用一次还原）。"""
    x = bytearray(buf)
    n = len(x)
    for i in range(n // 2):
        if i % 2 == 0:
            j = n - 1 - i
            x[i], x[j] = x[j], x[i]
    return bytes(x)


def enc_dex(plain):
    """加密业务 dex：镜像交换 → AES-128-CBC(PKCS7)。返回二进制密文。"""
    return aes_cbc_encrypt(derive_key(), derive_iv(), mirror_swap(plain))


def dec_dex(cipher):
    """解密（自测用）：AES-CBC 解密 → 去 PKCS7 → 镜像交换还原。"""
    return mirror_swap(_pkcs7_unpad(aes_cbc_decrypt(derive_key(), derive_iv(), cipher)))


def sign_of(ts, page):
    """取数签名 = MD5(hex(key) + 'page=N&ts=T')（MD5，非 HMAC）。"""
    return hashlib.md5((derive_key().hex() + "page=%d&ts=%d" % (page, ts)).encode()).hexdigest()


def sum_hash():
    """服务端数字总和 → MD5 hex（判胜用）。"""
    rng = random.Random(SEED_KKL2)
    total = sum(rng.randint(1, 100) for _ in range(PAGES_KKL2 * PER_PAGE_KKL2))
    return total, hashlib.md5(str(total).encode()).hexdigest()


# =========================================================================
# C++ 代码生成
# =========================================================================
def u16(s):
    return ",\n    ".join("0x%04X" % ord(c) for c in s)


def fmt_list(lst, per_line=16):
    lines = []
    for i in range(0, len(lst), per_line):
        lines.append(",".join("0x%02X" % x for x in lst[i:i + per_line]))
    return ",\n    ".join(lines)


def gen_cpp() -> str:
    tpl = r'''/*
 * 太玄之初 KKL2：万剑冢——二代壳（DEX 整体加密 · 内存加载不落盘 + JNI 动态注册）。
 *
 * 业务 DEX（com.fatdog.reverse.kkl2.GateKeeper2）构建期被整体加密成
 * assets/kkl2/echoes_of_blades.bin（AES-128-CBC 二进制密文）埋进 APK；本 so 干两件事：
 *
 *   1) nativeUnseal(enc)   —— AES-128-CBC 解密 + 去 PKCS7 + 镜像交换还原出明文
 *                            dex 字节，由 Java 侧 InMemoryDexClassLoader 内存加载
 *                            （不落盘，adb pull / 常规 dump 全部失效）。
 *   2) nativeDeriveSeal()   —— 返回取数签名 seal（16B，MD5 派生）。
 *
 * 密钥链（全部 MD5 派生，本关哈希只用 MD5，不用 HMAC）：
 *   key = MD5(真标记 Fatdog_tense + "|kkl2_swordfield")    —— 16B，AES-128 密钥 & 签名 seal
 *   iv  = MD5(真标记 + "|kkl2_cbc_iv")                     —— 16B，CBC 初始向量
 * 真标记以 UTF-16 码元藏在 .data（strings 哑火，strings -el 才见）；
 * 明文 yT4!pW8@kR2# 是诱饵，用它派生的 key/iv 解不开密文、验签 403。
 * salt 拆两段（SALT_HEAD + SALT_TAIL）用 std::string 运行时拼装——STL 教学点。
 *
 * 玩家需：① 认清 assets 里 classes_decoy.dex 是假壳 → 找到真密文 bin；
 *         ② 还原解密链（AES-128-CBC + 去填充 + 镜像交换；或 hook nativeUnseal 出口抓明文）；
 *         ③ 内存加载/dump 出 dex → 看 GateKeeper2.sign(key,page,ts) 取数逻辑；
 *         ④ nativeDeriveSeal 拿 seal → MD5 签名取数求和通关。
 */
#include <jni.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <string>
#include <vector>
#include <algorithm>

/* ================= 真标记（UTF-16 藏匿）/ 诱饵（明文） ================= */
static const volatile jchar MARKER[] = {
    __MARKER_U16__
};
static const char DECOY[] = "__DECOY__";     /* 明文诱饵：由 kkl2_seal_tag() 引用，保证进 .rodata */

/* ================= salt 两段拼装（std::string 教学点） ================= */
static const char SALT_HEAD[] = "__SALT_HEAD__";
static const char SALT_TAIL[] = "__SALT_TAIL__";
static const char IV_SALT[]   = "__IV_SALT__";

/* ================= MD5 ================= */
static const uint32_t MD5_K[64] = {
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
};
static const uint8_t MD5_S[64] = {
    7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
    5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
    4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
    6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21
};
#define ROTL32(x,c) (((x) << (c)) | ((x) >> (32 - (c))))

static void md5(const uint8_t *m, size_t l, uint8_t out[16]) {
    uint32_t a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
    size_t with_one = l + 1;
    size_t pad = ((56 - (with_one % 64)) + 64) % 64;
    size_t total = with_one + pad + 8;
    uint8_t *buf = (uint8_t *)calloc(total, 1);
    memcpy(buf, m, l);
    buf[l] = 0x80;
    uint64_t bits = (uint64_t)l * 8;
    for (int i = 0; i < 8; i++) buf[total - 8 + i] = (uint8_t)(bits >> (i * 8));
    for (size_t off = 0; off < total; off += 64) {
        uint32_t w[16];
        for (int i = 0; i < 16; i++) {
            w[i] = (uint32_t)buf[off+i*4] | ((uint32_t)buf[off+i*4+1] << 8)
                 | ((uint32_t)buf[off+i*4+2] << 16) | ((uint32_t)buf[off+i*4+3] << 24);
        }
        uint32_t a = a0, b = b0, c = c0, d = d0;
        for (int i = 0; i < 64; i++) {
            uint32_t f; int g;
            if (i < 16)       { f = (b & c) | (~b & d);  g = i; }
            else if (i < 32)  { f = (d & b) | (~d & c);  g = (5 * i + 1) % 16; }
            else if (i < 48)  { f = b ^ c ^ d;           g = (3 * i + 5) % 16; }
            else              { f = c ^ (b | ~d);        g = (7 * i) % 16; }
            uint32_t tmp = d;
            d = c; c = b;
            b = b + ROTL32(a + f + MD5_K[i] + w[g], MD5_S[i]);
            a = tmp;
        }
        a0 += a; b0 += b; c0 += c; d0 += d;
    }
    uint32_t hs[4] = { a0, b0, c0, d0 };
    for (int i = 0; i < 4; i++) {
        out[i*4]   = (uint8_t)(hs[i]);
        out[i*4+1] = (uint8_t)(hs[i] >> 8);
        out[i*4+2] = (uint8_t)(hs[i] >> 16);
        out[i*4+3] = (uint8_t)(hs[i] >> 24);
    }
    free(buf);
}

/* ================= AES-128（解密方向；加密只在构建期 Python 侧做） ================= */
static const uint8_t SBOX[256] = {
    __SBOX__
};
static const uint8_t RSBOX[256] = {
    __INV_SBOX__
};

static uint8_t xtime(uint8_t x) { return (uint8_t)((x << 1) ^ ((x >> 7) * 0x1b)); }

static uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        a = xtime(a);
        b >>= 1;
    }
    return p;
}

static void key_expansion(const uint8_t key[16], uint8_t rk[176]) {
    for (int i = 0; i < 16; i++) rk[i] = key[i];
    uint8_t rcon = 1;
    for (int i = 4; i < 44; i++) {
        uint8_t t[4];
        for (int j = 0; j < 4; j++) t[j] = rk[(i - 1) * 4 + j];
        if (i % 4 == 0) {
            uint8_t tmp = t[0]; t[0] = t[1]; t[1] = t[2]; t[2] = t[3]; t[3] = tmp;  /* RotWord */
            for (int j = 0; j < 4; j++) t[j] = SBOX[t[j]];                          /* SubWord */
            t[0] ^= rcon;                                                          /* Rcon */
            rcon = xtime(rcon);
        }
        for (int j = 0; j < 4; j++) rk[i * 4 + j] = rk[(i - 4) * 4 + j] ^ t[j];
    }
}

static void inv_cipher(const uint8_t in[16], const uint8_t rk[176], uint8_t out[16]) {
    uint8_t s[16];
    for (int i = 0; i < 16; i++) s[i] = in[i];
    for (int i = 0; i < 16; i++) s[i] ^= rk[160 + i];                  /* AddRoundKey(10) */
    for (int rnd = 9; rnd >= 1; rnd--) {
        uint8_t t;
        t = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = t;    /* InvShiftRows row1 */
        t = s[2];  s[2] = s[10]; s[10] = t; t = s[6]; s[6] = s[14]; s[14] = t;  /* row2 */
        t = s[3];  s[3] = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = t; /* row3 */
        for (int i = 0; i < 16; i++) s[i] = RSBOX[s[i]];                /* InvSubBytes */
        for (int i = 0; i < 16; i++) s[i] ^= rk[rnd * 16 + i];          /* AddRoundKey */
        for (int c = 0; c < 4; c++) {                                   /* InvMixColumns */
            int i0 = c * 4;
            uint8_t a0 = s[i0], a1 = s[i0 + 1], a2 = s[i0 + 2], a3 = s[i0 + 3];
            s[i0]     = gmul(a0,14) ^ gmul(a1,11) ^ gmul(a2,13) ^ gmul(a3,9);
            s[i0 + 1] = gmul(a0,9)  ^ gmul(a1,14) ^ gmul(a2,11) ^ gmul(a3,13);
            s[i0 + 2] = gmul(a0,13) ^ gmul(a1,9)  ^ gmul(a2,14) ^ gmul(a3,11);
            s[i0 + 3] = gmul(a0,11) ^ gmul(a1,13) ^ gmul(a2,9)  ^ gmul(a3,14);
        }
    }
    uint8_t t;
    t = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = t;        /* final InvShiftRows */
    t = s[2];  s[2] = s[10]; s[10] = t; t = s[6]; s[6] = s[14]; s[14] = t;
    t = s[3];  s[3] = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = t;
    for (int i = 0; i < 16; i++) s[i] = RSBOX[s[i]];                    /* final InvSubBytes */
    for (int i = 0; i < 16; i++) s[i] ^= rk[i];                         /* final AddRoundKey */
    for (int i = 0; i < 16; i++) out[i] = s[i];
}

static void aes128_cbc_decrypt(const uint8_t key[16], const uint8_t iv[16],
                               const uint8_t *in, size_t n, uint8_t *out) {
    uint8_t rk[176];
    key_expansion(key, rk);
    uint8_t prev[16];
    memcpy(prev, iv, 16);
    for (size_t off = 0; off + 16 <= n; off += 16) {
        uint8_t dec[16];
        inv_cipher(in + off, rk, dec);
        for (int i = 0; i < 16; i++) out[off + i] = (uint8_t)(dec[i] ^ prev[i]);
        memcpy(prev, in + off, 16);
    }
}

static size_t pkcs7_unpad(uint8_t *buf, size_t n) {
    if (n == 0) return 0;
    uint8_t p = buf[n - 1];
    if (p == 0 || p > 16 || (size_t)p > n) return n;
    for (size_t i = 0; i < (size_t)p; i++) {
        if (buf[n - 1 - i] != p) return n;
    }
    return n - (size_t)p;
}

/* ================= 密钥派生：真标记(UTF-16 降 ASCII) + salt 段拼装 ================= */
static std::string marker_ascii() {
    std::string s;
    for (size_t i = 0; i < sizeof(MARKER) / sizeof(jchar); i++) {
        s.push_back((char)(MARKER[i] & 0xFF));
    }
    return s;
}

static std::vector<uint8_t> md5_of(const std::string &s) {
    std::vector<uint8_t> o(16);
    md5((const uint8_t *)s.data(), s.size(), o.data());
    return o;
}

static std::vector<uint8_t> derive_key() {
    std::string salt = std::string(SALT_HEAD) + std::string(SALT_TAIL);  /* STL 拼装 */
    return md5_of(marker_ascii() + salt);
}

static std::vector<uint8_t> derive_iv() {
    return md5_of(marker_ascii() + std::string(IV_SALT));
}

/* ================= 解密：AES-128-CBC → 去 PKCS7 → 镜像交换 ================= */
static std::vector<uint8_t> unseal_bytes(const uint8_t *in, size_t n) {
    std::vector<uint8_t> key = derive_key();
    std::vector<uint8_t> iv = derive_iv();
    std::vector<uint8_t> v(n);
    aes128_cbc_decrypt(key.data(), iv.data(), in, n, v.data());
    size_t m = pkcs7_unpad(v.data(), n);       /* PKCS7 去填充 */
    v.resize(m);
    for (size_t i = 0; i < m / 2; i++) {       /* 镜像交换还原（std::swap） */
        if ((i & 1) == 0) std::swap(v[i], v[m - 1 - i]);
    }
    return v;
}

/* ================= 诱饵导出（防剧透噪音 / 误导） ================= */
extern "C" const char *kkl2_seal_tag(void) { return DECOY; }
extern "C" void kkl2_fake_key(void) {}

/* ================= JNI 动态注册（导出表无 Java_ 符号） ================= */
static jbyteArray JNICALL nativeUnseal(JNIEnv *env, jclass, jbyteArray enc) {
    jsize n = env->GetArrayLength(enc);
    if (n <= 0 || (n % 16) != 0) return NULL;   /* CBC 密文必为 16 的倍数 */
    std::vector<uint8_t> raw((size_t)n);
    env->GetByteArrayRegion(enc, 0, n, reinterpret_cast<jbyte *>(raw.data()));
    std::vector<uint8_t> plain = unseal_bytes(raw.data(), (size_t)n);
    jbyteArray out = env->NewByteArray((jsize)plain.size());
    if (out) {
        env->SetByteArrayRegion(out, 0, (jsize)plain.size(),
                                reinterpret_cast<const jbyte *>(plain.data()));
    }
    return out;
}

static jbyteArray JNICALL nativeDeriveSeal(JNIEnv *env, jclass) {
    std::vector<uint8_t> key = derive_key();
    jbyteArray out = env->NewByteArray(16);
    if (out) {
        env->SetByteArrayRegion(out, 0, 16, reinterpret_cast<const jbyte *>(key.data()));
    }
    return out;
}

static const JNINativeMethod METHODS[] = {
    {"nativeUnseal",    "([B)[B", (void *) &nativeUnseal},
    {"nativeDeriveSeal", "()[B",   (void *) &nativeDeriveSeal},
};

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void) reserved;
    JNIEnv *env = NULL;
    if (vm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    jclass cls = env->FindClass("com/fatdog/reverse/Kkl2Native");
    if (cls == NULL) {
        return JNI_ERR;
    }
    if (env->RegisterNatives(cls, METHODS, 2) != JNI_OK) {
        return JNI_ERR;
    }
    return JNI_VERSION_1_6;
}
'''
    return (tpl.replace('__MARKER_U16__', u16(MARKER))
                .replace('__DECOY__', DECOY)
                .replace('__SALT_HEAD__', SALT_HEAD)
                .replace('__SALT_TAIL__', SALT_TAIL)
                .replace('__IV_SALT__', IV_SALT)
                .replace('__SBOX__', fmt_list(SBOX))
                .replace('__INV_SBOX__', fmt_list(INV_SBOX)))


def bake(dex_path):
    """构建期：AES-128-CBC 加密业务 dex → assets 密文 + 伪造诱饵壳。"""
    plain = open(dex_path, 'rb').read()
    assert plain[:4] == b'dex\n', 'input is not a dex: %r' % plain[:8]
    cipher = enc_dex(plain)
    asset_dir = os.path.join(APP, 'assets', ASSET_DIR)
    os.makedirs(asset_dir, exist_ok=True)
    real_path = os.path.join(asset_dir, ASSET_REAL)
    with open(real_path, 'wb') as f:
        f.write(cipher)
    # 诱饵壳：真 dex magic + 假头/垃圾/明文误导串
    junk = bytearray(0x100)
    for i in range(len(junk)):
        junk[i] = (i * 31 + 7) & 0xFF
    decoy = (b'dex\n035\0' + bytes(junk[:0x78]) + b'decoy|' + DECOY.encode() + b'|not_the_gate'
             + bytes(junk[:0x80]))
    decoy_path = os.path.join(asset_dir, ASSET_DECOY)
    open(decoy_path, 'wb').write(decoy)
    total, sh = sum_hash()
    assert dec_dex(cipher) == plain, 'bake roundtrip mismatch!'
    print('[bake] plain dex %d B -> cipher %d B' % (len(plain), len(cipher)))
    print('[bake] real : %s' % real_path)
    print('[bake] decoy: %s' % decoy_path)
    print('[bake] key(hex): %s' % derive_key().hex())
    print('[bake] iv(hex) : %s' % derive_iv().hex())
    print('[bake] sum=%d md5=%s' % (total, sh))
    print('[bake] roundtrip OK')
    return real_path


def self_test():
    # 1) AES-128 单块 FIPS-197 向量：C.1
    key = bytes(range(16))
    pt = bytes.fromhex('00112233445566778899aabbccddeeff')
    want = '69c4e0d86a7b0430d8cdb78070b4c55a'
    rk = _expand_key(key)
    assert aes_encrypt_block(pt, rk).hex() == want, 'AES encrypt vector failed'
    assert aes_decrypt_block(bytes.fromhex(want), rk) == pt, 'AES decrypt vector failed'
    # 2) CBC 加解密回环（含真实 dex magic）
    sample = (b'dex\n035\0' + bytes(range(256)) * 5)
    assert dec_dex(enc_dex(sample)) == sample, 'roundtrip failed'
    # 3) key/iv 派生与 hashlib 一致
    assert derive_key().hex() == hashlib.md5((MARKER + SALT_HEAD + SALT_TAIL).encode()).hexdigest()
    assert derive_iv().hex() == hashlib.md5((MARKER + IV_SALT).encode()).hexdigest()
    assert derive_key() != derive_iv()
    # 4) 诱饵派生 != 真派生（学员用 yT4!pW8@kR2# 拼不出正确 key）
    decoy_key = hashlib.md5((DECOY + SALT_HEAD + SALT_TAIL).encode()).digest()
    assert decoy_key != derive_key()
    # 5) 签名向量稳定
    assert sign_of(1780000000, 7) == sign_of(1780000000, 7)
    total, sh = sum_hash()
    print('[self-test] AES FIPS-197 vector OK')
    print('[self-test] roundtrip OK; key=%s' % derive_key().hex())
    print('[self-test] iv =%s' % derive_iv().hex())
    print('[self-test] decoy key differs OK; sum=%d md5=%s' % (total, sh))


def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--bake':
        if len(sys.argv) < 3:
            sys.exit('usage: gen_kkl2.py --bake <path/to/classes.dex>')
        bake(sys.argv[2])
        return
    cpp = gen_cpp()
    out = os.path.join(APP, 'jni', 'kkl2.cpp')
    with open(out, 'w', encoding='utf-8', newline='\n') as f:
        f.write(cpp)
    print('[gen] wrote %s (%d B)' % (out, len(cpp)))
    self_test()


if __name__ == '__main__':
    main()

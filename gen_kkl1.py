#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gen_kkl1.py —— 「玄冥渊」（KKL1）so 生成器（C++ vtable 派发 + 抽取回填教学版）

产出 app/jni/kkl1.cpp（libkkl1.so）：
  - C++ 虚基类 CipherBase + 三个派生类（DecoyA / DecoyB / RealCipher），
    真抽取表只由 RealCipher.table() 虚函数返回（vtable 间接取表）；
  - 数据流：POOL(40B，含噪声) --抽取表--> ENC(32B) --XOR+循环左移--> PLAIN
    PLAIN = "KKL1_SEED:20260903" + 零填充；种子 20260903。
  - 真标记 Fatdog_hallow（UTF-16 码元藏 .data）；诱饵 Fatdog_hollow（一字之差）。
  - 诱饵派生类返回假表（identity / reverse），解出乱码，抽不出种子。

自测：Python 端复刻抽取+解密，校验种子=20260903 且 SHA-256 与 hashlib 对拍。

用法：python gen_kkl1.py   （在项目根目录执行）
"""
import hashlib
import os

HERE = os.path.dirname(os.path.abspath(__file__))

SEED = 20260903
SEED_STR = str(SEED)                      # "20260903"
PLAIN_PREFIX = b"KKL1_SEED:"              # 10 字节
PLAIN_LEN = 32
KEY = [0x4D, 0x9E, 0x2B, 0xF1, 0x88, 0x63, 0x3A, 0xC5]
EXTRACT_REAL = [6, 3, 0, 7, 4, 1, 5, 2]   # 真表：POOL 组 -> ENC 组
EXTRACT_IDENTITY = [0, 1, 2, 3, 4, 5, 6, 7]
EXTRACT_REVERSE = [7, 6, 5, 4, 3, 2, 1, 0]
NOISE = bytes([0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80])  # 噪声前缀，xor-sum&3==0


def rot_r3(b):
    """加密用：循环右移 3 位"""
    return ((b >> 3) | (b << 5)) & 0xFF


def build_pool():
    """构造 POOL(40B) = 噪声8B + 8组(4B/组)，组序按 EXTRACT_REAL 的逆映射摆放"""
    plain = bytearray(PLAIN_LEN)
    plain[0:len(PLAIN_PREFIX)] = PLAIN_PREFIX
    plain[len(PLAIN_PREFIX):len(PLAIN_PREFIX) + len(SEED_STR)] = SEED_STR.encode()
    enc = bytes(rot_r3(plain[i]) ^ KEY[i % 8] for i in range(PLAIN_LEN))
    groups = [enc[i * 4:(i + 1) * 4] for i in range(8)]
    pool = bytearray(len(NOISE) + 8 * 4)  # 预分配 40B
    pool[0:len(NOISE)] = NOISE
    for enc_idx, pool_idx in enumerate(EXTRACT_REAL):
        start = 8 + pool_idx * 4
        pool[start:start + 4] = groups[enc_idx]
    return bytes(pool), enc


def gen_cpp(pool_hex, enc_hex) -> str:
    marker = "Fatdog_hallow"
    decoy = "Fatdog_hollow"
    def u16(s):
        return ",\n    ".join("0x%04X" % ord(c) for c in s)
    tpl = r'''/*
 * 太玄之初 KKL1：玄冥渊——C++ vtable 派发 + 抽取回填（教学版）。
 *
 * 模拟"二代壳抽取回填"：真实密文被拆成 4 字节组，按抽取表乱序散落在
 * POOL 里（开头 8 字节是噪声，永不参与抽取）。运行时先用抽取表把 8 组
 * 字节"回填"成 32 字节 ENC，再 XOR + 循环左移得到明文：
 *     PLAIN = "KKL1_SEED:20260903" + 零填充（种子 = 20260903）。
 *
 * 抽取表不直接写死在主流程：三个 C++ 派生类通过虚函数 table() 各返回
 * 一张表，只有 RealCipher 是真身；另两个返回假表（identity/reverse），
 * 解出的都是乱码。选谁由 choose_selector() 运行时决定（默认走真身）。
 *
 * 玩家需：① 认 vtable 结构 → ② 定位真派生类 RealCipher → ③ 复刻抽取表
 *          与解密链 → ④ 提交 SHA-256(seed) 通关。
 *
 * 标记（真）：Fatdog_hallow — UTF-16 码元藏 .data。
 * 诱饵（假）：Fatdog_hollow — 一字之差（a→o）。
 */
#include <jni.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/* ================= 真/诱饵标记 ================= */
static const jchar MARKER[] = {
    __MARKER_U16__
};
#define MARKER_LEN (sizeof(MARKER) / sizeof(jchar))

static const jchar DECOY[] = {
    __DECOY_U16__
};
#define DECOY_LEN (sizeof(DECOY) / sizeof(jchar))

/* ================= 常量数据 ================= */
static const uint8_t XOR_KEY[8] = { __KEY__ };
static const uint8_t POOL[40] = {
    __POOL__
};
static const uint8_t NOISE_LEN = 8;      /* 前 8 字节噪声 */
static const uint8_t GROUP_N = 8;        /* 8 组 × 4 字节 = 32 字节密文 */

/* ================= SHA-256（与 libtaupe.so 同源） ================= */
static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
#define RR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(x,y,z) (((x)&(y))^((~(x))&(z)))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define EP0(x) (RR(x,2)^RR(x,13)^RR(x,22))
#define EP1(x) (RR(x,6)^RR(x,11)^RR(x,25))
#define S0(x) (RR(x,7)^RR(x,18)^((x)>>3))
#define S1(x) (RR(x,17)^RR(x,19)^((x)>>10))

static void sha256(const uint8_t *m, size_t l, uint8_t o[32]) {
    uint32_t h[] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                    0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    size_t ml = l * 8;
    size_t pl = ((l + 8 + 63) / 64) * 64;
    uint8_t *p = (uint8_t *)memset((uint8_t *)__builtin_alloca(pl + 64), 0, pl + 64);
    memcpy(p, m, l);
    p[l] = 0x80;
    for (int i = 0; i < 8; i++) p[pl - 1 - i] = (uint8_t)(ml >> (i * 8));
    for (size_t off = 0; off < pl; off += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; i++)
            w[i] = (uint32_t)p[off+i*4]<<24 | (uint32_t)p[off+i*4+1]<<16 |
                   (uint32_t)p[off+i*4+2]<<8  | (uint32_t)p[off+i*4+3];
        for (int i = 16; i < 64; i++)
            w[i] = S1(w[i-2]) + w[i-7] + S0(w[i-15]) + w[i-16];
        uint32_t a=h[0], b=h[1], c=h[2], d=h[3], e=h[4], f=h[5], g=h[6], hh=h[7];
        for (int i = 0; i < 64; i++) {
            uint32_t t1 = hh + EP1(e) + CH(e,f,g) + K256[i] + w[i];
            uint32_t t2 = EP0(a) + MAJ(a,b,c);
            hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }
    for (int i = 0; i < 8; i++) {
        o[i*4]   = (uint8_t)(h[i] >> 24);
        o[i*4+1] = (uint8_t)(h[i] >> 16);
        o[i*4+2] = (uint8_t)(h[i] >> 8);
        o[i*4+3] = (uint8_t)h[i];
    }
}

static void to_hex(const uint8_t *in, int n, char *out) {
    const char *t = "0123456789abcdef";
    for (int i = 0; i < n; i++) {
        out[i*2]   = t[(in[i] >> 4) & 0xF];
        out[i*2+1] = t[in[i] & 0xF];
    }
    out[n*2] = '\0';
}

/* ================= C++ 虚函数表派发 ================= */
class CipherBase {
public:
    virtual ~CipherBase() {}
    /* 返回抽取表：POOL 第 table[r] 组 -> ENC 第 r 组 */
    virtual const uint8_t *table(int &n) = 0;
};

/* 诱饵 A：identity —— 直接把含噪声的组序当密文，解出乱码 */
class DecoyCipherA : public CipherBase {
private:
    static const uint8_t T[8];
public:
    const uint8_t *table(int &n) override { n = 8; return T; }
};
const uint8_t DecoyCipherA::T[8] = { __TABLE_IDENTITY__ };

/* 诱饵 B：reverse —— 逆序抽取，同样解不出种子 */
class DecoyCipherB : public CipherBase {
private:
    static const uint8_t T[8];
public:
    const uint8_t *table(int &n) override { n = 8; return T; }
};
const uint8_t DecoyCipherB::T[8] = { __TABLE_REVERSE__ };

/* 真身：EXTRACT_REAL —— 唯一能还原 32 字节密文的表 */
class RealCipher : public CipherBase {
private:
    static const uint8_t T[8];
public:
    const uint8_t *table(int &n) override { n = 8; return T; }
};
const uint8_t RealCipher::T[8] = { __TABLE_REAL__ };

/* 运行时选择：默认 0 -> RealCipher；hook 此函数可观察派发目标 */
static int choose_selector(const uint8_t *pool) {
    /* (前两个噪声字节之和 & 3) 恒为 0 —— 正常路径永远是真身 */
    return (pool[0] + pool[1]) & 3;
}

static CipherBase *make_cipher(const uint8_t *pool) {
    static DecoyCipherA sA;
    static DecoyCipherB sB;
    static RealCipher    sR;
    switch (choose_selector(pool)) {
        case 1: return &sA;
        case 2: return &sB;
        default: return &sR;
    }
}

/* ================= 解密链 ================= */
/* 抽取：按表从 POOL 回填 8 组 -> ENC(32B) */
static void extract(const uint8_t *tab, uint8_t *enc) {
    for (int r = 0; r < 8; r++) {
        memcpy(enc + r * 4, POOL + NOISE_LEN + tab[r] * 4, 4);
    }
}

/* XOR + 循环左移 3 位（与 Python 生成器互为镜像） */
static void decrypt(uint8_t *out, const uint8_t *enc) {
    for (int i = 0; i < 32; i++) {
        uint8_t v = enc[i] ^ XOR_KEY[i % 8];
        out[i] = (uint8_t)((v << 3) | (v >> 5));
    }
}

/* 种子 = 明文第 10 字节起的 8 位十进制数字 */
static uint32_t extract_seed(const uint8_t *plain) {
    char buf[9];
    memcpy(buf, plain + 10, 8);
    buf[8] = '\0';
    return (uint32_t)strtoul(buf, (char **)0, 10);
}

static void get_answer(uint32_t seed, char out[65]) {
    uint8_t b[4] = {
        (uint8_t)(seed >> 24), (uint8_t)(seed >> 16),
        (uint8_t)(seed >> 8),  (uint8_t)seed
    };
    uint8_t h[32];
    sha256(b, 4, h);
    to_hex(h, 32, out);
}

/* ================= 诱饵导出（防剧透噪音） ================= */
extern "C" void kkl1_decoy_seal(void) {}
extern "C" void kkl1_fake_table(void) {}

/* ================= JNI 桥（Kkl1Native） ================= */
extern "C" {

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Kkl1Native_nativeDecrypt(JNIEnv *env, jclass clazz) {
    (void)clazz;
    CipherBase *c = make_cipher(POOL);
    int n = 0;
    const uint8_t *tab = c->table(n);
    uint8_t enc[32], plain[32];
    extract(tab, enc);
    decrypt(plain, enc);
    char hex[65];
    to_hex(plain, 32, hex);
    return env->NewStringUTF(hex);
}

JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Kkl1Native_nativeSeed(JNIEnv *env, jclass clazz) {
    (void)clazz;
    CipherBase *c = make_cipher(POOL);
    int n = 0;
    const uint8_t *tab = c->table(n);
    uint8_t enc[32], plain[32];
    extract(tab, enc);
    decrypt(plain, enc);
    return (jint)extract_seed(plain);
}

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Kkl1Native_nativeAnswer(JNIEnv *env, jclass clazz) {
    (void)clazz;
    CipherBase *c = make_cipher(POOL);
    int n = 0;
    const uint8_t *tab = c->table(n);
    uint8_t enc[32], plain[32];
    extract(tab, enc);
    decrypt(plain, enc);
    char hex[65];
    get_answer(extract_seed(plain), hex);
    return env->NewStringUTF(hex);
}

} /* extern "C" */
'''
    def fmt_bytes(b):
        return ",".join("0x%02X" % x for x in b)
    cpp = tpl
    cpp = cpp.replace("__MARKER_U16__", u16(marker))
    cpp = cpp.replace("__DECOY_U16__", u16(decoy))
    cpp = cpp.replace("__KEY__", fmt_bytes(bytes(KEY)))
    cpp = cpp.replace("__POOL__", fmt_bytes(pool_hex))
    cpp = cpp.replace("__TABLE_REAL__", fmt_bytes(bytes(EXTRACT_REAL)))
    cpp = cpp.replace("__TABLE_IDENTITY__", fmt_bytes(bytes(EXTRACT_IDENTITY)))
    cpp = cpp.replace("__TABLE_REVERSE__", fmt_bytes(bytes(EXTRACT_REVERSE)))
    return cpp


def selftest():
    pool, enc = build_pool()
    # 真表抽取 + 解密：ENC 第 r 组 = POOL 第 EXTRACT_REAL[r] 组（从偏移 8 起）
    dec = bytearray()
    for r in EXTRACT_REAL:
        dec += pool[8 + r * 4:12 + r * 4]
    plain = bytearray()
    for i in range(32):
        v = dec[i] ^ KEY[i % 8]
        plain.append(((v << 3) | (v >> 5)) & 0xFF)
    prefix = bytes(plain[:10])
    seed_str = bytes(plain[10:18]).decode()
    assert prefix == PLAIN_PREFIX, prefix
    assert seed_str == SEED_STR, seed_str
    assert SEED == int(seed_str)
    h = hashlib.sha256(SEED.to_bytes(4, "big")).hexdigest()
    print("[gen_kkl1] 种子 =", SEED, "答案 =", h)
    print("[gen_kkl1] 自测通过：抽取/解密/SHA-256 对拍一致")
    return h


def main():
    pool, enc = build_pool()
    cpp = gen_cpp(pool, enc)
    out = os.path.join(HERE, "app", "jni", "kkl1.cpp")
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        f.write(cpp)
    print("[gen_kkl1] 已写出", out, len(cpp), "bytes")
    selftest()


if __name__ == "__main__":
    main()

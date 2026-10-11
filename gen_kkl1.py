#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gen_kkl1.py —— 「玄冥渊」（KKL1）so 生成器 + 业务 DEX 整体加密烘焙
（C++17 · 一代壳：DEX 拆片整体加密 · 落盘加载 · 文本编码 + 古典摘要 + 流密码）

产出 app/jni/kkl1.cpp（libkkl1.so）：
  - 一簇同形变换器收进匿名命名空间（vtable / typeinfo / 掩码表不再进动态符号表），
    解密用的「掩码」只由其中一支的虚函数返回（vtable 间接取掩码）；
  - 密钥派生：真标记 Fatdog_hallow（UTF-16 藏 .data）→ mark = MD5(marker + salt)，
    轮钥 = mark XOR slot::M(16B)；明文诱饵 Fatdog_hollow 躺 .rodata（strings 只能翻到它）。
  - 解密链：assets 里是 文本编码(流密码(真业务 dex))，nativeFold 逆序还原出 dex。
  - 注册方式：JNI_OnLoad → RegisterNatives（导出表只剩 JNI_OnLoad，无任何 Java_ 符号）。

--bake 模式（构建期调用）：业务拆两片（1a/1b），各加密成一个 assets 密文；
再补一个明文诱饵 dex 直接落 assets：
  python gen_kkl1.py --bake <1a.dex> <1b.dex> <decoy.dex>
  → abyss_vein.bin = 密文(1a)、abyss_marrow.bin = 密文(1b)、classes_decoy.dex = 明文诱饵。

自测（默认模式）：加解密回环对拍 + mark/轮钥 派生与 hashlib 一致 + 签名向量。
"""
import base64
import hashlib
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
APP = os.path.join(HERE, 'app')

MARKER = "Fatdog_hallow"     # 真标记：参与 seal 派生（so 内 UTF-16 藏匿）
DECOY = "Fatdog_hollow"      # 诱饵标记：明文可见（一字之差 a→o）
SALT = "|kkl1_abyss"         # salt，与真标记拼成 seal 输入
MASK = bytes.fromhex("9c3a71d408f2b65e1d87c04be92653af")  # RealSigil::T（vtable 取）
POOL = bytes([0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80])  # 噪声（决定派发，恒真身）
ASSET_DIR = "kkl1"
ASSET_A = "abyss_vein.bin"          # base64(rc4(业务 1a dex))
ASSET_B = "abyss_marrow.bin"        # base64(rc4(业务 1b dex))
ASSET_DECOY = "classes_decoy.dex"   # 明文诱饵 dex（不加密）

# 服务端数字（与 server.py KKL1 区块一致）
PAGES_KKL1 = 100
PER_PAGE_KKL1 = 10
SEED_KKL1 = 20260902


def derive_seal():
    """seal = MD5('Fatdog_hallow' + '|kkl1_abyss')，三方一致：so / server / 本脚本。"""
    return hashlib.md5((MARKER + SALT).encode()).digest()


def derive_rc4_key():
    """rc4_key = seal XOR MASK（MASK 由 RealSigil::T 经 vtable 返回）。"""
    seal = derive_seal()
    return bytes(a ^ b for a, b in zip(seal, MASK))


def rc4(key, data):
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    out = bytearray()
    i = j = 0
    for ch in data:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out.append(ch ^ s[(s[i] + s[j]) & 0xFF])
    return bytes(out)


def enc_dex(plain):
    """整体加密：RC4 后整体 base64（ASCII 文本，肉眼可见 'base64 不是加密'）。"""
    return base64.b64encode(rc4(derive_rc4_key(), plain))


def dec_dex(cipher):
    """解密（自测用）：先 base64 解码，再 RC4。"""
    return rc4(derive_rc4_key(), base64.b64decode(cipher))


def sign_of(ts, page):
    """取数签名 = md5(hex(seal) + 'page=N&ts=T')（MD5，非 HMAC）。"""
    return hashlib.md5((derive_seal().hex() + "page=%d&ts=%d" % (page, ts)).encode()).hexdigest()


def sum_hash():
    """服务端数字总和 → md5 hex（判胜用，bake 时打印便于写进 Activity）。"""
    rng = random.Random(SEED_KKL1)
    total = sum(rng.randint(1, 100) for _ in range(PAGES_KKL1 * PER_PAGE_KKL1))
    return total, hashlib.md5(str(total).encode()).hexdigest()


def u16(s):
    return ",\n    ".join("0x%04X" % ord(c) for c in s)


def fmt_bytes(b):
    return ",".join("0x%02X" % x for x in b)


def gen_cpp() -> str:
    marker_u16 = u16(MARKER)
    tpl = r'''/*
 * 太玄之初 KKL1 · 玄冥渊 —— 一代壳（业务 DEX 拆片整体加密 · 落盘加载）。
 *
 * 构建期把业务两片（com.fatdog.reverse.kkl1.GateKeeper1a / GateKeeper1b）
 * 各自整体加密成 assets/kkl1/abyss_vein.bin、abyss_marrow.bin 埋进 APK。
 * 本 so 对外只保留一个加载入口（JNI_OnLoad），两个 native 方法经
 * RegisterNatives 动态注册 —— 导出表里不出现任何 Java_ 符号；一簇同形变换器
 * 收进匿名命名空间，vtable / typeinfo / 掩码表不再进动态符号表；全模块
 * -fvisibility=hidden。
 *
 * 数据流（与整改前逐字节一致，只改名与注册方式，行为零变化）：
 *   nativeFold(byte[])  —— 密文 → 文本解码 → 流还原 → 明文 dex 字节
 *   nativeSeed()        —— 取数签名用的 mark（16B = MD5(真标记 + salt)）
 * 轮钥 = mark ⊕ 掩码；掩码由一簇同形类经虚表返回，运行时择一（正常恒走同一支）。
 * 明文诱饵 SHAM 与真标记只有一字之差：用它拼出的 mark 解不开密文、验签必 403。
 * 真标记以 UTF-16 码元藏在 .data —— 普通 strings 只能翻到诱饵。
 */
#include <jni.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/* ================= 真标记（UTF-16 藏匿） / 明文诱饵（一字之差） ================= */
static const volatile jchar MARK[] = {
    __MARKER_U16__
};
static const char SUFFIX[] = "__SALT__";
/* 明文诱饵：加 used 属性强制留进 .rodata（不依赖任何导出符号引用） */
static const char SHAM[] __attribute__((used)) = "__DECOY__";

/* ================= 噪声：决定虚表派发（恒选中同一支） ================= */
static const uint8_t NOISE[8] = { __POOL__ };

/* ================= 摘要（古典 MD5） ================= */
static const uint32_t Z_K[64] = {
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
};
static const uint8_t Z_S[64] = {
    7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
    5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
    4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
    6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21
};
#define SHL32(x,c) (((x) << (c)) | ((x) >> (32 - (c))))

static void zeta(const uint8_t *m, size_t l, uint8_t out[16]) {
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
            b = b + SHL32(a + f + Z_K[i] + w[g], Z_S[i]);
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

/* ================= 文本解码（忽略 '=' 与空白） ================= */
static int unfold_ch(int c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static int unfold(const uint8_t *in, size_t n, uint8_t *out) {
    uint32_t acc = 0; int bits = 0; int oi = 0;
    for (size_t i = 0; i < n; i++) {
        int v = unfold_ch(in[i]);
        if (v < 0) continue;
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) { bits -= 8; out[oi++] = (uint8_t)((acc >> bits) & 0xFF); }
    }
    return oi;
}

/* ================= 流还原（对称） ================= */
static void swirl(const uint8_t *pad, int plen, uint8_t *data, size_t n) {
    uint8_t s[256];
    for (int i = 0; i < 256; i++) s[i] = (uint8_t)i;
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + s[i] + pad[i % plen]) & 0xFF;
        uint8_t t = s[i]; s[i] = s[j]; s[j] = t;
    }
    int i2 = 0; j = 0;
    for (size_t k = 0; k < n; k++) {
        i2 = (i2 + 1) & 0xFF;
        j = (j + s[i2]) & 0xFF;
        uint8_t t = s[i2]; s[i2] = s[j]; s[j] = t;
        data[k] ^= s[(s[i2] + s[j]) & 0xFF];
    }
}

/* ================= 一簇同形变换器（匿名命名空间：不进导出表） ================= */
namespace {

class Slot {
public:
    virtual ~Slot() {}
    /* 返回变换掩码（16B），与 mark 异或得轮钥 */
    virtual const uint8_t *mask(int &n) = 0;
};

class SlotAsh : public Slot {
private:
    static const uint8_t M[16];
public:
    const uint8_t *mask(int &n) override { n = 16; return M; }
};
const uint8_t SlotAsh::M[16] = {
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};

class SlotRime : public Slot {
private:
    static const uint8_t M[16];
public:
    const uint8_t *mask(int &n) override { n = 16; return M; }
};
const uint8_t SlotRime::M[16] = { __MASK_REV__ };

class SlotVein : public Slot {
private:
    static const uint8_t M[16];
public:
    const uint8_t *mask(int &n) override { n = 16; return M; }
};
const uint8_t SlotVein::M[16] = { __MASK__ };

/* 运行时择一：(前两个噪声字节之和 & 3) 恒为 0 —— 正常路径恒走同一支 */
int pick_slot(const uint8_t *noise) {
    return (noise[0] + noise[1]) & 3;
}

Slot *slot_of(void) {
    static SlotAsh a;
    static SlotRime b;
    static SlotVein c;
    switch (pick_slot(NOISE)) {
        case 1: return &a;
        case 2: return &b;
        default: return &c;
    }
}

} /* anonymous namespace */

/* ================= 派生 ================= */
static void mark_of(uint8_t out[16]) {
    uint8_t in[64];
    int p = 0;
    for (size_t i = 0; i < sizeof(MARK) / sizeof(jchar); i++) {
        in[p++] = (uint8_t)(MARK[i] & 0xFF);
    }
    for (const char *s = SUFFIX; *s; s++) in[p++] = (uint8_t)*s;
    zeta(in, (size_t)p, out);
}

static void weave(const uint8_t *mask, uint8_t out[16]) {
    uint8_t mark[16];
    mark_of(mark);
    for (int i = 0; i < 16; i++) out[i] = mark[i] ^ mask[i];
}

/* ================= native 实现（static，供 RegisterNatives） ================= */
static jbyteArray JNICALL impl_fold(JNIEnv *env, jclass clazz, jbyteArray src) {
    (void)clazz;
    jsize n = env->GetArrayLength(src);
    if (n <= 0) return NULL;
    uint8_t *raw = (uint8_t *)malloc((size_t)n);
    if (!raw) return NULL;
    env->GetByteArrayRegion(src, 0, n, (jbyte *)raw);
    uint8_t *ct = (uint8_t *)malloc((size_t)n);
    if (!ct) { free(raw); return NULL; }
    int cn = unfold(raw, (size_t)n, ct);
    free(raw);
    if (cn <= 0) { free(ct); return NULL; }
    int tn = 0;
    const uint8_t *mask = slot_of()->mask(tn);
    (void)tn;
    uint8_t pad[16];
    weave(mask, pad);
    swirl(pad, 16, ct, cn);
    jbyteArray out = env->NewByteArray(cn);
    if (out) {
        env->SetByteArrayRegion(out, 0, cn, (const jbyte *)ct);
    }
    free(ct);
    return out;
}

static jbyteArray JNICALL impl_seed(JNIEnv *env, jclass clazz) {
    (void)clazz;
    uint8_t mark[16];
    mark_of(mark);
    jbyteArray out = env->NewByteArray(16);
    if (out) {
        env->SetByteArrayRegion(out, 0, 16, (const jbyte *)mark);
    }
    return out;
}

/* ================= 动态注册（导出表只剩 JNI_OnLoad） ================= */
static const JNINativeMethod kMethods[] = {
    { "nativeFold", "([B)[B", (void *)&impl_fold },
    { "nativeSeed", "()[B",   (void *)&impl_seed },
};

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;
    JNIEnv *env = NULL;
    if (vm->GetEnv((void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_VERSION_1_6;   /* 防御：取环境失败也不阻断加载 */
    }
    jclass cls = env->FindClass("com/fatdog/reverse/Kkl1Native");
    if (cls) {
        env->RegisterNatives(cls, kMethods, (jint)(sizeof(kMethods) / sizeof(kMethods[0])));
        env->DeleteLocalRef(cls);
    }
    return JNI_VERSION_1_6;
}
'''
    cpp = tpl
    cpp = cpp.replace("__MARKER_U16__", marker_u16)
    cpp = cpp.replace("__DECOY__", DECOY)
    cpp = cpp.replace("__SALT__", SALT)
    cpp = cpp.replace("__POOL__", fmt_bytes(POOL))
    cpp = cpp.replace("__MASK__", fmt_bytes(MASK))
    cpp = cpp.replace("__MASK_REV__", fmt_bytes(bytes(reversed(MASK))))
    return cpp


def bake(dex_a, dex_b, dex_decoy):
    """构建期：业务两片（1a/1b）各整体加密 → 两个 assets 密文；诱饵 dex 明文落 assets。
    返回 (path_a, path_b, path_decoy)。"""
    asset_dir = os.path.join(APP, 'assets', ASSET_DIR)
    os.makedirs(asset_dir, exist_ok=True)

    out = []
    for src, name, label in ((dex_a, ASSET_A, '1a'), (dex_b, ASSET_B, '1b')):
        plain = open(src, 'rb').read()
        assert plain[:4] == b'dex\n', 'input is not a dex: %r' % plain[:8]
        cipher = enc_dex(plain)
        assert dec_dex(cipher) == plain, 'bake roundtrip mismatch (%s)!' % label
        dst = os.path.join(asset_dir, name)
        with open(dst, 'wb') as f:
            f.write(cipher)
        print('[bake] %s plain %d B -> cipher %d B  (%s)' % (label, len(plain), len(cipher), name))
        out.append(dst)

    # 明文诱饵：直接落 dex（不加密），钓"只 dump 到假壳就收工"的人
    decoy_plain = open(dex_decoy, 'rb').read()
    assert decoy_plain[:4] == b'dex\n', 'decoy is not a dex: %r' % decoy_plain[:8]
    decoy_dst = os.path.join(asset_dir, ASSET_DECOY)
    with open(decoy_dst, 'wb') as f:
        f.write(decoy_plain)
    print('[bake] decoy plain %d B (明文·不加密)  (%s)' % (len(decoy_plain), ASSET_DECOY))
    out.append(decoy_dst)

    total, sh = sum_hash()
    print('[bake] seal(hex)    : %s' % derive_seal().hex())
    print('[bake] rc4_key(hex) : %s' % derive_rc4_key().hex())
    print('[bake] sum=%d md5=%s' % (total, sh))
    print('[bake] roundtrip OK (1a/1b)')
    return tuple(out)


def self_test():
    # 1) 加解密回环（含真实 dex magic）
    sample = (b'dex\n035\0' + bytes(range(256)) * 5)
    assert dec_dex(enc_dex(sample)) == sample, 'roundtrip failed'
    # 2) seal / rc4_key 派生与 hashlib 一致
    assert derive_seal().hex() == hashlib.md5((MARKER + SALT).encode()).hexdigest()
    assert derive_rc4_key() != derive_seal(), 'rc4_key should differ from seal'
    # 3) 诱饵 seal ≠ 真 seal（学员用 Fatdog_hollow 拼出的钥解不开）
    decoy_seal = hashlib.md5((DECOY + SALT).encode()).digest()
    assert decoy_seal != derive_seal()
    # 4) 签名向量稳定（同输入同输出）
    assert sign_of(1780000000, 7) == sign_of(1780000000, 7)
    total, sh = sum_hash()
    print('[self-test] roundtrip OK; seal=%s' % derive_seal().hex())
    print('[self-test] rc4_key=%s' % derive_rc4_key().hex())
    print('[self-test] decoy seal differs OK; sum=%d md5=%s' % (total, sh))


def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--bake':
        if len(sys.argv) < 5:
            sys.exit('usage: gen_kkl1.py --bake <1a.dex> <1b.dex> <decoy.dex>')
        bake(sys.argv[2], sys.argv[3], sys.argv[4])
        return
    cpp = gen_cpp()
    out = os.path.join(APP, 'jni', 'kkl1.cpp')
    with open(out, 'w', encoding='utf-8', newline='\n') as f:
        f.write(cpp)
    print('[gen] wrote %s (%d B)' % (out, len(cpp)))
    self_test()


if __name__ == '__main__':
    main()

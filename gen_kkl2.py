#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gen_kkl2.py —— 「万剑冢」（KKL2）so 生成器 + 业务 DEX 加密烘焙
（C++17 · JNI 动态注册 · 真 DEX 内存加载教学版）

产出 app/jni/kkl2.cpp（libkkl2.so）：
  - 导出表只有 JNI_OnLoad，两个 native 方法经 RegisterNatives 动态绑定：
      nativeUnseal(byte[] enc) -> byte[]   解密 assets 里加密的业务 DEX
      nativeDeriveKey()       -> byte[]   HMAC 密钥（真标记 UTF-16 藏匿派生）
  - 解密链（STL 教学）：std::string 两段拼 salt → 真标记派生 32B 密钥 dk →
    std::vector<uint8_t> + 流式 XOR（std::transform + lambda 捕获 idx）→
    偶数下标镜像交换还原（std::swap）。
  - 真标记 Fatdog_tense（UTF-16 码元藏 .data）；诱饵 Fatdog_timid 明文躺
    .rodata（strings 可见）——用它派生密钥解不开密文，学员先撞一堵墙。

--bake 模式（构建期调用）：
  python gen_kkl2.py --bake build/kkl2dex/dex/classes.dex
  → 用同一算法把业务 dex 加密写 app/assets/kkl2/echoes_of_blades.bin，
    并伪造诱饵壳 app/assets/kkl2/classes_decoy.dex（真壳形状假内容）。

自测（默认模式）：加密/解密回环对拍 + HMAC 派生密钥与 hashlib 一致。
"""
import hashlib
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
APP = os.path.join(HERE, 'app')

MARKER = "Fatdog_tense"     # 真标记：参与 HMAC 密钥派生（so 内 UTF-16 藏匿）
DECOY = "Fatdog_timid"      # 诱饵标记：明文可见，派生密钥解不开密文
SALT = "|kkl2_swordfield"   # salt 拆两段藏 so：SALT_HEAD "|kkl2_" + SALT_TAIL "swordfield"
ASSET_DIR = "kkl2"
ASSET_REAL = "echoes_of_blades.bin"      # 加密后的真业务 DEX（剑冢深埋）
ASSET_DECOY = "classes_decoy.dex"        # 诱饵壳：真壳形状、假内容

# 服务端数字（与 server.py KKL2 区块一致）
PAGES_KKL2 = 100
PER_PAGE_KKL2 = 10
SEED_KKL2 = 20260909


def derive_dk():
    """HMAC 密钥 = SHA-256('Fatdog_tense' + '|kkl2_swordfield')，三方一致：so / server / 本脚本。"""
    return hashlib.sha256((MARKER + SALT).encode()).digest()


def _stream(n, dk):
    out = bytearray(n)
    acc = dk[0] ^ 0x5A
    for i in range(n):
        acc = (acc + dk[i % 32]) & 0xFF
        out[i] = acc
    return bytes(out)


def enc_dex(plain):
    """加密业务 dex：流式 XOR（keystream 由 dk 派生）→ 偶数下标镜像交换。"""
    n = len(plain)
    dk = derive_dk()
    ks = _stream(n, dk)
    x = bytearray(plain[i] ^ ks[i] for i in range(n))
    for i in range(n // 2):
        if i % 2 == 0:
            j = n - 1 - i
            x[i], x[j] = x[j], x[i]
    return bytes(x)


def dec_dex(cipher):
    """解密（自测用）：逆序还原——先交换回来，再流式 XOR。"""
    n = len(cipher)
    dk = derive_dk()
    x = bytearray(cipher)
    for i in range(n // 2):
        if i % 2 == 0:
            j = n - 1 - i
            x[i], x[j] = x[j], x[i]
    ks = _stream(n, dk)
    return bytes(x[i] ^ ks[i] for i in range(n))


def sum_hash():
    """服务端数字总和 → SHA-256 hex（判胜用，bake 时打印便于写进 Activity）。"""
    rng = random.Random(SEED_KKL2)
    total = sum(rng.randint(1, 100) for _ in range(PAGES_KKL2 * PER_PAGE_KKL2))
    return total, hashlib.sha256(str(total).encode()).hexdigest()


def u16(s):
    return ",\n    ".join("0x%04X" % ord(c) for c in s)


def gen_cpp() -> str:
    marker_u16 = u16(MARKER)
    decoy_u16 = u16(DECOY)
    tpl = r'''/*
 * 太玄之初 KKL2：万剑冢——真 DEX 内存加载 + JNI 动态注册（教学版）。
 *
 * 业务 DEX（com.fatdog.reverse.kkl2.GateKeeper2）构建期被加密成
 * assets/kkl2/echoes_of_blades.bin 埋进 APK；本 so 只干两件事：
 *
 *   1) nativeUnseal(enc)   —— 流式 XOR + 镜像交换还原出明文 dex 字节，
 *                            由 Java 侧用 InMemoryDexClassLoader 内存加载
 *                            （不落盘，adb pull / 常规 dump 全部失效）。
 *   2) nativeDeriveKey()   —— 返回 HMAC-SHA256 密钥（32B）。密钥 = SHA-256(
 *                            真标记 Fatdog_tense + "|kkl2_swordfield")，
 *                            真标记以 UTF-16 码元藏在 .data（strings 哑火，
 *                            strings -el 才见）；明文 Fatdog_timid 是诱饵，
 *                            用它派生的密钥解不开密文、验签 403。
 *
 * 解密链故意走 STL（教学点：容器逆向 / lambda 捕获 / std::swap）：
 *   dk = SHA-256(marker|salt) → keystream（32B 循环加性流）→ vector 流式 XOR
 *   → 偶数下标与镜像位交换还原。
 *
 * 玩家需：① 认清 assets 里 classes_decoy.dex 是假壳 → 找到真密文 bin；
 *         ② 还原解密链（或 Frida hook nativeUnseal 出口抓明文 dex）；
 *         ③ dump/加载出 dex → 看到 GateKeeper2.sign(key,page,ts) 取数逻辑；
 *         ④ nativeDeriveKey 拿密钥 → HMAC 取数求和通关。
 */
#include <jni.h>
#include <stdint.h>
#include <string.h>
#include <string>
#include <vector>
#include <array>
#include <algorithm>

/* ================= 真标记（UTF-16 藏匿）/ 诱饵（明文） ================= */
static const jchar MARKER[] = {
    __MARKER_U16__
};
static const char DECOY[] = "__DECOY__";     /* 明文诱饵：strings 可见 */

/* ================= salt 两段拼装（std::string 教学点） ================= */
static const char SALT_HEAD[] = "|kkl2_";
static const char SALT_TAIL[] = "swordfield";

/* ================= SHA-256（手写，与 libkkl1.so 同源） ================= */
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
    uint32_t h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a;
    uint32_t h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
    size_t n = l + 1;
    size_t rem = n % 64;
    size_t pad = rem > 56 ? 120 - rem : 56 - rem;
    n += pad + 8;
    std::vector<uint8_t> buf(n, 0);
    memcpy(buf.data(), m, l);
    buf[l] = 0x80;
    uint64_t bits = (uint64_t)l * 8;
    for (int i = 0; i < 8; i++) buf[n - 1 - i] = (uint8_t)(bits >> (i * 8));
    for (size_t off = 0; off < n; off += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; i++) {
            w[i] = ((uint32_t)buf[off + i*4] << 24) | ((uint32_t)buf[off + i*4+1] << 16)
                 | ((uint32_t)buf[off + i*4+2] << 8) |  (uint32_t)buf[off + i*4+3];
        }
        for (int i = 16; i < 64; i++) {
            uint32_t t = S1(w[i-2]) + w[i-7] + S0(w[i-15]) + w[i-16];
            w[i] = t;
        }
        uint32_t a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,hh=h7;
        for (int i = 0; i < 64; i++) {
            uint32_t t1 = hh + EP1(e) + CH(e,f,g) + K256[i] + w[i];
            uint32_t t2 = EP0(a) + MAJ(a,b,c);
            hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        h0+=a; h1+=b; h2+=c; h3+=d; h4+=e; h5+=f; h6+=g; h7+=hh;
    }
    uint32_t hs[8] = {h0,h1,h2,h3,h4,h5,h6,h7};
    for (int i = 0; i < 8; i++) {
        o[i*4]   = (uint8_t)(hs[i] >> 24);
        o[i*4+1] = (uint8_t)(hs[i] >> 16);
        o[i*4+2] = (uint8_t)(hs[i] >> 8);
        o[i*4+3] = (uint8_t)hs[i];
    }
}

/* ================= 密钥派生：真标记(UTF-16 降 ASCII) + 两段 salt ================= */
static std::vector<uint8_t> derive_key() {
    std::string tag;
    for (size_t i = 0; i < sizeof(MARKER)/sizeof(jchar); i++) {
        tag.push_back((char)(MARKER[i] & 0xFF));      /* ASCII 码元 */
    }
    std::string salt = std::string(SALT_HEAD) + std::string(SALT_TAIL);  /* std::string 拼装 */
    std::string input = tag + salt;
    std::vector<uint8_t> dk(32);
    sha256((const uint8_t*)input.data(), input.size(), dk.data());
    return dk;
}

/* ================= 解密：keystream 流式 XOR + 镜像交换还原 ================= */
static std::vector<uint8_t> unseal_bytes(const uint8_t *in, size_t n) {
    std::vector<uint8_t> dk = derive_key();
    /* 1) 偶数下标与镜像位交换还原（std::swap） */
    std::vector<uint8_t> v(in, in + n);
    for (size_t i = 0; i < n / 2; i++) {
        if ((i & 1) == 0) {
            std::swap(v[i], v[n - 1 - i]);
        }
    }
    /* 2) 加性 keystream：acc = dk[0]^0x5A；acc += dk[i%32] */
    std::vector<uint8_t> ks(n);
    uint8_t acc = (uint8_t)(dk[0] ^ 0x5A);
    for (size_t i = 0; i < n; i++) {
        acc = (uint8_t)(acc + dk[i % 32]);
        ks[i] = acc;
    }
    /* 3) 流式 XOR：std::transform + lambda（捕获索引 idx） */
    size_t idx = 0;
    std::transform(v.begin(), v.end(), v.begin(),
                   [&](uint8_t x) { return (uint8_t)(x ^ ks[idx++]); });
    return v;
}

/* ================= JNI 动态注册（导出表无 Java_ 符号） ================= */
static jbyteArray JNICALL nativeUnseal(JNIEnv *env, jclass, jbyteArray enc) {
    jsize n = env->GetArrayLength(enc);
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

static jbyteArray JNICALL nativeDeriveKey(JNIEnv *env, jclass) {
    std::vector<uint8_t> dk = derive_key();
    jbyteArray out = env->NewByteArray(32);
    if (out) {
        env->SetByteArrayRegion(out, 0, 32, reinterpret_cast<const jbyte *>(dk.data()));
    }
    return out;
}

static const JNINativeMethod METHODS[] = {
    {"nativeUnseal",    "([B)[B", (void *) &nativeUnseal},
    {"nativeDeriveKey", "()[B",   (void *) &nativeDeriveKey},
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
    return (tpl.replace('__MARKER_U16__', marker_u16)
                .replace('__DECOY_U16__', decoy_u16)
                .replace('__DECOY__', DECOY))


def bake(dex_path):
    """构建期：加密业务 dex → assets 密文 + 伪造诱饵壳。返回密文路径等。"""
    plain = open(dex_path, 'rb').read()
    assert plain[:4] == b'dex\n', 'input is not a dex: %r' % plain[:8]
    cipher = enc_dex(plain)
    asset_dir = os.path.join(APP, 'assets', ASSET_DIR)
    os.makedirs(asset_dir, exist_ok=True)
    real_path = os.path.join(asset_dir, ASSET_REAL)
    open(real_path, 'wb').write(cipher)
    # 诱饵壳：真 dex magic + 假头/垃圾/明文误导串
    decoy_path = os.path.join(asset_dir, ASSET_DECOY)
    junk = bytearray(0x100)
    for i in range(len(junk)):
        junk[i] = (i * 31 + 7) & 0xFF
    decoy = (b'dex\n035\0' + bytes(junk[:0x78]) + b'decoy|' + DECOY.encode() + b'|not_the_gate'
             + bytes(junk[:0x80]))
    open(decoy_path, 'wb').write(decoy)
    total, sh = sum_hash()
    print('[bake] plain dex %d B -> cipher %d B' % (len(plain), len(cipher)))
    print('[bake] real : %s' % real_path)
    print('[bake] decoy: %s' % decoy_path)
    print('[bake] HMAC key(hex): %s' % derive_dk().hex())
    print('[bake] sum=%d sha256=%s' % (total, sh))
    # 回环对拍
    assert dec_dex(cipher) == plain, 'bake roundtrip mismatch!'
    print('[bake] roundtrip OK')
    return real_path


def self_test():
    # 1) 加解密回环
    sample = (b'dex\n035\0' + bytes(range(256)) * 5)
    assert dec_dex(enc_dex(sample)) == sample, 'roundtrip failed'
    # 2) 派生密钥与 hashlib 一致
    assert derive_dk().hex() == hashlib.sha256((MARKER + SALT).encode()).hexdigest()
    # 3) 诱饵派生 ≠ 真钥（学员用 Fatdog_timid 拼不出正确流）
    decoy_dk = hashlib.sha256((DECOY + SALT).encode()).digest()
    assert decoy_dk != derive_dk()
    # 4) 数字对拍
    total, sh = sum_hash()
    print('[self-test] roundtrip OK; dk=%s' % derive_dk().hex())
    print('[self-test] decoy key differs OK; sum=%d sha256=%s' % (total, sh))


def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--bake':
        if len(sys.argv) < 3:
            sys.exit('usage: gen_kkl2.py --bake <path/to/classes.dex>')
        bake(sys.argv[2])
        return
    cpp = gen_cpp()
    out = os.path.join(APP, 'jni', 'kkl2.cpp')
    open(out, 'w', encoding='utf-8', newline='\n').write(cpp)
    print('[gen] wrote %s (%d B)' % (out, len(cpp)))
    self_test()


if __name__ == '__main__':
    main()

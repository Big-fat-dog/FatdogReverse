// kl37.cpp —— KL37「风中鸢尾」（碧落天 · Dart AOT 代码还原 + 混淆对抗）
//
// 伴生 so（runtime 侧）：本关只用**一种对称加密**——AES-128-ECB + PKCS#7。
//   enc = AES-128-ECB-PKCS7(key, "page=<page>&ts=<ts>")  → hex
// 密钥按"拆两段、运行时拼接"的口径保存（镜像实现）：
//   PART_A + PART_B = 完整密钥（两段各按 UTF-8 逐字节异或 0x3C 藏匿），再补零到 16 字节。
// 载荷侧（libapp.so 的 Dart 业务代码）同样是**两瓣分别存放**：第一瓣是字符串字面量，
// 第二瓣以码元数组形式存在——`strings` 只能抓到半截，要拼全得看对象池。
//
// 相比 KL36：本关载荷用 `--obfuscate` 构建，符号名被抹成 a.b()，必须靠调用链定位业务函数。

#ifndef KL37_HOST_TEST
#include <jni.h>
#endif

#include "mt_rng.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

#ifdef ANDROID
#include <android/log.h>
#define LOG_TAG "kl37"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#else
#define LOGI(...) printf(__VA_ARGS__)
#endif

// ============================================================
// AES-128（仅加密，ECB 模式 + PKCS#7）
// ============================================================
namespace aes_ns {

static const uint8_t SBOX[256] = {
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
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t RCON[11] = {0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

static inline uint8_t xtime(uint8_t x) { return (uint8_t)((x << 1) ^ ((x >> 7) * 0x1b)); }

struct Ctx {
    uint8_t rk[176];   // 11 轮密钥
    void expand(const uint8_t key[16]) {
        memcpy(rk, key, 16);
        for (int i = 4; i < 44; i++) {
            uint8_t t[4];
            memcpy(t, rk + (i - 1) * 4, 4);
            if (i % 4 == 0) {
                uint8_t tmp = t[0];
                t[0] = (uint8_t)(SBOX[t[1]] ^ RCON[i / 4]);
                t[1] = SBOX[t[2]];
                t[2] = SBOX[t[3]];
                t[3] = SBOX[tmp];
            }
            for (int k = 0; k < 4; k++) rk[i * 4 + k] = (uint8_t)(rk[(i - 4) * 4 + k] ^ t[k]);
        }
    }
    void encryptBlock(const uint8_t in[16], uint8_t out[16]) const {
        uint8_t s[16];
        for (int i = 0; i < 16; i++) s[i] = (uint8_t)(in[i] ^ rk[i]);
        for (int round = 1; round <= 10; round++) {
            // SubBytes + ShiftRows
            uint8_t t[16];
            for (int c = 0; c < 4; c++)
                for (int r = 0; r < 4; r++)
                    t[c * 4 + r] = SBOX[s[((c + r) % 4) * 4 + r]];
            memcpy(s, t, 16);
            // MixColumns（末轮不做）
            if (round != 10) {
                for (int c = 0; c < 4; c++) {
                    uint8_t* p = s + c * 4;
                    uint8_t a0 = p[0], a1 = p[1], a2 = p[2], a3 = p[3];
                    uint8_t x = (uint8_t)(a0 ^ a1 ^ a2 ^ a3);
                    p[0] ^= (uint8_t)(x ^ xtime((uint8_t)(a0 ^ a1)));
                    p[1] ^= (uint8_t)(x ^ xtime((uint8_t)(a1 ^ a2)));
                    p[2] ^= (uint8_t)(x ^ xtime((uint8_t)(a2 ^ a3)));
                    p[3] ^= (uint8_t)(x ^ xtime((uint8_t)(a3 ^ a0)));
                }
            }
            // AddRoundKey
            for (int i = 0; i < 16; i++) s[i] ^= rk[round * 16 + i];
        }
        memcpy(out, s, 16);
    }
};

// ECB + PKCS#7，返回 hex
static std::string ecbEncryptHex(const std::string& key16, const std::string& plain) {
    uint8_t k[16];
    memset(k, 0, 16);
    memcpy(k, key16.data(), key16.size() < 16 ? key16.size() : 16);
    Ctx ctx;
    ctx.expand(k);

    std::string buf = plain;
    uint8_t pad = (uint8_t)(16 - (buf.size() % 16));
    buf.append(pad, (char)pad);

    static const char* H = "0123456789abcdef";
    std::string out;
    out.reserve(buf.size() * 2);
    for (size_t off = 0; off < buf.size(); off += 16) {
        uint8_t blk[16];
        ctx.encryptBlock(reinterpret_cast<const uint8_t*>(buf.data() + off), blk);
        for (int i = 0; i < 16; i++) { out += H[blk[i] >> 4]; out += H[blk[i] & 0xF]; }
    }
    return out;
}

} // namespace aes_ns

// ============================================================
// SHA-256（nativeAnswer：sha256(str(sum))[:8]）
// ============================================================
namespace sha256_ns {
static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
static inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
struct Ctx {
    uint32_t h[8]; uint64_t bitlen; uint8_t data[64]; size_t datalen;
    Ctx() { h[0]=0x6a09e667; h[1]=0xbb67ae85; h[2]=0x3c6ef372; h[3]=0xa54ff53a;
            h[4]=0x510e527f; h[5]=0x9b05688c; h[6]=0x1f83d9ab; h[7]=0x5be0cd19;
            bitlen=0; datalen=0; }
};
static void transform(Ctx& c, const uint8_t d[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)d[i*4]<<24)|((uint32_t)d[i*4+1]<<16)|((uint32_t)d[i*4+2]<<8)|d[i*4+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr(w[i-15],7)^rotr(w[i-15],18)^(w[i-15]>>3);
        uint32_t s1 = rotr(w[i-2],17)^rotr(w[i-2],19)^(w[i-2]>>10);
        w[i] = w[i-16]+s0+w[i-7]+s1;
    }
    uint32_t a=c.h[0],b=c.h[1],cc=c.h[2],dd=c.h[3],e=c.h[4],f=c.h[5],g=c.h[6],hh=c.h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1=rotr(e,6)^rotr(e,11)^rotr(e,25);
        uint32_t ch=(e&f)^(~e&g);
        uint32_t t1=hh+S1+ch+K[i]+w[i];
        uint32_t S0=rotr(a,2)^rotr(a,13)^rotr(a,22);
        uint32_t mj=(a&b)^(a&cc)^(b&cc);
        uint32_t t2=S0+mj;
        hh=g; g=f; f=e; e=dd+t1; dd=cc; cc=b; b=a; a=t1+t2;
    }
    c.h[0]+=a; c.h[1]+=b; c.h[2]+=cc; c.h[3]+=dd;
    c.h[4]+=e; c.h[5]+=f; c.h[6]+=g; c.h[7]+=hh;
}
static void update(Ctx& c, const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        c.data[c.datalen++] = data[i];
        if (c.datalen == 64) { transform(c, c.data); c.bitlen += 512; c.datalen = 0; }
    }
}
static std::string hex_impl(Ctx& c) {
    uint64_t bits = c.bitlen + c.datalen * 8;
    c.data[c.datalen++] = 0x80;
    if (c.datalen > 56) { while (c.datalen < 64) c.data[c.datalen++] = 0; transform(c, c.data); c.datalen = 0; }
    while (c.datalen < 56) c.data[c.datalen++] = 0;
    for (int i = 7; i >= 0; i--) c.data[c.datalen++] = (uint8_t)((bits >> (i*8)) & 0xFF);
    transform(c, c.data);
    char out[65];
    for (int i = 0; i < 8; i++) snprintf(out + i*8, 9, "%08x", c.h[i]);
    return std::string(out, 64);
}
static std::string digest_hex(const std::string& s) {
    Ctx c; update(c, reinterpret_cast<const uint8_t*>(s.data()), s.size()); return hex_impl(c);
}
} // namespace sha256_ns

// ============================================================
// 密钥：两段常量运行时拼接（volatile 防常量折叠，rule 35）
// ============================================================
namespace key_store {
// PART_A = "Fatdog_" ^0x3C
static const volatile uint8_t PART_A[] = {122,93,72,88,83,91,99};
// PART_B = "kite" ^0x3C
static const volatile uint8_t PART_B[] = {87,85,72,89};

static std::string build() {
    std::string a, b;
    for (size_t i = 0; i < sizeof(PART_A); i++) a += (char)(PART_A[i] ^ 0x3C);
    for (size_t i = 0; i < sizeof(PART_B); i++) b += (char)(PART_B[i] ^ 0x3C);
    return a + b;   // "Fatdog_kite"
}
} // namespace key_store

// 本关"签名"就是密文本身：enc = AES-128-ECB-PKCS7(key, "page=N&ts=T")
static std::string build_enc(int page, long long ts) {
    char head[64];
    snprintf(head, sizeof(head), "page=%d&ts=%lld", page, ts);
    return aes_ns::ecbEncryptHex(key_store::build(), std::string(head));
}

// nativeAnswer：sha256(str(1000 数和))[:8]，SEED_KL37 = 20280615
static std::string build_answer() {
    return sha256_ns::digest_hex(std::to_string(mt_rng::kl_server_sum(20280615))).substr(0, 8);
}

// ============================================================
// 宿主自测
// ============================================================
#ifdef KL37_HOST_TEST

int main() {
    printf("enc(1,1787013761) = %s\n", build_enc(1, 1787013761LL).c_str());
    printf("expect            = 090bc733f1ed59870c72957a2d3fd8fc97d41e467b8d9eb8fe880c4a20682d35\n");
    printf("enc(7,1700000000) = %s\n", build_enc(7, 1700000000LL).c_str());
    printf("expect            = 94fc20c9ca7fce633f5cb9c31954621b01de75946bfd097fa42ac6a9abe19cce\n");
    printf("answer(KL37)      = %s\n", build_answer().c_str());
    printf("expect            = 1a8c6e65\n");
    printf("key               = %s\n", key_store::build().c_str());
    return 0;
}

#else  // ---------- JNI ----------

extern "C" {

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_FlutterCore_nativeEnc(JNIEnv* env, jclass clz, jint page, jlong ts) {
    (void)clz;
    return env->NewStringUTF(build_enc((int)page, (long long)ts).c_str());
}

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_FlutterCore_nativeAnswer(JNIEnv* env, jclass clz) {
    (void)clz;
    return env->NewStringUTF(build_answer().c_str());
}

// 只读自检：只报算法口径与摘要自检，不含密钥明文、不判胜
JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_FlutterCore_nativeGetStatus(JNIEnv* env, jclass clz) {
    (void)clz;
    // AES-128 已知向量自检（FIPS-197）：key=000102...0f, pt=00112233445566778899aabbccddeeff
    //   → 69c4e0d86a7b0430d8cdb78070b4c55a
    std::string k; for (int i = 0; i < 16; i++) k += (char)i;
    const uint8_t ptv[16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                             0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    std::string p(reinterpret_cast<const char*>(ptv), 16);
    std::string hex = aes_ns::ecbEncryptHex(k, p).substr(0, 32);
    const bool ok = (hex == "69c4e0d86a7b0430d8cdb78070b4c55a");
    char buf[128];
    snprintf(buf, sizeof(buf), "密码原语:AES-128-ECB 自检:%s 载荷:已混淆", ok ? "通过" : "异常");
    return env->NewStringUTF(buf);
}

} // extern "C"

#endif

/*
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
    0x0046,
    0x0061,
    0x0074,
    0x0064,
    0x006F,
    0x0067,
    0x005F,
    0x0074,
    0x0065,
    0x006E,
    0x0073,
    0x0065
};
static const char DECOY[] = "yT4!pW8@kR2#";     /* 明文诱饵：由 kkl2_seal_tag() 引用，保证进 .rodata */

/* ================= salt 两段拼装（std::string 教学点） ================= */
static const char SALT_HEAD[] = "|kkl2_";
static const char SALT_TAIL[] = "swordfield";
static const char IV_SALT[]   = "|kkl2_cbc_iv";

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
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
    0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
    0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
    0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
    0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
    0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
    0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
    0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
    0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
    0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
    0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
    0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
    0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
    0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
    0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16
};
static const uint8_t RSBOX[256] = {
    0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,0xBF,0x40,0xA3,0x9E,0x81,0xF3,0xD7,0xFB,
    0x7C,0xE3,0x39,0x82,0x9B,0x2F,0xFF,0x87,0x34,0x8E,0x43,0x44,0xC4,0xDE,0xE9,0xCB,
    0x54,0x7B,0x94,0x32,0xA6,0xC2,0x23,0x3D,0xEE,0x4C,0x95,0x0B,0x42,0xFA,0xC3,0x4E,
    0x08,0x2E,0xA1,0x66,0x28,0xD9,0x24,0xB2,0x76,0x5B,0xA2,0x49,0x6D,0x8B,0xD1,0x25,
    0x72,0xF8,0xF6,0x64,0x86,0x68,0x98,0x16,0xD4,0xA4,0x5C,0xCC,0x5D,0x65,0xB6,0x92,
    0x6C,0x70,0x48,0x50,0xFD,0xED,0xB9,0xDA,0x5E,0x15,0x46,0x57,0xA7,0x8D,0x9D,0x84,
    0x90,0xD8,0xAB,0x00,0x8C,0xBC,0xD3,0x0A,0xF7,0xE4,0x58,0x05,0xB8,0xB3,0x45,0x06,
    0xD0,0x2C,0x1E,0x8F,0xCA,0x3F,0x0F,0x02,0xC1,0xAF,0xBD,0x03,0x01,0x13,0x8A,0x6B,
    0x3A,0x91,0x11,0x41,0x4F,0x67,0xDC,0xEA,0x97,0xF2,0xCF,0xCE,0xF0,0xB4,0xE6,0x73,
    0x96,0xAC,0x74,0x22,0xE7,0xAD,0x35,0x85,0xE2,0xF9,0x37,0xE8,0x1C,0x75,0xDF,0x6E,
    0x47,0xF1,0x1A,0x71,0x1D,0x29,0xC5,0x89,0x6F,0xB7,0x62,0x0E,0xAA,0x18,0xBE,0x1B,
    0xFC,0x56,0x3E,0x4B,0xC6,0xD2,0x79,0x20,0x9A,0xDB,0xC0,0xFE,0x78,0xCD,0x5A,0xF4,
    0x1F,0xDD,0xA8,0x33,0x88,0x07,0xC7,0x31,0xB1,0x12,0x10,0x59,0x27,0x80,0xEC,0x5F,
    0x60,0x51,0x7F,0xA9,0x19,0xB5,0x4A,0x0D,0x2D,0xE5,0x7A,0x9F,0x93,0xC9,0x9C,0xEF,
    0xA0,0xE0,0x3B,0x4D,0xAE,0x2A,0xF5,0xB0,0xC8,0xEB,0xBB,0x3C,0x83,0x53,0x99,0x61,
    0x17,0x2B,0x04,0x7E,0xBA,0x77,0xD6,0x26,0xE1,0x69,0x14,0x63,0x55,0x21,0x0C,0x7D
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

/*
 * 太玄之初 KKL1：玄冥渊——二代壳（DEX 整体加密 · 落盘加载 + C++ 虚表解密器分发）。
 *
 * 业务 DEX（com.fatdog.reverse.kkl1.GateKeeper1）构建期被整体加密成
 * assets/kkl1/abyss_vein.bin（base64(rc4(dex))）埋进 APK。本 so 干两件事：
 *
 *   1) nativeUnseal(enc)   —— base64 解码 → RC4 解密，还原出明文 dex 字节。
 *   2) nativeDeriveSeal()   —— 返回取数签名用的 seal（16B，MD5 派生）。
 *
 * 密钥链（两因素：真标记 + 虚表掩码，缺一不可）：
 *   seal     = MD5(真标记 Fatdog_hallow + "|kkl1_abyss")   —— 真标记 UTF-16 藏 .data
 *   rc4_key  = seal XOR mask                               —— mask 由 RealSigil::T 经 vtable 返回
 * 三个派生类各返回一张 mask，只有 RealSigil 是真身；另两个返回零表 / 逆序表，
 * 解出的都是乱码。选谁由 choose_selector() 运行时决定（默认走真身）。
 * 明文 Fatdog_hollow 是诱饵（一字之差），用它拼出的 seal 解不开密文、验签 403。
 *
 * 玩家路径（两条）：
 *   A. 动态：在 nativeUnseal 出口观察明文 dex（或 hook 落盘点）。
 *   B. 静态：认 vtable → 定位真身 RealSigil → 复刻 mask → 拼 seal → RC4 解密 assets
 *            → 得业务 dex → 反射取数签名 → 取 100 页求和。
 * 落盘加载是本关设定：解密出的 dex 会写到沙箱目录（一代壳的经典破绽）。
 */
#include <jni.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/* ================= 真标记（UTF-16 藏匿）/ 诱饵（明文） ================= */
static const volatile jchar MARKER[] = {
    0x0046,
    0x0061,
    0x0074,
    0x0064,
    0x006F,
    0x0067,
    0x005F,
    0x0068,
    0x0061,
    0x006C,
    0x006C,
    0x006F,
    0x0077
};
static const char SALT[] = "|kkl1_abyss";
static const char DECOY[] = "Fatdog_hollow";     /* 明文诱饵：由 kkl1_seal_tag() 引用，保证进 .rodata */

/* ================= 噪声：决定 vtable 派发（恒选中真身） ================= */
static const uint8_t POOL[8] = { 0x10,0x20,0x30,0x40,0x50,0x60,0x70,0x80 };

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

/* ================= base64 解码（忽略 '=' 与空白） ================= */
static int b64_val(int c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static int b64_decode(const uint8_t *in, size_t n, uint8_t *out) {
    uint32_t acc = 0; int bits = 0; int oi = 0;
    for (size_t i = 0; i < n; i++) {
        int v = b64_val(in[i]);
        if (v < 0) continue;
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) { bits -= 8; out[oi++] = (uint8_t)((acc >> bits) & 0xFF); }
    }
    return oi;
}

/* ================= RC4 ================= */
static void rc4(const uint8_t *key, int klen, uint8_t *data, size_t n) {
    uint8_t s[256];
    for (int i = 0; i < 256; i++) s[i] = (uint8_t)i;
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + s[i] + key[i % klen]) & 0xFF;
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

/* ================= C++ 虚表：解密器分发 ================= */
class SigilBase {
public:
    virtual ~SigilBase() {}
    /* 返回解密掩码（16B），与 seal 异或得 RC4 钥 */
    virtual const uint8_t *mask(int &n) = 0;
};

/* 诱饵 A：全零掩码 —— 直接拿 seal 当钥，解出乱码 */
class DecoySigilA : public SigilBase {
private:
    static const uint8_t T[16];
public:
    const uint8_t *mask(int &n) override { n = 16; return T; }
};
const uint8_t DecoySigilA::T[16] = {
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};

/* 诱饵 B：逆序掩码 —— 同样解不出 dex */
class DecoySigilB : public SigilBase {
private:
    static const uint8_t T[16];
public:
    const uint8_t *mask(int &n) override { n = 16; return T; }
};
const uint8_t DecoySigilB::T[16] = { 0xAF,0x53,0x26,0xE9,0x4B,0xC0,0x87,0x1D,0x5E,0xB6,0xF2,0x08,0xD4,0x71,0x3A,0x9C };

/* 真身：唯一能还原正确 RC4 钥的掩码 */
class RealSigil : public SigilBase {
private:
    static const uint8_t T[16];
public:
    const uint8_t *mask(int &n) override { n = 16; return T; }
};
const uint8_t RealSigil::T[16] = { 0x9C,0x3A,0x71,0xD4,0x08,0xF2,0xB6,0x5E,0x1D,0x87,0xC0,0x4B,0xE9,0x26,0x53,0xAF };

/* 运行时选择：默认 0 -> RealSigil；hook 此函数可观察派发目标 */
static int choose_selector(const uint8_t *pool) {
    /* (前两个噪声字节之和 & 3) 恒为 0 —— 正常路径永远是真身 */
    return (pool[0] + pool[1]) & 3;
}

static SigilBase *make_sigil(void) {
    static DecoySigilA sA;
    static DecoySigilB sB;
    static RealSigil    sR;
    switch (choose_selector(POOL)) {
        case 1: return &sA;
        case 2: return &sB;
        default: return &sR;
    }
}

/* ================= 密钥派生 ================= */
static void derive_seal(uint8_t out[16]) {
    uint8_t in[64];
    int p = 0;
    for (size_t i = 0; i < sizeof(MARKER) / sizeof(jchar); i++) {
        in[p++] = (uint8_t)(MARKER[i] & 0xFF);
    }
    for (const char *s = SALT; *s; s++) in[p++] = (uint8_t)*s;
    md5(in, (size_t)p, out);
}

static void build_rc4_key(const uint8_t *mask, uint8_t key[16]) {
    uint8_t seal[16];
    derive_seal(seal);
    for (int i = 0; i < 16; i++) key[i] = seal[i] ^ mask[i];
}

/* ================= 诱饵导出（防剧透噪音 / 误导） ================= */
/* kkl1_seal_tag 返回明文诱饵标记：反编译时容易被当成真标记 —— 假象 */
extern "C" const char *kkl1_seal_tag(void) { return DECOY; }
extern "C" void kkl1_fake_mask(void) {}

/* ================= JNI 桥（Kkl1Native，静态导出名） ================= */
extern "C" {

JNIEXPORT jbyteArray JNICALL
Java_com_fatdog_reverse_Kkl1Native_nativeUnseal(JNIEnv *env, jclass clazz, jbyteArray enc) {
    (void)clazz;
    jsize n = env->GetArrayLength(enc);
    if (n <= 0) return NULL;
    uint8_t *raw = (uint8_t *)malloc((size_t)n);
    env->GetByteArrayRegion(enc, 0, n, (jbyte *)raw);
    uint8_t *ct = (uint8_t *)malloc((size_t)n);
    int cn = b64_decode(raw, (size_t)n, ct);
    free(raw);
    if (cn <= 0) { free(ct); return NULL; }
    int tn = 0;
    const uint8_t *mask = make_sigil()->mask(tn);
    (void)tn;
    uint8_t key[16];
    build_rc4_key(mask, key);
    rc4(key, 16, ct, cn);
    jbyteArray out = env->NewByteArray(cn);
    if (out) {
        env->SetByteArrayRegion(out, 0, cn, (const jbyte *)ct);
    }
    free(ct);
    return out;
}

JNIEXPORT jbyteArray JNICALL
Java_com_fatdog_reverse_Kkl1Native_nativeDeriveSeal(JNIEnv *env, jclass clazz) {
    (void)clazz;
    uint8_t seal[16];
    derive_seal(seal);
    jbyteArray out = env->NewByteArray(16);
    if (out) {
        env->SetByteArrayRegion(out, 0, 16, (const jbyte *)seal);
    }
    return out;
}

} /* extern "C" */

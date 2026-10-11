/*
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
static const char SUFFIX[] = "|kkl1_abyss";
/* 明文诱饵：加 used 属性强制留进 .rodata（不依赖任何导出符号引用） */
static const char SHAM[] __attribute__((used)) = "Fatdog_hollow";

/* ================= 噪声：决定虚表派发（恒选中同一支） ================= */
static const uint8_t NOISE[8] = { 0x10,0x20,0x30,0x40,0x50,0x60,0x70,0x80 };

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
const uint8_t SlotRime::M[16] = { 0xAF,0x53,0x26,0xE9,0x4B,0xC0,0x87,0x1D,0x5E,0xB6,0xF2,0x08,0xD4,0x71,0x3A,0x9C };

class SlotVein : public Slot {
private:
    static const uint8_t M[16];
public:
    const uint8_t *mask(int &n) override { n = 16; return M; }
};
const uint8_t SlotVein::M[16] = { 0x9C,0x3A,0x71,0xD4,0x08,0xF2,0xB6,0x5E,0x1D,0x87,0xC0,0x4B,0xE9,0x26,0x53,0xAF };

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

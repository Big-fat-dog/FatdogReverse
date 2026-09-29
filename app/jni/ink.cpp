/* libink.so ——「篡墨之谜」L37b（C++17 · 类封装 + 命名空间）
 *
 * 手工实现的一枚 32 位摘要算法：小端字节序、64 步四轮、常量表可辨认——
 * 但有两处被动过手脚（初始状态整组换血 / 常量表三处换血），
 * 标准库实现永远对不上。认骨架、找改动点，才是正路。
 *
 * 组织方式（贴近真实 App 的 native 库）：
 *   - 全程不使用 static：工具函数放 namespace 级（有外部符号）、
 *     业务逻辑用 class 封装（实例状态 + 构造期派生）；
 *   - 常量表以 extern "C" 全局导出，符号可读、数据落 .rodata 便于辨认；
 *   - 仅 JNI 入口走 extern "C"，其余是 C++ 符号（IDA demangle 后可见类/方法名）。
 *
 * sign = hex(摘要("dev=<d>|nonce=<n>|page=<p>|ts=<t>"))
 */
#include <cstring>
#include <cstdio>
#include <string>

#ifndef INK_HOST_TEST
#include <jni.h>
#endif

extern "C" {

/* 真标记 UTF-16 码元表：非 static 非 const 全局，防止常量折叠进指令流；
 * 默认 strings 看不出明文，strings -el 可取证。 */
unsigned short INK_MARK[11] = {
        0x0046, 0x0061, 0x0074, 0x0064, 0x006f, 0x0067, 0x005f, 0x0062,
        0x006c, 0x006f, 0x0074,
};

/* 明文诱饵标记：strings 一眼可见，与真标记一字之差 */
const char INK_DECOY[] = "Fatdog_bolt";

/* 标准常量表与移位表：骨架可辨认的依据（落 .rodata，符号可读） */
unsigned int ink_table[64] = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
};

unsigned char ink_shift[64] = {
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
};

} /* extern "C" */

namespace ink {

/* ---------- 算法工具（namespace 级，非 static：有外部符号） ---------- */

unsigned int rotl32(unsigned int x, int n) {
    return (x << n) | (x >> (32 - n));
}

void compressBlock(unsigned int h[4], const unsigned char *p, const unsigned int K[64]) {
    unsigned int M[16], a, b, c, d, f, g, tmp;
    int r, i;
    for (i = 0; i < 16; i++)
        M[i] = (unsigned int)p[i * 4] | ((unsigned int)p[i * 4 + 1] << 8)
               | ((unsigned int)p[i * 4 + 2] << 16) | ((unsigned int)p[i * 4 + 3] << 24);
    a = h[0]; b = h[1]; c = h[2]; d = h[3];
    for (r = 0; r < 64; r++) {
        if (r < 16) { f = (b & c) | ((~b) & d); g = (unsigned int)r; }
        else if (r < 32) { f = (d & b) | ((~d) & c); g = (unsigned int)((5 * r + 1) % 16); }
        else if (r < 48) { f = b ^ c ^ d; g = (unsigned int)((3 * r + 5) % 16); }
        else { f = c ^ (b | (~d)); g = (unsigned int)((7 * r) % 16); }
        tmp = d; d = c; c = b;
        b = b + rotl32(a + f + K[r] + M[g], ink_shift[r]);
        a = tmp;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
}

void digestCore(const unsigned int iv[4], const unsigned int K[64],
                const unsigned char *msg, unsigned int len, unsigned char out[16]) {
    unsigned int h[4], off, rem, tlen, i;
    unsigned long long bits = (unsigned long long)len * 8ULL;
    unsigned char tail[128];
    h[0] = iv[0]; h[1] = iv[1]; h[2] = iv[2]; h[3] = iv[3];
    for (off = 0; off + 64 <= len; off += 64)
        compressBlock(h, msg + off, K);
    rem = len - off;
    std::memset(tail, 0, sizeof(tail));
    std::memcpy(tail, msg + off, rem);
    tail[rem] = 0x80;
    tlen = (rem + 9 <= 64) ? 64 : 128;
    for (i = 0; i < 8; i++)
        tail[tlen - 8 + i] = (unsigned char)((bits >> (8 * i)) & 0xFF);   /* 小端长度 */
    compressBlock(h, tail, K);
    if (tlen == 128) compressBlock(h, tail + 64, K);
    for (i = 0; i < 4; i++) {
        out[i * 4] = (unsigned char)(h[i] & 0xFF);
        out[i * 4 + 1] = (unsigned char)((h[i] >> 8) & 0xFF);
        out[i * 4 + 2] = (unsigned char)((h[i] >> 16) & 0xFF);
        out[i * 4 + 3] = (unsigned char)((h[i] >> 24) & 0xFF);
    }
}

/* 标记物化：UTF-16 码元 → ASCII（明文不落地） */
void markerAscii(char *out, int cap) {
    int n = (int)(sizeof(INK_MARK) / sizeof(INK_MARK[0]));
    int i;
    for (i = 0; i < n && i < cap - 1; i++)
        out[i] = (char)(INK_MARK[i] & 0xFF);
    out[i] = 0;
}

/* ---------- 摘要器：实例状态 + 构造期换血 ---------- */

class Digest {
public:
    Digest();
    void compute(const unsigned char *msg, unsigned int len, unsigned char out[16]) const;

private:
    unsigned int m_state[4];
    unsigned int m_const[64];
};

Digest::Digest() {
    /* 换血点①：初始状态整组替换为 标准摘要(<标记> + "|iv") 的小端拆字 */
    char mk[32], seed[40];
    unsigned char d[16];
    const unsigned int stdIv[4] = {0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u};
    markerAscii(mk, (int)sizeof(mk));
    unsigned int n = (unsigned int)std::strlen(mk);
    std::memcpy(seed, mk, n);
    std::memcpy(seed + n, "|iv", 3);
    digestCore(stdIv, ink_table, (const unsigned char *)seed, n + 3u, d);
    for (int i = 0; i < 4; i++)
        m_state[i] = (unsigned int)d[i * 4] | ((unsigned int)d[i * 4 + 1] << 8)
                     | ((unsigned int)d[i * 4 + 2] << 16) | ((unsigned int)d[i * 4 + 3] << 24);
    /* 换血点②：常量表三处改动 */
    for (int i = 0; i < 64; i++) m_const[i] = ink_table[i];
    m_const[5] ^= 0x5A5A5A5Au;
    m_const[23] ^= 0x5A5A5A5Au;
    m_const[41] ^= 0x5A5A5A5Au;
}

void Digest::compute(const unsigned char *msg, unsigned int len, unsigned char out[16]) const {
    digestCore(m_state, m_const, msg, len, out);
}

/* ---------- 签名器：持有摘要实例，负责载荷拼装 ---------- */

class Signer {
public:
    explicit Signer(const char *dev) : m_dev(dev ? dev : "") {}

    void sign(int page, long long ts, const char *nonce, char out[33]) const {
        char payload[192];
        unsigned char dg[16];
        std::snprintf(payload, sizeof(payload), "dev=%s|nonce=%s|page=%d|ts=%lld",
                      m_dev.c_str(), nonce ? nonce : "", page, ts);
        m_digest.compute((const unsigned char *)payload, (unsigned int)std::strlen(payload), dg);
        for (int i = 0; i < 16; i++)
            std::sprintf(out + i * 2, "%02x", dg[i]);
        out[32] = 0;
    }

private:
    Digest m_digest;
    std::string m_dev;
};

} /* namespace ink */

#ifndef INK_HOST_TEST

extern "C" JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Qb_nativeSign(JNIEnv *env, jclass clazz, jint page, jlong ts,
                                      jstring nonce, jstring dev) {
    const char *n;
    const char *d;
    char out[33];
    (void)clazz;
    if (!nonce || !dev) return env->NewStringUTF("ERR_INPUT");
    n = env->GetStringUTFChars(nonce, NULL);
    d = env->GetStringUTFChars(dev, NULL);
    if (!n || !d) return env->NewStringUTF("ERR_UTF");
    ink::Signer signer(d);
    signer.sign((int)page, (long long)ts, n, out);
    env->ReleaseStringUTFChars(nonce, n);
    env->ReleaseStringUTFChars(dev, d);
    return env->NewStringUTF(out);
}

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm;
    (void)reserved;
    return JNI_VERSION_1_6;
}

#endif /* !INK_HOST_TEST */

#ifdef INK_HOST_TEST
/* 主机自测：g++ -std=c++17 -DINK_HOST_TEST -o inktest ink.cpp && ./inktest */
int main() {
    char out[33], h[33], mk[32];
    unsigned char d[16];
    const unsigned int stdIv[4] = {0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u};
    ink::Signer signer("android");
    signer.sign(1, 1787013761LL, "1a2b3c4d", out);
    std::printf("variant_sign       = %s\n", out);
    ink::markerAscii(mk, (int)sizeof(mk));
    std::printf("marker             = %s\n", mk);
    ink::digestCore(stdIv, ink_table, (const unsigned char *)"abc", 3, d);
    for (int i = 0; i < 16; i++) std::sprintf(h + i * 2, "%02x", d[i]);
    h[32] = 0;
    std::printf("std_digest(abc)    = %s  (expect 900150983cd24fb0d6963f7d28e17f72)\n", h);
    return 0;
}
#endif

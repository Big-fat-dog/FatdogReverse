/* 自动生成：python gen_kkl5.py —— 请勿手改。 */
/* 太玄之初 KKL5 诛仙台 · 五 so 编队（门面/虚拟机/复合分组/摘要/守卫）。 */

/*
 * tallow —— 太玄之初 KKL5 诛仙台的摘要内核（MD5，零 HMAC）。
 *
 * 取数签名 = md5( hex(主钥) + 密文十六进制 )，由上层拼好后交给 tl_tally。
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define TL_VIS __attribute__((visibility("default")))

static const uint32_t TL_K[64] = {
    0xd76aa478u,0xe8c7b756u,0x242070dbu,0xc1bdceeeu,0xf57c0fafu,0x4787c62au,0xa8304613u,0xfd469501u,
    0x698098d8u,0x8b44f7afu,0xffff5bb1u,0x895cd7beu,0x6b901122u,0xfd987193u,0xa679438eu,0x49b40821u,
    0xf61e2562u,0xc040b340u,0x265e5a51u,0xe9b6c7aau,0xd62f105du,0x02441453u,0xd8a1e681u,0xe7d3fbc8u,
    0x21e1cde6u,0xc33707d6u,0xf4d50d87u,0x455a14edu,0xa9e3e905u,0xfcefa3f8u,0x676f02d9u,0x8d2a4c8au,
    0xfffa3942u,0x8771f681u,0x6d9d6122u,0xfde5380cu,0xa4beea44u,0x4bdecfa9u,0xf6bb4b60u,0xbebfbc70u,
    0x289b7ec6u,0xeaa127fau,0xd4ef3085u,0x04881d05u,0xd9d4d039u,0xe6db99e5u,0x1fa27cf8u,0xc4ac5665u,
    0xf4292244u,0x432aff97u,0xab9423a7u,0xfc93a039u,0x655b59c3u,0x8f0ccc92u,0xffeff47du,0x85845dd1u,
    0x6fa87e4fu,0xfe2ce6e0u,0xa3014314u,0x4e0811a1u,0xf7537e82u,0xbd3af235u,0x2ad7d2bbu,0xeb86d391u
};
#define TL_RL(x,c) (((x) << (c)) | ((x) >> (32 - (c))))

extern "C" TL_VIS void tl_tally(const uint8_t *msg, size_t len, uint8_t out[16]) {
    uint32_t h[4] = {0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u};
    size_t n = len + 1;
    size_t rem = n % 64;
    size_t pad = rem > 56 ? 120 - rem : 56 - rem;
    n += pad + 8;
    uint8_t *buf = (uint8_t *)calloc(n, 1);
    if (!buf) { memset(out, 0, 16); return; }
    memcpy(buf, msg, len);
    buf[len] = 0x80;
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) buf[n - 8 + i] = (uint8_t)(bits >> (i * 8));
    for (size_t off = 0; off < n; off += 64) {
        uint32_t m[16];
        for (int i = 0; i < 16; i++)
            m[i] = ((uint32_t)buf[off + i * 4]) | ((uint32_t)buf[off + i * 4 + 1] << 8)
                 | ((uint32_t)buf[off + i * 4 + 2] << 16) | ((uint32_t)buf[off + i * 4 + 3] << 24);
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        static const int S[64] = {
            7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
            5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
            4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
            6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
        };
        for (int i = 0; i < 64; i++) {
            uint32_t f; int g;
            if (i < 16)      { f = (b & c) | (~b & d);        g = i; }
            else if (i < 32) { f = (d & b) | (~d & c);        g = (5 * i + 1) % 16; }
            else if (i < 48) { f = b ^ c ^ d;                 g = (3 * i + 5) % 16; }
            else             { f = c ^ (b | ~d);              g = (7 * i) % 16; }
            uint32_t tmp = d;
            d = c; c = b;
            b = b + TL_RL(a + f + TL_K[i] + m[g], S[i]);
            a = tmp;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    }
    free(buf);
    for (int i = 0; i < 4; i++) {
        out[i * 4]     = (uint8_t)h[i];
        out[i * 4 + 1] = (uint8_t)(h[i] >> 8);
        out[i * 4 + 2] = (uint8_t)(h[i] >> 16);
        out[i * 4 + 3] = (uint8_t)(h[i] >> 24);
    }
}

extern "C" TL_VIS void tl_hex(const uint8_t *in, int n, char *out) {
    const char *t = "0123456789abcdef";
    for (int i = 0; i < n; i++) {
        out[i * 2] = t[(in[i] >> 4) & 0xF];
        out[i * 2 + 1] = t[in[i] & 0xF];
    }
    out[n * 2] = '\0';
}

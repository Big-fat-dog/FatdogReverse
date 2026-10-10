/* 自动生成：python gen_kkl4.py —— 请勿手改。 */
/* 太玄之初 KKL4 锁妖塔 · 五 so 编队（门面/虚拟机/分组/摘要/守卫）。 */

/*
 * cavern —— 太玄之初 KKL4 锁妖塔的分组原语内核。
 *
 * AES-128 分组 + **CTR 模式**（计数器块 = iv[0:12] ‖ (iv[12:16] + 块号) 大端）。
 * S 盒按 FIPS-197 硬编码；轮常量 Rcon 用 xtime 现算。CTR 加解密同构。
 */
#include <stdint.h>
#include <string.h>

#define CV_VIS __attribute__((visibility("default")))

static const uint8_t SBOX[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
};

static uint8_t cv_xtime(uint8_t x) { return (uint8_t)((x << 1) ^ ((x >> 7) * 0x1b)); }

static uint8_t cv_gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        a = cv_xtime(a);
        b >>= 1;
    }
    return p;
}

static void cv_key_expand(const uint8_t key[16], uint8_t rk[176]) {
    for (int i = 0; i < 16; i++) rk[i] = key[i];
    uint8_t rcon = 1;
    for (int i = 4; i < 44; i++) {
        uint8_t t[4];
        for (int j = 0; j < 4; j++) t[j] = rk[(i - 1) * 4 + j];
        if (i % 4 == 0) {
            uint8_t tmp = t[0]; t[0] = t[1]; t[1] = t[2]; t[2] = t[3]; t[3] = tmp;
            for (int j = 0; j < 4; j++) t[j] = SBOX[t[j]];
            t[0] ^= rcon;
            rcon = cv_xtime(rcon);
        }
        for (int j = 0; j < 4; j++) rk[i * 4 + j] = rk[(i - 4) * 4 + j] ^ t[j];
    }
}

static void cv_add_rk(uint8_t s[16], const uint8_t *rk) {
    for (int i = 0; i < 16; i++) s[i] ^= rk[i];
}

static void cv_sub_bytes(uint8_t s[16]) {
    for (int i = 0; i < 16; i++) s[i] = SBOX[s[i]];
}

static void cv_shift_rows(uint8_t s[16]) {
    uint8_t t;
    t = s[1];  s[1]  = s[5];  s[5]  = s[9];  s[9]  = s[13]; s[13] = t;
    t = s[2];  s[2]  = s[10]; s[10] = t;     t = s[6]; s[6] = s[14]; s[14] = t;
    t = s[15]; s[15] = s[11]; s[11] = s[7];  s[7]  = s[3];  s[3]  = t;
}

static void cv_mix_columns(uint8_t s[16]) {
    for (int c = 0; c < 4; c++) {
        int i = c * 4;
        uint8_t a0 = s[i], a1 = s[i + 1], a2 = s[i + 2], a3 = s[i + 3];
        s[i]     = (uint8_t)(cv_gmul(a0, 2) ^ cv_gmul(a1, 3) ^ a2 ^ a3);
        s[i + 1] = (uint8_t)(a0 ^ cv_gmul(a1, 2) ^ cv_gmul(a2, 3) ^ a3);
        s[i + 2] = (uint8_t)(a0 ^ a1 ^ cv_gmul(a2, 2) ^ cv_gmul(a3, 3));
        s[i + 3] = (uint8_t)(cv_gmul(a0, 3) ^ a1 ^ a2 ^ cv_gmul(a3, 2));
    }
}

static void cv_encrypt_block(const uint8_t in[16], const uint8_t rk[176], uint8_t out[16]) {
    uint8_t s[16];
    memcpy(s, in, 16);
    cv_add_rk(s, rk);
    for (int r = 1; r < 10; r++) {
        cv_sub_bytes(s);
        cv_shift_rows(s);
        cv_mix_columns(s);
        cv_add_rk(s, rk + r * 16);
    }
    cv_sub_bytes(s);
    cv_shift_rows(s);
    cv_add_rk(s, rk + 160);
    memcpy(out, s, 16);
}

/* AES-128-CTR 加解密（同构）；返回输出长度（== 输入长度），失败 -1。 */
extern "C" CV_VIS int cv_seal(const uint8_t key[16], const uint8_t iv[16],
                              const uint8_t *in, size_t len, uint8_t *out) {
    if (!key || !iv || !in || !out) return -1;
    uint8_t rk[176];
    cv_key_expand(key, rk);
    uint32_t base = ((uint32_t)iv[12] << 24) | ((uint32_t)iv[13] << 16)
                  | ((uint32_t)iv[14] << 8) | (uint32_t)iv[15];
    for (size_t off = 0; off < len; off += 16) {
        uint8_t ctr[16], ks[16];
        memcpy(ctr, iv, 12);
        uint32_t c = base + (uint32_t)(off / 16);
        ctr[12] = (uint8_t)(c >> 24); ctr[13] = (uint8_t)(c >> 16);
        ctr[14] = (uint8_t)(c >> 8);  ctr[15] = (uint8_t)c;
        cv_encrypt_block(ctr, rk, ks);
        size_t m = (len - off < 16) ? (len - off) : 16;
        for (size_t i = 0; i < m; i++) out[off + i] = (uint8_t)(in[off + i] ^ ks[i]);
    }
    return (int)len;
}

/* 十六进制编码（小写）。 */
extern "C" CV_VIS void cv_hex(const uint8_t *in, size_t len, char *out) {
    const char *t = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = t[(in[i] >> 4) & 0xF];
        out[i * 2 + 1] = t[in[i] & 0xF];
    }
    out[len * 2] = '\0';
}

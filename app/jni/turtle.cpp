/*
 * libturtle.so — L51 雷霆山巅（密钥体 + 盐头段 + 摘要，名字不体现算法）
 *
 * 被 libshark.so 通过 dlopen/dlsym 加载。导出名一律中性化，
 * 只看导出表看不出这里装的是 3DES 密钥 / SM3 盐 / 摘要实现。
 *
 * 跨 so + 跨层拼装：
 *   tt_seed → 24 字节密钥体（只在本关内部使用）
 *   tt_salt → 盐**头段** 12 字节；尾段 5 字节在 Java（shark 侧跨层回调取件）
 *   tt_slen → 盐头段长度
 *   tt_mark → 摘要
 * 所有密钥/盐数据符号都是 static（不进 .dynsym）。
 */

#include <string>
#include <cstring>
#include <cstdint>
#include <vector>

/* ============================================================
 * 编译期常量展开
 * ============================================================ */

template<int N>
struct RoundKey {
    static constexpr uint8_t value[N] = {0};
};

/* ============================================================
 * SM3 哈希（C++ 实现，带 IV 换血）
 * ============================================================ */

static const uint32_t SM3_T[64] = {
    0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,
    0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,
    0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,
    0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,
    0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,
    0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,
    0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,
    0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a
};

static inline uint32_t sm3_rotl(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
static inline uint32_t sm3_ff(int j, uint32_t x, uint32_t y, uint32_t z) {
    return j < 16 ? (x ^ y ^ z) : ((x & y) | (x & z) | (y & z));
}
static inline uint32_t sm3_gg(int j, uint32_t x, uint32_t y, uint32_t z) {
    return j < 16 ? (x ^ y ^ z) : ((x & y) | (~x & z));
}
static inline uint32_t sm3_p0(uint32_t x) { return x ^ sm3_rotl(x, 9) ^ sm3_rotl(x, 17); }
static inline uint32_t sm3_p1(uint32_t x) { return x ^ sm3_rotl(x, 15) ^ sm3_rotl(x, 23); }

static void sm3_cf(uint32_t V[8], const uint8_t B[64]) {
    uint32_t W[68], W1[64];
    for (int i = 0; i < 16; i++)
        W[i] = ((uint32_t)B[i*4] << 24) | ((uint32_t)B[i*4+1] << 16) | ((uint32_t)B[i*4+2] << 8) | B[i*4+3];
    for (int i = 16; i < 68; i++)
        W[i] = sm3_p1(W[i-16] ^ W[i-9] ^ sm3_rotl(W[i-3], 15)) ^ sm3_rotl(W[i-13], 7) ^ W[i-6];
    for (int i = 0; i < 64; i++) W1[i] = W[i] ^ W[i+4];
    uint32_t A=V[0],B_=V[1],C=V[2],D=V[3],E=V[4],F=V[5],G=V[6],H=V[7];
    for (int j = 0; j < 64; j++) {
        uint32_t SS1 = sm3_rotl((sm3_rotl(A,12) + E + sm3_rotl(SM3_T[j], j%32)) & 0xFFFFFFFF, 7);
        uint32_t SS2 = SS1 ^ sm3_rotl(A, 12);
        uint32_t TT1 = (sm3_ff(j,A,B_,C) + D + SS2 + W1[j]) & 0xFFFFFFFF;
        uint32_t TT2 = (sm3_gg(j,E,F,G) + H + SS1 + W[j]) & 0xFFFFFFFF;
        D=C; C=sm3_rotl(B_,9); B_=A; A=TT1;
        H=G; G=sm3_rotl(F,19); F=E; E=sm3_p0(TT2);
    }
    V[0]^=A; V[1]^=B_; V[2]^=C; V[3]^=D; V[4]^=E; V[5]^=F; V[6]^=G; V[7]^=H;
}

static std::string sm3_hex(const uint8_t* data, size_t len) {
    // SM3 IV（标准值，L51 服务端用标准 IV）
    uint32_t V[8] = {0x7380166f,0x4914b2b9,0x172442d7,0xda8a0600,
                     0xa96f30bc,0x163138aa,0xe38dee4d,0xb0fb0e4e};
    size_t msgLen = len;
    std::vector<uint8_t> msg(len + 72);  // 1 bit-pad + up to 63 zeros + 8 length bytes
    memcpy(msg.data(), data, len);
    msg[len] = 0x80;
    size_t totalLen = len + 1;
    while (totalLen % 64 != 56) msg[totalLen++] = 0;
    for (int i = 0; i < 8; i++) msg[totalLen + i] = (uint8_t)(msgLen >> (56 - 8*i));
    totalLen += 8;
    for (size_t i = 0; i < totalLen; i += 64) {
        uint8_t block[64];
        memcpy(block, msg.data() + i, 64);
        sm3_cf(V, block);
    }
    char hex[65];
    for (int i = 0; i < 8; i++)
        snprintf(hex + i*8, 9, "%08x", V[i]);
    return std::string(hex, 64);
}

/* ============================================================
 * 导出函数
 * ============================================================ */

extern "C" {

/* 24 字节密钥体（XOR ^0x4B 藏匿）；static → 不进导出表 */
static const unsigned char DES_KEY_XOR[24] = {
    0x0d,0x2a,0x3f,0x2f,0x24,0x2c,0x14,0x3f,0x23,0x3e,0x25,0x2f,
    0x2e,0x39,0x14,0x79,0x7b,0x79,0x7d,0x4b,0x4b,0x4b,0x4b,0x4b
};
/* 盐**头段** 12 字节（XOR ^0x2D 藏匿）；尾段 5 字节在 Java（shark 回调取件） */
static const unsigned char SALT_HEAD_XOR[12] = {
    0x6b,0x4c,0x59,0x49,0x42,0x4a,0x72,0x5d,0x48,0x4c,0x46,0x72
};

static unsigned char DES_KEY[24];
static unsigned char SALT_HEAD[12];
static bool MARKS_READY = false;

static void prime_marks() {
    if (MARKS_READY) return;
    /* 掩码走 volatile：否则 -O2 会把异或折叠成明文常量写进 .rodata */
    volatile unsigned char k1 = 0x4B;
    volatile unsigned char k2 = 0x2D;
    for (int i = 0; i < 24; i++) DES_KEY[i] = (unsigned char)(DES_KEY_XOR[i] ^ k1);
    for (int i = 0; i < 12; i++) SALT_HEAD[i] = (unsigned char)(SALT_HEAD_XOR[i] ^ k2);
    MARKS_READY = true;
}

/* —— 中性导出名（供 libshark.so 运行时 dlsym） —— */
const unsigned char* tt_seed() { prime_marks(); return DES_KEY; }
const unsigned char* tt_salt() { prime_marks(); return SALT_HEAD; }
int tt_slen() { prime_marks(); return 12; }

const char* tt_mark(const unsigned char* data, int len) {
    static std::string result;
    result = sm3_hex(data, len);
    return result.c_str();
}

} /* extern "C" */

/* gate.cpp — KL55 迷阵「破阵而出」（C++ OOP + 手写 OLLVM 综合收官卷）
 *
 * 八重对抗叠加（C++ 化后难度上调，全卷最难）：
 *  ① 控制流平坦化：外层 gate_sign 与内层 stage_crypt / stage_digest 三级状态机
 *     真实块之间插无意义中间块（破坏"真实块→预分发块"固定模式）
 *  ② 虚假控制流：不透明谓词 g_opaque 落 .bss + **异常边不透明谓词**（angr 默认不走异常边，
 *     天然抗符号执行；真实路径永不抛）
 *  ③ 字符串加密：标记 Fatdog_gate / 诱饵 Fatdog_fence 的 XOR 0x5A 密文，
 *     解密步骤本身拆进 JNI_OnLoad 的状态机（不在 .init_array 落明文）
 *  ④ 间接跳转：函数指针表 g_dispatch 派发 4 个同形副本，只有索引 0 是真签名
 *  ⑤ 多层嵌套：gate_sign → stage_crypt → stage_digest（外加虚派发到轮平坦化）
 *  ⑥ 反调试评分制：tracerPid + timing >= 2 静默换诱饵标记（令 sign 一并错）
 *  ⑦ 支配节点 key：g_dom_key 由入口块首次执行才派生（依赖运行时地址），
 *     分发器状态一律 ^= g_dom_key —— 「单独抽块模拟执行」必错（抗 angr/unicorn 逐个击破）
 *  ⑧ 虚函数藏算法：Cipher / Digest / Responder 抽象基类 + 真身派生 + 诱饵派生（RTTI 类名留线索）
 *
 * 算法（与 server.py 的 KEY_KL55 = "Fatdog_gate" 严格一致）：
 *   enc  = hex(魔改AES-128-ECB(S 盒换值, aes_key, "page=N&ts=T" 零填充到 32))
 *   sign = SHA256(真标记 + "|" + page + "|" + ts)     ← 标记参与签名（反调试换标记 → sign 亦错）
 *   响应体 = 魔改Base64(魔改AES-128-CBC(resp_key, resp_iv, JSON))
 *   aes_key  = SHA256(mark|aes)[:16]
 *   resp_key = SHA256(mark|resp)[:16]
 *   resp_iv  = SHA256(mark|riv)[:16]
 * 魔改点：AES S 盒 0x3A↔0x7F、0xB2↔0xE8 换值；Base64 码表左移 9 位。
 *
 * 破解路线：
 *   ① 逆 JNI_OnLoad 状态机（字符串解密 → 密钥派生），拿真标记 "Fatdog_gate"
 *   ② 恢复 vtable 定位真派生类：Cipher 真身 / Digest 真身 / Responder 真身
 *      （ARM64 指纹：LDR X8,[X0] → LDR X9,[X8,#8*N] → BLR X9）
 *   ③ 手工还原三级状态机（外层调度 + 两个内层阶段）
 *   ④ 认魔改 AES（认 RCON 常量 01 02 04 08…，比对 S 盒与标准 d6 90 e9 fe… 的差异）
 *   ⑤ 认魔改 Base64 码表（对比标准 A-Za-z0-9+/ 找循环移位量）
 *   ⑥ Frida hook 跳转表入口 / 类虚表观察实际目标
 *
 * 标记（真）：Fatdog_gate    诱饵（假）：Fatdog_fence（一字之差，命中即 403）
 */
#include <jni.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* ==================== 标记留存（字符串加密：XOR 0x5A 密文） ==================== */
static const unsigned char MARK_ENC[] = {
    28, 59, 46, 62, 53, 61, 5, 61, 59, 46, 63     /* "Fatdog_gate"  ^ 0x5A */
};
#define MARK_LEN 11
static const unsigned char FENCE_ENC[] = {
    28, 59, 46, 62, 53, 61, 5, 60, 63, 52, 57, 63 /* "Fatdog_fence" ^ 0x5A */
};
#define FENCE_LEN 12
static char g_mark[16];
static char g_fence[16];
static volatile uint32_t g_marker_proof = 0;

/* ==================== 状态编码密钥 ==================== */
/* 分发器状态一律 st ^ g_xor_key（^ g_dom_key）解码，令标准 FLA 形态匹配失效。 */
static volatile uint32_t g_xor_key = 0x5A5A5A5Au;
static volatile uint32_t g_dom_key = 0;   /* 支配节点 key：入口块首次执行才派生 */
static volatile int g_opaque = 0;         /* 不透明谓词（落 .bss，初始 0） */

/* ==================== 魔改 AES S 盒（4 处换值：0x3A↔0x7F、0xB2↔0xE8） ==================== */
static const unsigned char SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0xd2,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0x80,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x9b,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x37,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};
/* 换值：SBOX[0x3A]=d2(原80)、SBOX[0x7F]=80(原d2)、SBOX[0xB2]=9b(原37)、SBOX[0xE8]=37(原9b) */

static const unsigned char RCON[10] = { 0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36 };

/* 魔改 AES 逆 S 盒（对应换值后的 S 盒，自洽可逆） */
static const unsigned char INV_SBOX[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xe8,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x7f,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xb2,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x3a,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

/* ==================== AES 原语（轮函数走平坦化） ==================== */
static void aes_key_expand(const unsigned char key[16], unsigned char rk[176]) {
    int i, j;
    memcpy(rk, key, 16);
    for (i = 4; i < 44; i++) {
        unsigned char temp[4];
        for (j = 0; j < 4; j++) temp[j] = rk[(i - 1) * 4 + j];
        if (i % 4 == 0) {
            unsigned char t = temp[0];
            temp[0] = (unsigned char)(SBOX[temp[1]] ^ RCON[i / 4 - 1]);
            temp[1] = SBOX[temp[2]];
            temp[2] = SBOX[temp[3]];
            temp[3] = SBOX[t];
        }
        for (j = 0; j < 4; j++) rk[i * 4 + j] = (unsigned char)(rk[(i - 4) * 4 + j] ^ temp[j]);
    }
}

static unsigned char xtime(unsigned char x) {
    return (unsigned char)((x << 1) ^ ((x >> 7) ? 0x1b : 0));
}

/* 平坦化：AES 加密块 —— 10 轮拆进 switch(state)，语义与顺序实现逐字节一致 */
static void aes_enc_block_flat(const unsigned char rk[176], const unsigned char in[16], unsigned char out[16]) {
    unsigned char s[16];
    int i, c, r;
    uint32_t st = 0x10u ^ g_xor_key;
    memcpy(s, in, 16);
    for (;;) {
        uint32_t k = st ^ g_xor_key;
        switch (k) {
        case 0x10:  /* AddRoundKey(0) */
            for (i = 0; i < 16; i++) s[i] ^= rk[i];
            r = 1; st = 0x11u ^ g_xor_key; break;            /* → 轮循环头 */
        case 0x11:  /* 轮循环头（r<10 继续，否则收尾） */
            st = (r < 10) ? (0x12u ^ g_xor_key) : (0x19u ^ g_xor_key); break;
        case 0x12:  /* SubBytes */
            for (i = 0; i < 16; i++) s[i] = SBOX[s[i]];
            st = 0x13u ^ g_xor_key; break;
        case 0x13:  /* ShiftRows */
            { unsigned char t;
              t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
              t = s[2]; s[2] = s[10]; s[10] = t;
              t = s[6]; s[6] = s[14]; s[14] = t;
              t = s[3]; s[3] = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = t; }
            st = 0x14u ^ g_xor_key; break;
        case 0x14:  /* MixColumns */
            for (c = 0; c < 4; c++) {
                int o = c * 4;
                unsigned char a0 = s[o], a1 = s[o+1], a2 = s[o+2], a3 = s[o+3];
                unsigned char x = (unsigned char)(a0 ^ a1 ^ a2 ^ a3);
                s[o]   ^= (unsigned char)(x ^ xtime((unsigned char)(a0 ^ a1)));
                s[o+1] ^= (unsigned char)(x ^ xtime((unsigned char)(a1 ^ a2)));
                s[o+2] ^= (unsigned char)(x ^ xtime((unsigned char)(a2 ^ a3)));
                s[o+3] ^= (unsigned char)(x ^ xtime((unsigned char)(a3 ^ a0)));
            }
            st = 0x15u ^ g_xor_key; break;
        case 0x15:  /* AddRoundKey(r) */
            for (i = 0; i < 16; i++) s[i] ^= rk[r * 16 + i];
            st = 0x16u ^ g_xor_key; break;
        case 0x16:  /* r++ → 回轮循环头 */
            r++; st = 0x11u ^ g_xor_key; break;
        case 0x19:  /* 末轮 SubBytes */
            for (i = 0; i < 16; i++) s[i] = SBOX[s[i]];
            st = 0x1Au ^ g_xor_key; break;
        case 0x1A:  /* 末轮 ShiftRows */
            { unsigned char t;
              t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
              t = s[2]; s[2] = s[10]; s[10] = t;
              t = s[6]; s[6] = s[14]; s[14] = t;
              t = s[3]; s[3] = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = t; }
            st = 0x1Bu ^ g_xor_key; break;
        case 0x1B:  /* AddRoundKey(10) */
            for (i = 0; i < 16; i++) s[i] ^= rk[160 + i];
            st = 0x1Cu ^ g_xor_key; break;
        case 0x1C:  /* 出口 */
            memcpy(out, s, 16); return;
        case 0x1F:  /* 虚假块（恒不可达）：无意义运算后跳出口 */
            { volatile uint32_t t = 0x1Fu; t ^= t >> 3; }
            st = 0x1Cu ^ g_xor_key; break;
        default:
            st = 0x1Cu ^ g_xor_key; break;
        }
    }
}

/* ---- 逆操作辅助（供 CBC 解密） ---- */
static unsigned char xtime_dec(unsigned char x) {
    return (unsigned char)((x << 1) ^ ((x >> 7) ? 0x1b : 0));
}
static unsigned char mul9(unsigned char x)  { return (unsigned char)(xtime_dec(xtime_dec(xtime_dec(x))) ^ x); }
static unsigned char mul11(unsigned char x) { unsigned char t = xtime_dec(xtime_dec(xtime_dec(x))); return (unsigned char)(t ^ xtime_dec(x) ^ x); }
static unsigned char mul13(unsigned char x) { unsigned char t = xtime_dec(xtime_dec(xtime_dec(x))); return (unsigned char)(t ^ xtime_dec(xtime_dec(x)) ^ x); }
static unsigned char mul14(unsigned char x) { unsigned char t = xtime_dec(xtime_dec(xtime_dec(x))); return (unsigned char)(t ^ xtime_dec(xtime_dec(x)) ^ xtime_dec(x)); }

static void inv_shift_rows(unsigned char s[16]) {
    unsigned char t;
    t = s[1]; s[1] = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = t;
    t = s[2]; s[2] = s[10]; s[10] = t;
    t = s[6]; s[6] = s[14]; s[14] = t;
    t = s[3]; s[3] = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = t;
}

static void inv_mix_columns(unsigned char s[16]) {
    int c;
    for (c = 0; c < 4; c++) {
        int o = c * 4;
        unsigned char a0 = s[o], a1 = s[o+1], a2 = s[o+2], a3 = s[o+3];
        s[o]   = (unsigned char)(mul14(a0) ^ mul11(a1) ^ mul13(a2) ^ mul9(a3));
        s[o+1] = (unsigned char)(mul9(a0)  ^ mul14(a1) ^ mul11(a2) ^ mul13(a3));
        s[o+2] = (unsigned char)(mul13(a0) ^ mul9(a1)  ^ mul14(a2) ^ mul11(a3));
        s[o+3] = (unsigned char)(mul11(a0) ^ mul13(a1) ^ mul9(a2)  ^ mul14(a3));
    }
}

/* 平坦化：AES 解密块（与顺序实现逐字节一致） */
static void aes_dec_block_flat(const unsigned char rk[176], const unsigned char in[16], unsigned char out[16]) {
    unsigned char s[16];
    int i, r;
    uint32_t st = 0x20u ^ g_xor_key;
    memcpy(s, in, 16);
    for (;;) {
        uint32_t k = st ^ g_xor_key;
        switch (k) {
        case 0x20:  /* AddRoundKey(round 10) */
            for (i = 0; i < 16; i++) s[i] ^= rk[160 + i];
            r = 9; st = 0x21u ^ g_xor_key; break;
        case 0x21:  /* 轮循环头（r>=1 继续，否则收尾） */
            st = (r >= 1) ? (0x22u ^ g_xor_key) : (0x29u ^ g_xor_key); break;
        case 0x22:  /* InvShiftRows */
            inv_shift_rows(s);
            st = 0x23u ^ g_xor_key; break;
        case 0x23:  /* InvSubBytes */
            for (i = 0; i < 16; i++) s[i] = INV_SBOX[s[i]];
            st = 0x24u ^ g_xor_key; break;
        case 0x24:  /* AddRoundKey(r) */
            for (i = 0; i < 16; i++) s[i] ^= rk[r * 16 + i];
            st = 0x25u ^ g_xor_key; break;
        case 0x25:  /* InvMixColumns */
            inv_mix_columns(s);
            st = 0x26u ^ g_xor_key; break;
        case 0x26:  /* r-- → 回轮循环头 */
            r--; st = 0x21u ^ g_xor_key; break;
        case 0x29:  /* 末轮 InvShiftRows */
            inv_shift_rows(s);
            st = 0x2Au ^ g_xor_key; break;
        case 0x2A:  /* 末轮 InvSubBytes */
            for (i = 0; i < 16; i++) s[i] = INV_SBOX[s[i]];
            st = 0x2Bu ^ g_xor_key; break;
        case 0x2B:  /* AddRoundKey(0) */
            for (i = 0; i < 16; i++) s[i] ^= rk[i];
            st = 0x2Cu ^ g_xor_key; break;
        case 0x2C:
            memcpy(out, s, 16); return;
        default:
            st = 0x2Cu ^ g_xor_key; break;
        }
    }
}

/* 魔改 AES-128-CBC 解密（PKCS5 去填充）—— 供 Responder 使用 */
static int aes_cbc_decrypt(const unsigned char key[16], const unsigned char iv[16],
                           const unsigned char *ct, int ctlen, unsigned char *out) {
    unsigned char rk[176], prev[16], dec[16];
    int i, off, o = 0;
    if (ctlen <= 0 || ctlen % 16 != 0) return -1;
    aes_key_expand(key, rk);
    memcpy(prev, iv, 16);
    for (off = 0; off < ctlen; off += 16) {
        aes_dec_block_flat(rk, ct + off, dec);
        for (i = 0; i < 16; i++) out[o + i] = (unsigned char)(dec[i] ^ prev[i]);
        memcpy(prev, ct + off, 16);
        o += 16;
    }
    {
        int pad = out[o - 1];
        if (pad < 1 || pad > 16) return -1;
        return o - pad;
    }
}

/* ==================== SHA-256 ==================== */
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
static uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static void sha256(const unsigned char *msg, int len, unsigned char out[32]) {
    uint32_t h[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };
    unsigned char buf[64];
    unsigned long long bitlen = (unsigned long long)len * 8;
    int i, off = 0;
    for (off = 0; off + 64 <= len; off += 64) {
        uint32_t w[64], a,b,c,d,e,f,g,hh, s0,s1,ch,maj,t1,t2;
        for (i = 0; i < 16; i++)
            w[i] = ((uint32_t)msg[off+i*4]<<24)|((uint32_t)msg[off+i*4+1]<<16)
                 | ((uint32_t)msg[off+i*4+2]<<8)|(uint32_t)msg[off+i*4+3];
        for (i = 16; i < 64; i++) {
            s0 = rotr(w[i-15],7)^rotr(w[i-15],18)^(w[i-15]>>3);
            s1 = rotr(w[i-2],17)^rotr(w[i-2],19)^(w[i-2]>>10);
            w[i] = w[i-16]+s0+w[i-7]+s1;
        }
        a=h[0];b=h[1];c=h[2];d=h[3];e=h[4];f=h[5];g=h[6];hh=h[7];
        for (i = 0; i < 64; i++) {
            s1 = rotr(e,6)^rotr(e,11)^rotr(e,25);
            ch = (e&f)^((~e)&g);
            t1 = hh+s1+ch+K256[i]+w[i];
            s0 = rotr(a,2)^rotr(a,13)^rotr(a,22);
            maj = (a&b)^(a&c)^(b&c);
            t2 = s0+maj;
            hh=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
        }
        h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
    }
    {
        int rem = len - off;
        memcpy(buf, msg + off, rem);
        buf[rem] = 0x80;
        memset(buf + rem + 1, 0, 64 - rem - 1);
        if (rem >= 56) {
            uint32_t w[64], a,b,c,d,e,f,g,hh, s0,s1,ch,maj,t1,t2;
            for (i = 0; i < 16; i++)
                w[i] = ((uint32_t)buf[i*4]<<24)|((uint32_t)buf[i*4+1]<<16)
                     | ((uint32_t)buf[i*4+2]<<8)|(uint32_t)buf[i*4+3];
            for (i = 16; i < 64; i++) {
                s0 = rotr(w[i-15],7)^rotr(w[i-15],18)^(w[i-15]>>3);
                s1 = rotr(w[i-2],17)^rotr(w[i-2],19)^(w[i-2]>>10);
                w[i] = w[i-16]+s0+w[i-7]+s1;
            }
            a=h[0];b=h[1];c=h[2];d=h[3];e=h[4];f=h[5];g=h[6];hh=h[7];
            for (i = 0; i < 64; i++) {
                s1 = rotr(e,6)^rotr(e,11)^rotr(e,25);
                ch = (e&f)^((~e)&g);
                t1 = hh+s1+ch+K256[i]+w[i];
                s0 = rotr(a,2)^rotr(a,13)^rotr(a,22);
                maj = (a&b)^(a&c)^(b&c);
                t2 = s0+maj;
                hh=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
            }
            h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
            memset(buf, 0, 64);
        }
        for (i = 0; i < 8; i++) buf[63-i] = (unsigned char)((bitlen >> (i*8)) & 0xFF);
        {
            uint32_t w[64], a,b,c,d,e,f,g,hh, s0,s1,ch,maj,t1,t2;
            for (i = 0; i < 16; i++)
                w[i] = ((uint32_t)buf[i*4]<<24)|((uint32_t)buf[i*4+1]<<16)
                     | ((uint32_t)buf[i*4+2]<<8)|(uint32_t)buf[i*4+3];
            for (i = 16; i < 64; i++) {
                s0 = rotr(w[i-15],7)^rotr(w[i-15],18)^(w[i-15]>>3);
                s1 = rotr(w[i-2],17)^rotr(w[i-2],19)^(w[i-2]>>10);
                w[i] = w[i-16]+s0+w[i-7]+s1;
            }
            a=h[0];b=h[1];c=h[2];d=h[3];e=h[4];f=h[5];g=h[6];hh=h[7];
            for (i = 0; i < 64; i++) {
                s1 = rotr(e,6)^rotr(e,11)^rotr(e,25);
                ch = (e&f)^((~e)&g);
                t1 = hh+s1+ch+K256[i]+w[i];
                s0 = rotr(a,2)^rotr(a,13)^rotr(a,22);
                maj = (a&b)^(a&c)^(b&c);
                t2 = s0+maj;
                hh=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
            }
            h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
        }
    }
    for (i = 0; i < 8; i++) {
        out[i*4]   = (unsigned char)(h[i] >> 24);
        out[i*4+1] = (unsigned char)(h[i] >> 16);
        out[i*4+2] = (unsigned char)(h[i] >> 8);
        out[i*4+3] = (unsigned char)(h[i]);
    }
}

/* ==================== 魔改 Base64（码表左移 9 位；真/诱饵两套码表） ==================== */
static const char B64_CUSTOM[65] = "JKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/ABCDEFGHI";
static const char B64_STD[65]    = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int b64_val(const char *table, char c) {
    const char *p = strchr(table, c);
    return p ? (int)(p - table) : -1;
}

/* 按给定码表解码（'=' 与空白跳过；非法字符跳过） */
static int b64_decode_tbl(const char *table, const char *in, int inlen, unsigned char *out) {
    int i, o = 0, val = 0, bits = 0;
    for (i = 0; i < inlen; i++) {
        char c = in[i];
        int v;
        if (c == '=' || c == '\n' || c == '\r') continue;
        v = b64_val(table, c);
        if (v < 0) continue;
        val = (val << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[o++] = (unsigned char)((val >> bits) & 0xFF);
        }
    }
    return o;
}

/* ==================== 密钥派生（标记参与派生） ==================== */
static unsigned char g_aes_key[16];
static unsigned char g_resp_key[16];
static unsigned char g_resp_iv[16];
static volatile int g_keys_ready = 0;

static void derive_keys(void) {
    unsigned char dg[32];
    char buf[64];
    int bl;
    bl = snprintf(buf, sizeof(buf), "%s|aes", g_mark);
    sha256((const unsigned char *)buf, bl, dg);
    memcpy(g_aes_key, dg, 16);
    bl = snprintf(buf, sizeof(buf), "%s|resp", g_mark);
    sha256((const unsigned char *)buf, bl, dg);
    memcpy(g_resp_key, dg, 16);
    bl = snprintf(buf, sizeof(buf), "%s|riv", g_mark);
    sha256((const unsigned char *)buf, bl, dg);
    memcpy(g_resp_iv, dg, 16);
    g_keys_ready = 1;
}

/* ==================== 反调试评分制（宽松：>=2 才判） ==================== */
static int debug_score(void) {
    int score = 0;
    {
        FILE *fp = fopen("/proc/self/status", "r");
        char line[256];
        if (fp) {
            while (fgets(line, sizeof(line), fp)) {
                if (strncmp(line, "TracerPid:", 10) == 0) {
                    int pid = atoi(line + 10);
                    if (pid != 0) score++;
                    break;
                }
            }
            fclose(fp);
        }
    }
    {
        clock_t a = clock();
        clock_t b = clock();
        if ((b - a) > 5000) score++;
    }
    return score;
}

/* ==================== 输出缓冲 ==================== */
struct Board {
    char enc_hex[65];
    char sign_hex[65];
    char msg[64];
    unsigned char plain[32];
    unsigned char enc[32];
};
static Board &board() { static Board b; return b; }

/* ==================== 面向对象：虚函数藏加密算法 ==================== */
/* 请求加密器：真身魔改 AES-128-ECB；诱饵为"改坏的完整算法"（RTTI 类名留线索）。 */
class Cipher {
public:
    Cipher() : armed_(false) { memset(key_, 0, 16); }
    virtual ~Cipher() { wipe(); }
    virtual const char *sigil() const = 0;
    virtual void encrypt(const unsigned char *in, size_t n, unsigned char *out) const = 0;
    bool armed() const { return armed_; }
protected:
    void install(const unsigned char *k, size_t n) {
        size_t m = (n < 16) ? n : 16;
        memcpy(key_, k, m);
        armed_ = true;
    }
    void wipe() { for (int i = 0; i < 16; i++) key_[i] = 0; }
    unsigned char key_[16];
    bool armed_;
};

/* 真身：魔改 AES-128-ECB（轮函数走平坦化） */
class GateCipher : public Cipher {
public:
    explicit GateCipher(const unsigned char *k) { install(k, 16); aes_key_expand(key_, rk_); }
    const char *sigil() const override { return "gate"; }
    void encrypt(const unsigned char *in, size_t n, unsigned char *out) const override {
        size_t off;
        for (off = 0; off + 16 <= n; off += 16)
            aes_enc_block_flat(rk_, in + off, out + off);
    }
private:
    unsigned char rk_[176];
};

/* 诱饵：同结构但跳过 MixColumns（结果不同） */
class FenceCipher : public Cipher {
public:
    explicit FenceCipher(const unsigned char *k) { install(k, 16); aes_key_expand(key_, rk_); }
    const char *sigil() const override { return "fence"; }
    void encrypt(const unsigned char *in, size_t n, unsigned char *out) const override {
        size_t off;
        for (off = 0; off + 16 <= n; off += 16) {
            unsigned char blk[16];
            int i;
            memcpy(blk, in + off, 16);
            for (i = 0; i < 16; i++) blk[i] ^= rk_[i];
            /* 只做 SubBytes + ShiftRows，跳过 MixColumns */
            for (i = 0; i < 16; i++) blk[i] = SBOX[blk[i]];
            { unsigned char t;
              t = blk[1]; blk[1] = blk[5]; blk[5] = blk[9]; blk[9] = blk[13]; blk[13] = t;
              t = blk[2]; blk[2] = blk[10]; blk[10] = t;
              t = blk[6]; blk[6] = blk[14]; blk[14] = t;
              t = blk[3]; blk[3] = blk[15]; blk[15] = blk[11]; blk[11] = blk[7]; blk[7] = t; }
            for (i = 0; i < 16; i++) blk[i] ^= rk_[160 + i];
            memcpy(out + off, blk, 16);
        }
    }
private:
    unsigned char rk_[176];
};

/* 诱饵：LCG 驱动的伪随机流（与 AES 无关） */
class RuneCipher : public Cipher {
public:
    explicit RuneCipher(const unsigned char *k) { install(k, 16); }
    const char *sigil() const override { return "rune"; }
    void encrypt(const unsigned char *in, size_t n, unsigned char *out) const override {
        uint32_t s = 0x9E3779B9u;
        size_t i;
        for (i = 0; i < n; i++) {
            s = s * 1664525u + 1013904223u;
            out[i] = (unsigned char)(in[i] ^ (unsigned char)(s >> 24) ^ key_[(s >> 4) & 15]);
        }
    }
};

enum CipherKind { kGateCipher = 0, kFenceCipher = 1, kRuneCipher = 2 };
/* 工厂：三类都实例化 → 三个 vtable 都留在 .rodata（"恢复 vtable"考点） */
static Cipher *make_cipher(int kind) {
    switch (kind) {
    case kFenceCipher: return new FenceCipher(g_aes_key);
    case kRuneCipher:  return new RuneCipher(g_aes_key);
    case kGateCipher:
    default:           return new GateCipher(g_aes_key);
    }
}

/* ==================== 摘要器（真身 SHA256；诱饵先反转消息） ==================== */
class Digest {
public:
    virtual ~Digest() {}
    virtual const char *sigil() const = 0;
    virtual void hash(const char *msg, int len, unsigned char out[32]) const = 0;
};

class GateDigest : public Digest {
public:
    const char *sigil() const override { return "gate"; }
    void hash(const char *msg, int len, unsigned char out[32]) const override {
        sha256((const unsigned char *)msg, len, out);
    }
};

class FenceDigest : public Digest {
public:
    const char *sigil() const override { return "fence"; }
    void hash(const char *msg, int len, unsigned char out[32]) const override {
        unsigned char tmp[256];
        int i, n = (len > 256) ? 256 : len;
        for (i = 0; i < n; i++) tmp[i] = (unsigned char)msg[n - 1 - i];
        sha256(tmp, n, out);
    }
};

enum DigestKind { kGateDigest = 0, kFenceDigest = 1 };
static Digest *make_digest(int kind) {
    switch (kind) {
    case kFenceDigest: return new FenceDigest();
    case kGateDigest:
    default:           return new GateDigest();
    }
}

/* ==================== 响应体解密器（魔改 Base64 + 魔改 AES-CBC） ==================== */
class Responder {
public:
    Responder() : armed_(false) { memset(key_, 0, 16); memset(iv_, 0, 16); }
    virtual ~Responder() { wipe(); }
    virtual const char *sigil() const = 0;
    /* 输入：魔改 Base64 文本；输出：解密后的明文字节数（<0 失败） */
    virtual int decode(const char *in, int inlen, unsigned char *out) const = 0;
protected:
    void install(const unsigned char *k, const unsigned char *iv) { memcpy(key_, k, 16); memcpy(iv_, iv, 16); armed_ = true; }
    void wipe() { for (int i = 0; i < 16; i++) { key_[i] = 0; iv_[i] = 0; } }
    unsigned char key_[16];
    unsigned char iv_[16];
    bool armed_;
};

/* 真身：自定义码表 + 魔改 AES-CBC */
class GateResponder : public Responder {
public:
    GateResponder() { install(g_resp_key, g_resp_iv); }
    const char *sigil() const override { return "gate"; }
    int decode(const char *in, int inlen, unsigned char *out) const override {
        unsigned char ct[4096];
        int ctlen = b64_decode_tbl(B64_CUSTOM, in, inlen, ct);
        if (ctlen <= 0 || ctlen % 16 != 0) return -1;
        return aes_cbc_decrypt(key_, iv_, ct, ctlen, out);
    }
};

/* 诱饵：标准 Base64 码表（解不出魔改串） */
class FenceResponder : public Responder {
public:
    FenceResponder() { install(g_resp_key, g_resp_iv); }
    const char *sigil() const override { return "fence"; }
    int decode(const char *in, int inlen, unsigned char *out) const override {
        unsigned char ct[4096];
        int ctlen = b64_decode_tbl(B64_STD, in, inlen, ct);
        if (ctlen <= 0 || ctlen % 16 != 0) return -1;
        return aes_cbc_decrypt(key_, iv_, ct, ctlen, out);
    }
};

enum ResponderKind { kGateResponder = 0, kFenceResponder = 1 };
static Responder *make_responder(int kind) {
    switch (kind) {
    case kFenceResponder: return new FenceResponder();
    case kGateResponder:
    default:              return new GateResponder();
    }
}

/* ==================== 4 个同形签名副本（间接跳转派发） ==================== */
typedef void (*SignFn)(int, long long, const char *);

static void real_sign(int page, long long ts, const char *master);
static void fence_sign(int page, long long ts, const char *master);
static void order_sign(int page, long long ts, const char *master);
static void prefix_sign(int page, long long ts, const char *master);

/* 跳转表：索引 0 是真签名，其余为"完整但改坏"的同形副本 */
static const SignFn g_dispatch[4] = { real_sign, fence_sign, order_sign, prefix_sign };

/* ==================== 内层状态机①：加密阶段 ==================== */
/* 语义：拼消息 → 零填充到 32 → 虚派发加密（ECB 2 块）→ hex */
static void stage_crypt(int page, long long ts) {
    Board &B = board();
    static Cipher *g_cp = 0;
    static const char *H = "0123456789abcdef";
    int i;
    uint32_t st;
    if (!g_cp) g_cp = make_cipher(kGateCipher);
    (void)g_cp->armed();

    st = 0x300u ^ g_xor_key ^ g_dom_key;
    for (;;) {
        uint32_t s = st ^ g_xor_key ^ g_dom_key;
        switch (s) {
        case 0x300:  /* 拼消息 */
            snprintf(B.msg, sizeof(B.msg), "page=%d&ts=%lld", page, ts);
            st = 0x301u ^ g_xor_key ^ g_dom_key; break;
        case 0x301:  /* 零填充到 32 */
            memset(B.plain, 0, 32);
            {
                int ml = (int)strlen(B.msg);
                if (ml > 32) ml = 32;
                memcpy(B.plain, B.msg, ml);
            }
            st = 0x302u ^ g_xor_key ^ g_dom_key; break;
        case 0x302:  /* 虚派发加密（ECB 2 块） */
            g_cp->encrypt(B.plain, 32, B.enc);
            st = 0x303u ^ g_xor_key ^ g_dom_key; break;
        case 0x303:  /* enc → hex */
            for (i = 0; i < 32; i++) {
                B.enc_hex[2*i]   = H[B.enc[i] >> 4];
                B.enc_hex[2*i+1] = H[B.enc[i] & 0xF];
            }
            B.enc_hex[64] = 0;
            st = 0x304u ^ g_xor_key ^ g_dom_key; break;
        case 0x304: return;
        case 0x3F0:  /* 虚假块（恒不可达） */
            B.enc_hex[0] = 0; return;
        default:
            st = 0x304u ^ g_xor_key ^ g_dom_key; break;
        }
    }
}

/* ==================== 内层状态机②：签名阶段 ==================== */
/* 语义：拼签名消息（真标记参与）→ 虚派发摘要 → hex */
static void stage_digest(int page, long long ts) {
    Board &B = board();
    static Digest *g_dg = 0;
    static const char *H = "0123456789abcdef";
    char sigbuf[128];
    unsigned char dg[32];
    int i, sl;
    uint32_t st;
    if (!g_dg) g_dg = make_digest(kGateDigest);

    st = 0x380u ^ g_xor_key ^ g_dom_key;
    for (;;) {
        uint32_t s = st ^ g_xor_key ^ g_dom_key;
        switch (s) {
        case 0x380:  /* 拼签名消息（真标记 + page + ts） */
            sl = snprintf(sigbuf, sizeof(sigbuf), "%s|%d|%lld", g_mark, page, ts);
            st = 0x381u ^ g_xor_key ^ g_dom_key; break;
        case 0x381:  /* 虚派发摘要 */
            g_dg->hash(sigbuf, sl, dg);
            st = 0x382u ^ g_xor_key ^ g_dom_key; break;
        case 0x382:  /* hex */
            for (i = 0; i < 32; i++) {
                B.sign_hex[2*i]   = H[dg[i] >> 4];
                B.sign_hex[2*i+1] = H[dg[i] & 0xF];
            }
            B.sign_hex[64] = 0;
            st = 0x383u ^ g_xor_key ^ g_dom_key; break;
        case 0x383: return;
        default:
            st = 0x383u ^ g_xor_key ^ g_dom_key; break;
        }
    }
}

/* ==================== 外层状态机：调度（支配节点 key + 异常边 + 虚假块） ==================== */
static void gate_sign(int page, long long ts) {
    uint32_t st;
    /* 入口块：首次执行才派生支配节点 key（依赖运行时地址，静态/离线不可知）。
       单独抽块模拟执行时 g_dom_key=0 → 状态解码全错（抗 angr/unicorn 逐个击破）。 */
    g_dom_key = (uint32_t)((uintptr_t)&g_dom_key >> 4) ^ 0x9E3779B9u;

    st = 0x100u ^ g_xor_key ^ g_dom_key;
    for (;;) {
        uint32_t s = st ^ g_xor_key ^ g_dom_key;
        switch (s) {
        /* ---------- 真实块 ---------- */
        case 0x100:  /* R0：不透明谓词（恒真） */
            if (g_opaque * (g_opaque + 1) % 2 == 0 && g_opaque < 10)
                st = 0x101u ^ g_xor_key ^ g_dom_key;
            else
                st = 0x3FFu ^ g_xor_key ^ g_dom_key;   /* 恒假分支（不可达） */
            break;
        case 0x101:  /* R1：加密阶段（内层状态机） */
            stage_crypt(page, ts);
            st = 0x200u ^ g_xor_key ^ g_dom_key; break;   /* → 中间块 M0 */
        case 0x200:  /* M0：无意义中间块 */
            { volatile uint32_t t = 0x9E37u; t = t * 3u + 1u; }
            st = 0x102u ^ g_xor_key ^ g_dom_key; break;
        case 0x102:  /* R2：异常边不透明谓词（真实路径永不抛，但 CFG 有 invoke/landingpad） */
            try {
                if (((g_opaque * (g_opaque + 1)) & 1u) != 0u) throw 1;
            } catch (...) {
                Board &B = board();
                B.enc_hex[0] = 0;   /* 不可达 */
            }
            st = 0x103u ^ g_xor_key ^ g_dom_key; break;
        case 0x103:  /* R3：签名阶段（内层状态机） */
            stage_digest(page, ts);
            st = 0x201u ^ g_xor_key ^ g_dom_key; break;   /* → 中间块 M1 */
        case 0x201:  /* M1 */
            { volatile uint32_t t = 0x51EDu; t ^= t >> 7; }
            st = 0x104u ^ g_xor_key ^ g_dom_key; break;
        case 0x104:  /* 出口 */
            return;
        /* ---------- 虚假块 ---------- */
        case 0x3FF:  /* 提前 return（截断签名） */
            board().sign_hex[0] = 0;
            return;
        case 0x3FE:  /* 死循环 */
            for (;;) { }
        case 0x3FD:  /* 无意义运算后跳回入口 */
            { volatile uint32_t t = 1u; t <<= 24; }
            st = 0x100u ^ g_xor_key ^ g_dom_key; break;
        default:
            st = 0x104u ^ g_xor_key ^ g_dom_key; break;
        }
    }
}

/* ==================== 真签名（间接跳转目标） ==================== */
static void real_sign(int page, long long ts, const char *master) {
    (void)master;
    /* 反调试评分：>= 2 换诱饵标记 —— 令 sign 一并错（标记参与签名） */
    if (debug_score() >= 2) {
        memcpy(g_mark, g_fence, FENCE_LEN);
        g_mark[FENCE_LEN] = 0;
    }
    gate_sign(page, ts);
}

/* 假副本 1：标记写错（gate→fence），完整算法但内容错 */
static void fence_sign(int page, long long ts, const char *master) {
    Board &B = board();
    char sigbuf[128];
    unsigned char dg[32];
    static const char *H = "0123456789abcdef";
    int i, sl;
    (void)master;
    stage_crypt(page, ts);
    sl = snprintf(sigbuf, sizeof(sigbuf), "Fatdog_fence|%d|%lld", page, ts);
    sha256((const unsigned char *)sigbuf, sl, dg);
    for (i = 0; i < 32; i++) {
        B.sign_hex[2*i]   = H[dg[i] >> 4];
        B.sign_hex[2*i+1] = H[dg[i] & 0xF];
    }
    B.sign_hex[64] = 0;
}

/* 假副本 2：拼接顺序错（ts|page 颠倒） */
static void order_sign(int page, long long ts, const char *master) {
    Board &B = board();
    char sigbuf[128];
    unsigned char dg[32];
    static const char *H = "0123456789abcdef";
    int i, sl;
    (void)master;
    stage_crypt(page, ts);
    sl = snprintf(sigbuf, sizeof(sigbuf), "%s|%lld|%d", g_mark, ts, page);
    sha256((const unsigned char *)sigbuf, sl, dg);
    for (i = 0; i < 32; i++) {
        B.sign_hex[2*i]   = H[dg[i] >> 4];
        B.sign_hex[2*i+1] = H[dg[i] & 0xF];
    }
    B.sign_hex[64] = 0;
}

/* 假副本 3：缺标记前缀（只哈希 page|ts） */
static void prefix_sign(int page, long long ts, const char *master) {
    Board &B = board();
    char sigbuf[128];
    unsigned char dg[32];
    static const char *H = "0123456789abcdef";
    int i, sl;
    (void)master;
    stage_crypt(page, ts);
    sl = snprintf(sigbuf, sizeof(sigbuf), "%d|%lld", page, ts);
    sha256((const unsigned char *)sigbuf, sl, dg);
    for (i = 0; i < 32; i++) {
        B.sign_hex[2*i]   = H[dg[i] >> 4];
        B.sign_hex[2*i+1] = H[dg[i] & 0xF];
    }
    B.sign_hex[64] = 0;
}

/* 间接派发（真入口索引由运行时派生，静态不直白） */
static void indirect_sign(int page, long long ts) {
    uint32_t idx = (g_xor_key ^ 0x5A5A5A5Au) & 3u;   /* 恒 0，但静态不可判 */
    g_dispatch[idx](page, ts, g_mark);
}

/* ==================== JNI 接口（.cpp 里必须 extern "C"） ==================== */
extern "C" JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_GateCore_nativeSign(JNIEnv *env, jclass clazz, jint page, jlong ts) {
    (void)clazz;
    indirect_sign((int)page, (long long)ts);
    return env->NewStringUTF(board().enc_hex);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_GateCore_nativeSignHex(JNIEnv *env, jclass clazz, jint page, jlong ts) {
    (void)clazz;
    indirect_sign((int)page, (long long)ts);
    return env->NewStringUTF(board().sign_hex);
}

/* 解密响应体：魔改 Base64 解码 + 魔改 AES-CBC 解密（虚派发 Responder） */
extern "C" JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_GateCore_nativeDecrypt(JNIEnv *env, jclass clazz, jstring b64in) {
    (void)clazz;
    static Responder *g_rs = 0;
    const char *in;
    unsigned char pt[4096];
    int ptlen;
    if (!g_keys_ready) derive_keys();
    if (!g_rs) g_rs = make_responder(kGateResponder);
    in = env->GetStringUTFChars(b64in, 0);
    if (!in) return env->NewStringUTF("");
    ptlen = g_rs->decode(in, (int)strlen(in), pt);
    env->ReleaseStringUTFChars(b64in, in);
    if (ptlen <= 0) return env->NewStringUTF("");
    pt[ptlen] = 0;
    return env->NewStringUTF((const char *)pt);
}

/* ==================== JNI_OnLoad（分发器：字符串解密 + 密钥派生 + 标记留存） ==================== */
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm; (void)reserved;
    uint32_t st = 0x400u ^ g_xor_key;
    for (;;) {
        uint32_t s = st ^ g_xor_key;
        switch (s) {
        case 0x400:  /* 字符串加密变体：解密真标记 */
            { int i; for (i = 0; i < MARK_LEN; i++) g_mark[i] = (char)(MARK_ENC[i] ^ 0x5A); g_mark[MARK_LEN] = 0; }
            st = 0x401u ^ g_xor_key; break;
        case 0x401:  /* 解密诱饵标记 */
            { int i; for (i = 0; i < FENCE_LEN; i++) g_fence[i] = (char)(FENCE_ENC[i] ^ 0x5A); g_fence[FENCE_LEN] = 0; }
            st = 0x402u ^ g_xor_key; break;
        case 0x402:  /* 密钥派生（标记参与，aes/resp/riv） */
            if (!g_keys_ready) derive_keys();
            st = 0x403u ^ g_xor_key; break;
        case 0x403:  /* 标记留存：引用密文常量防 gc-sections 删除 */
            {
                uint32_t mp = 0x5A5A5A5Au;
                int i;
                for (i = 0; i < MARK_LEN;  i++) mp ^= ((uint32_t)MARK_ENC[i]  << (i & 7));
                for (i = 0; i < FENCE_LEN; i++) mp ^= ((uint32_t)FENCE_ENC[i] << (i & 7));
                g_marker_proof = mp;
            }
            st = 0x404u ^ g_xor_key; break;
        case 0x404: return JNI_VERSION_1_6;
        case 0x4FF:  /* 虚假块（恒不可达） */
            g_marker_proof = 0;
            return 0;
        default: st = 0x404u ^ g_xor_key; break;
        }
    }
}

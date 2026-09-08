/**
 * native53c.cpp — L53 焚天火域（加密核心 + 密钥 + 魔改 AES）
 *
 * 魔改 AES：4 处 S 盒替换 + 4 组 FK 常量异或 + 3 组循环左移密钥扩展
 * Feistel 轮函数：8 轮，每轮 3 个子密钥，轮函数用 AES 加密
 * RC4 响应加密 + HMAC-SHA256 签名
 * 密钥分散在 3 个混淆数组 + 2 个 XOR 数组
 */

#include <cstdint>
#include <cstring>
#include <string>
#include <android/log.h>

#define LOG_TAG "native53c"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// ==================== 魔改 S 盒（4 处替换） ====================
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
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16,
};
// 替换位置：SBOX[0x63]=0x3A, SBOX[0x7C]=0x7F, SBOX[0x77]=0xB2, SBOX[0x7B]=0xE8
// 解题时需先还原 S 盒

static uint8_t sbox_sub(uint8_t val) {
    uint8_t s = SBOX[val];
    // 4 处动态替换（与 L52 不同的替换逻辑）
    if (val == 0x63) s = 0x3A;
    else if (val == 0x7C) s = 0x7F;
    else if (val == 0x77) s = 0xB2;
    else if (val == 0x7B) s = 0xE8;
    return s;
}

// ==================== 魔改 FK 常量（4 组异或） ====================
static const uint32_t FK_XOR[] = { 0x5254465F, 0x4C33335F, 0x46495245, 0x5F4D4B35 };

static uint32_t fk_transform(uint32_t val, int round) {
    return val ^ FK_XOR[round % 4];
}

// ==================== 魔改密钥扩展（循环左移 3 个变体） ====================
static uint32_t rcon[12] = {
    0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1B000000,
    0x36000000, 0x6C000000
};

static uint32_t rot_word(uint32_t w) { return (w << 8) | (w >> 24); }

static uint32_t sub_word(uint32_t w) {
    uint8_t b[4];
    b[0] = sbox_sub((w >> 24) & 0xFF);
    b[1] = sbox_sub((w >> 16) & 0xFF);
    b[2] = sbox_sub((w >> 8) & 0xFF);
    b[3] = sbox_sub(w & 0xFF);
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | b[3];
}

// 3 个密钥扩展变体
static uint32_t key_expand_variant1(uint32_t prev, uint32_t rcon_val) {
    uint32_t tmp = rot_word(prev);
    tmp = sub_word(tmp);
    tmp ^= rcon_val;
    return tmp;
}

static uint32_t key_expand_variant2(uint32_t prev, uint32_t rcon_val) {
    // 循环左移 1 位后再 SubWord
    uint32_t tmp = (prev << 1) | (prev >> 31);
    tmp = sub_word(tmp);
    tmp ^= rcon_val;
    return tmp;
}

static uint32_t key_expand_variant3(uint32_t prev, uint32_t rcon_val) {
    // 循环左移 2 位后再 SubWord
    uint32_t tmp = (prev << 2) | (prev >> 30);
    tmp = sub_word(tmp);
    tmp ^= rcon_val;
    return tmp;
}

// ==================== Feistel 轮函数（8 轮 × 3 子密钥） ====================
static const int FEISTEL_ROUNDS = 8;

// Feistel 轮函数：用 AES 加密 right_half，然后 XOR left_half
static void feistel_round(uint8_t* left, uint8_t* right, const uint8_t* subkey) {
    // 轮函数：AES round 操作（SubBytes + ShiftRows + MixColumns）
    uint8_t tmp[16];
    for (int i = 0; i < 16; i++) tmp[i] = sbox_sub(right[i]);

    // ShiftRows（简化版）
    uint8_t shifted[16];
    shifted[0] = tmp[0]; shifted[1] = tmp[5]; shifted[2] = tmp[10]; shifted[3] = tmp[15];
    shifted[4] = tmp[4]; shifted[5] = tmp[9]; shifted[6] = tmp[14]; shifted[7] = tmp[3];
    shifted[8] = tmp[8]; shifted[9] = tmp[13]; shifted[10] = tmp[2]; shifted[11] = tmp[7];
    shifted[12] = tmp[12]; shifted[13] = tmp[1]; shifted[14] = tmp[6]; shifted[15] = tmp[11];

    // 与子密钥异或后 XOR 到 left
    for (int i = 0; i < 16; i++) left[i] ^= (shifted[i] ^ subkey[i]);
}

// 生成 Feistel 子密钥（从 16 字节主密钥扩展出 8×3×16 字节）
static void feistel_expand_keys(const uint8_t master[16], uint8_t keys[8][3][16]) {
    uint32_t w[4];
    w[0] = (master[0]<<24)|(master[1]<<16)|(master[2]<<8)|master[3];
    w[1] = (master[4]<<24)|(master[5]<<16)|(master[6]<<8)|master[7];
    w[2] = (master[8]<<24)|(master[9]<<16)|(master[10]<<8)|master[11];
    w[3] = (master[12]<<24)|(master[13]<<16)|(master[14]<<8)|master[15];

    // 扩展出 48 个子密钥（24 组 × 2 字 = 48 个 uint32_t）
    uint32_t expanded[48];
    for (int i = 0; i < 4; i++) expanded[i] = w[i];

    for (int i = 4; i < 48; i++) {
        uint32_t tmp = expanded[i-1];
        if (i % 4 == 0) {
            // 3 个密钥扩展变体轮流使用
            int variant = (i / 4) % 3;
            if (variant == 0) tmp = key_expand_variant1(tmp, rcon[i/4]);
            else if (variant == 1) tmp = key_expand_variant2(tmp, rcon[i/4]);
            else tmp = key_expand_variant3(tmp, rcon[i/4]);
        }
        expanded[i] = expanded[i-4] ^ tmp;
    }

    // 取 8 轮 × 3 子密钥
    for (int r = 0; r < FEISTEL_ROUNDS; r++) {
        for (int k = 0; k < 3; k++) {
            int idx = r * 3 + k;
            uint32_t val = expanded[idx % 48];
            keys[r][k][0] = (val >> 24) & 0xFF;
            keys[r][k][1] = (val >> 16) & 0xFF;
            keys[r][k][2] = (val >> 8) & 0xFF;
            keys[r][k][3] = val & 0xFF;
            // 复制到 16 字节（用扩展值填充）
            for (int j = 4; j < 16; j++) {
                keys[r][k][j] = keys[r][k][j % 4] ^ (j * 0x11 + r * 0x37 + k * 0x5B);
            }
        }
    }
}

// Feistel 加密：8 轮，每轮 3 个子密钥
static std::string feistel_encrypt(const std::string& data, const uint8_t key[16]) {
    // 填充到 32 字节
    std::string padded = data;
    while (padded.size() % 32 != 0) padded += '\0';

    uint8_t keys[FEISTEL_ROUNDS][3][16];
    feistel_expand_keys(key, keys);

    std::string result = padded;
    for (size_t blk = 0; blk < padded.size(); blk += 32) {
        uint8_t left[16], right[16];
        memcpy(left, padded.c_str() + blk, 16);
        memcpy(right, padded.c_str() + blk + 16, 16);

        for (int r = 0; r < FEISTEL_ROUNDS; r++) {
            // 每轮用不同的子密钥
            const uint8_t* sk = (r % 3 == 0) ? keys[r][0] : (r % 3 == 1) ? keys[r][1] : keys[r][2];
            // Feistel round: new_right = left ^ F(right, sk)
            uint8_t tmp[16];
            // F 函数：SubBytes → ShiftRows → XOR sk
            for (int i = 0; i < 16; i++) tmp[i] = sbox_sub(right[i]);
            uint8_t shifted[16];
            shifted[0]=tmp[0]; shifted[1]=tmp[5]; shifted[2]=tmp[10]; shifted[3]=tmp[15];
            shifted[4]=tmp[4]; shifted[5]=tmp[9]; shifted[6]=tmp[14]; shifted[7]=tmp[3];
            shifted[8]=tmp[8]; shifted[9]=tmp[13]; shifted[10]=tmp[2]; shifted[11]=tmp[7];
            shifted[12]=tmp[12]; shifted[13]=tmp[1]; shifted[14]=tmp[6]; shifted[15]=tmp[11];
            uint8_t new_right[16];
            for (int i = 0; i < 16; i++) new_right[i] = left[i] ^ shifted[i] ^ sk[i];
            // swap
            memcpy(left, right, 16);
            memcpy(right, new_right, 16);
        }

        memcpy(result.data() + blk, left, 16);
        memcpy(result.data() + blk + 16, right, 16);
    }
    return result;
}

// ==================== RC4 ====================
static std::string rc4_crypt(const uint8_t* key, int key_len, const std::string& data) {
    uint8_t S[256];
    for (int i = 0; i < 256; i++) S[i] = i;
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % key_len]) & 0xFF;
        uint8_t t = S[i]; S[i] = S[j]; S[j] = t;
    }
    std::string result = data;
    int x = 0, y = 0;
    for (size_t i = 0; i < data.size(); i++) {
        x = (x + 1) & 0xFF;
        y = (y + S[x]) & 0xFF;
        uint8_t t = S[x]; S[x] = S[y]; S[y] = t;
        result[i] ^= S[(S[x] + S[y]) & 0xFF];
    }
    return result;
}

// ==================== 密钥分散存储 ====================
// 混淆数组 A：^0x3C 还原 = "Fatdog_aes_key_\x00"（16 bytes）
uint8_t K53_AES_OBFUSC_A[] = {
    0x7a,0x5d,0x48,0x58,0x53,0x5b,0x63,0x5d,
    0x59,0x4f,0x63,0x57,0x59,0x45,0x63,0x3c
};
static const uint8_t K53_AES_XOR_A = 0x3C;

// 混淆数组 B：^0x3C 还原 = "Fatdog_hmac_k53\x00"（16 bytes）
uint8_t K53_HMAC_OBFUSC_B[] = {
    0x7a,0x5d,0x48,0x58,0x53,0x5b,0x63,0x54,
    0x51,0x5d,0x5f,0x63,0x57,0x09,0x0f,0x3c
};
static const uint8_t K53_HMAC_XOR_B = 0x3C;

// 混淆数组 C：^0x3C 还原 = "Fatdog_rc4_k53\x00\x00"（16 bytes）
uint8_t K53_RC4_OBFUSC_C[] = {
    0x7a,0x5d,0x48,0x58,0x53,0x5b,0x63,0x4e,
    0x5f,0x08,0x63,0x57,0x09,0x0f,0x3c,0x3c
};
static const uint8_t K53_RC4_XOR_C = 0x3C;

static std::string get_key_a() {
    std::string k(16, '\0');
    for (int i = 0; i < 16; i++) k[i] = K53_AES_OBFUSC_A[i] ^ K53_AES_XOR_A;
    return k;
}

static std::string get_key_b() {
    std::string k(16, '\0');
    for (int i = 0; i < 16; i++) k[i] = K53_HMAC_OBFUSC_B[i] ^ K53_HMAC_XOR_B;
    return k;
}

static std::string get_key_c() {
    std::string k(16, '\0');
    for (int i = 0; i < 16; i++) k[i] = K53_RC4_OBFUSC_C[i] ^ K53_RC4_XOR_C;
    return k;
}

// ==================== 内部接口（C++，被 native53 dlsym 调用） ====================
static uint8_t g_hmac_key[16], g_aes_key[16], g_rc4_key[16];
static bool g_keys_init = false;

static void ensure_keys() {
    if (g_keys_init) return;
    std::string hb = get_key_b();
    memcpy(g_hmac_key, hb.c_str(), 16);
    std::string ab = get_key_a();
    memcpy(g_aes_key, ab.c_str(), 16);
    std::string cb = get_key_c();
    memcpy(g_rc4_key, cb.c_str(), 16);
    g_keys_init = true;
}


static void build_feistel_key(uint8_t aes_key[16]) {
    ensure_keys();
    memcpy(aes_key, g_aes_key, 16);
    // FK 按大端逐字节异或，与 Python/server 端一致
    for (int i = 0; i < 4; i++) {
        uint32_t val = ((uint32_t)aes_key[i * 4] << 24) |
                       ((uint32_t)aes_key[i * 4 + 1] << 16) |
                       ((uint32_t)aes_key[i * 4 + 2] << 8) |
                       aes_key[i * 4 + 3];
        val = fk_transform(val, i);
        aes_key[i * 4] = (val >> 24) & 0xFF;
        aes_key[i * 4 + 1] = (val >> 16) & 0xFF;
        aes_key[i * 4 + 2] = (val >> 8) & 0xFF;
        aes_key[i * 4 + 3] = val & 0xFF;
    }
}

// 魔改 AES 加密（AES S盒替换 + FK 异或 + Feistel）
std::string aesEncrypt(const std::string& data) {
    uint8_t aes_key[16];
    build_feistel_key(aes_key);
    return feistel_encrypt(data, aes_key);
}

// RC4 响应加密
std::string rc4Encrypt(const std::string& data) {
    ensure_keys();
    return rc4_crypt(g_rc4_key, 16, data);
}

// ==================== C 导出接口（dlsym 可用） ====================
extern "C" {

// HMAC key（返回 16 字节 buffer）
const uint8_t* getHmacKey() {
    ensure_keys();
    return g_hmac_key;
}

// AES key
const uint8_t* getAesKeyC() {
    ensure_keys();
    return g_aes_key;
}

// RC4 key
const uint8_t* getRc4KeyC() {
    ensure_keys();
    return g_rc4_key;
}

int k53FeistelEncrypt(const uint8_t* in, int inLen, uint8_t* out, int outCap, int* outLen) {
    ensure_keys();
    if (!out || !outLen || inLen < 0) return -1;
    uint8_t aes_key[16];
    build_feistel_key(aes_key);
    std::string raw(inLen > 0 ? (const char*)in : "", inLen > 0 ? inLen : 0);
    std::string enc = feistel_encrypt(raw, aes_key);
    if ((int)enc.size() > outCap) return -2;
    memcpy(out, enc.data(), enc.size());
    *outLen = (int)enc.size();
    return 0;
}

int k53Rc4Crypt(const uint8_t* in, int inLen, uint8_t* out, int outCap, int* outLen) {
    ensure_keys();
    if (!out || !outLen || inLen < 0 || inLen > outCap) return -1;
    std::string raw(inLen > 0 ? (const char*)in : "", inLen > 0 ? inLen : 0);
    std::string enc = rc4_crypt(g_rc4_key, 16, raw);
    memcpy(out, enc.data(), enc.size());
    *outLen = inLen;
    return 0;
}

}  // extern "C"

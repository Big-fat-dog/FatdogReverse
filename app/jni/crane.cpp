/*
 * libcrane.so — L50 幽暗深渊（Native大陆第 3 关）
 *
 * 特性：vtable 虚函数表分发 · AES-128-ECB + SHA-256 · 跨层回调 · 全动态注册
 *
 * 静态分析视角（本关刻意堵死"打开 so 一眼看穿"）：
 *   - 导出表里**只有 JNI_OnLoad**：原来的 Java_* 静态命名导出已改成
 *     RegisterNatives 动态注册，注册用的类名/方法名/签名全是密文；
 *   - 真正的算法类（Seal / SealAlpha / SealBeta / Relay）全部落在
 *     **匿名命名空间**里 —— 连 vtable 与析构函数都不再进 .dynsym；
 *   - AES 密钥只有头段在本 so（XOR ^0x2A），尾段在 Java（跨层回调取件）。
 *
 * 跨层回调（native → Java）：
 *   Bk50 构造函数用**反射**造出 com.fatdog.reverse.s 包下某个被 R8 改名的
 *   类实例 → bindHolder(实例) 交给本 so 存成全局引用 → 加密时按方法名回调
 *   slice(int mask) 取尾段 "2026"；掩码（K50_MASK）只有本 so 知道。
 *   少了掩码，Java 侧解出来的是乱码 → AES key 拼错 → 服务端 403。
 *
 * 业务代码（~600 行）— 真实业务函数名，无人调用，纯干扰。
 *
 * 协议：GET /api/l50?enc=AES 密文&sign=SHA256 签名&ts=T（秒级 ts，System.currentTimeMillis()/1000）
 * flag：FLAG_18_L50{abyssal_depths}
 */

#include <jni.h>
#include <string>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <vector>
#include <map>
#include <functional>
#include <memory>
#include <sstream>
#include <algorithm>
#include <cstdint>
#include <array>
#include <mutex>
#include <thread>

/* ============================================================
 * 字符串密文化：下表全是 XOR 后的字节，运行时 decloak 还原。
 * 掩码必须走 volatile —— 否则 -O2 会把整表折叠成明文常量写进 .rodata。
 * ============================================================ */
static std::string decloak(const unsigned char* enc, size_t n, unsigned char mk) {
    std::string out(n, '\0');
    volatile unsigned char m = mk;
    for (size_t i = 0; i < n; i++) out[i] = (char)(enc[i] ^ m);
    return out;
}
#define DK(ARR, MK) decloak((ARR), sizeof(ARR), (unsigned char)(MK))

/* 类名 / 方法名 / 签名 / 回调锚点 / 提示串 —— 构建期 XOR ^0x5A 密文化 */
static const unsigned char A_CLS[] = { 0x39,0x35,0x37,0x75,0x3C,0x3B,0x2E,0x3E,0x35,0x3D,0x75,0x28,0x3F,0x2C,0x3F,0x28,0x29,0x3F,0x75,0x18,0x31,0x6F,0x6A };  // com/fatdog/reverse/Bk50
static const unsigned char A_M1[] = { 0x34,0x3B,0x2E,0x33,0x2C,0x3F,0x1F,0x34,0x39 };  // nativeEnc
static const unsigned char A_G1[] = { 0x72,0x13,0x10,0x73,0x16,0x30,0x3B,0x2C,0x3B,0x75,0x36,0x3B,0x34,0x3D,0x75,0x09,0x2E,0x28,0x33,0x34,0x3D,0x61 };  // (IJ)Ljava/lang/String;
static const unsigned char A_M2[] = { 0x34,0x3B,0x2E,0x33,0x2C,0x3F,0x09,0x33,0x3D,0x34 };  // nativeSign
static const unsigned char A_G2[] = { 0x72,0x16,0x30,0x3B,0x2C,0x3B,0x75,0x36,0x3B,0x34,0x3D,0x75,0x09,0x2E,0x28,0x33,0x34,0x3D,0x61,0x73,0x16,0x30,0x3B,0x2C,0x3B,0x75,0x36,0x3B,0x34,0x3D,0x75,0x09,0x2E,0x28,0x33,0x34,0x3D,0x61 };  // (Ljava/lang/String;)Ljava/lang/String;
static const unsigned char A_M3[] = { 0x3D,0x3F,0x2E,0x11,0x3F,0x23,0x12,0x33,0x34,0x2E };  // getKeyHint
static const unsigned char A_G3[] = { 0x72,0x73,0x16,0x30,0x3B,0x2C,0x3B,0x75,0x36,0x3B,0x34,0x3D,0x75,0x09,0x2E,0x28,0x33,0x34,0x3D,0x61 };  // ()Ljava/lang/String;
static const unsigned char A_M4[] = { 0x38,0x33,0x34,0x3E,0x12,0x35,0x36,0x3E,0x3F,0x28 };  // bindHolder
static const unsigned char A_G4[] = { 0x72,0x16,0x30,0x3B,0x2C,0x3B,0x75,0x36,0x3B,0x34,0x3D,0x75,0x15,0x38,0x30,0x3F,0x39,0x2E,0x61,0x73,0x0C };  // (Ljava/lang/Object;)V
static const unsigned char A_CB[] = { 0x29,0x36,0x33,0x39,0x3F };  // slice
static const unsigned char A_GB[] = { 0x72,0x13,0x73,0x16,0x30,0x3B,0x2C,0x3B,0x75,0x36,0x3B,0x34,0x3D,0x75,0x09,0x2E,0x28,0x33,0x34,0x3D,0x61 };  // (I)Ljava/lang/String;
static const unsigned char A_HINT[] = { 0x32,0x33,0x34,0x2E,0x05,0x32,0x33,0x3E,0x3E,0x3F,0x34 };  // hint_hidden

/* AES 密钥头段（"Fatdog_abys_" ^0x2A）；尾段在 Java，跨层回调取件 */
static const unsigned char K50_AES_HEAD[] = { 0x6C,0x4B,0x5E,0x4E,0x45,0x4D,0x75,0x4B,0x48,0x53,0x59,0x75 };

/* ============================================================
 * AES-128-ECB — 标准实现
 * ============================================================ */

static const uint8_t AES_SBOX[256] = {
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

static const uint8_t AES_RCON[11] = {
    0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
};

static void aes_key_expand(const uint8_t key[16], uint8_t roundKeys[176]) {
    for (int i = 0; i < 16; i++) roundKeys[i] = key[i];
    int bytesGenerated = 16;
    int rconIter = 1;
    uint8_t temp[4];
    while (bytesGenerated < 176) {
        for (int i = 0; i < 4; i++) temp[i] = roundKeys[bytesGenerated - 4 + i];
        if (bytesGenerated % 16 == 0) {
            uint8_t t = temp[0];
            temp[0] = AES_SBOX[temp[1]] ^ AES_RCON[rconIter++];
            temp[1] = AES_SBOX[temp[2]];
            temp[2] = AES_SBOX[temp[3]];
            temp[3] = AES_SBOX[t];
        }
        for (int i = 0; i < 4; i++) {
            roundKeys[bytesGenerated] = roundKeys[bytesGenerated - 16] ^ temp[i];
            bytesGenerated++;
        }
    }
}

static void aes_add_round_key(uint8_t state[16], const uint8_t rk[16]) {
    for (int i = 0; i < 16; i++) state[i] ^= rk[i];
}

static void aes_sub_bytes(uint8_t state[16]) {
    for (int i = 0; i < 16; i++) state[i] = AES_SBOX[state[i]];
}

static void aes_shift_rows(uint8_t state[16]) {
    uint8_t t;
    t = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = t;
    t = state[2]; state[2] = state[10]; state[10] = t; t = state[6]; state[6] = state[14]; state[14] = t;
    t = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = t;
}

static uint8_t aes_xtime(uint8_t x) { return (uint8_t)((x << 1) ^ (((x >> 7) & 1) * 0x1b)); }

static void aes_mix_columns(uint8_t state[16]) {
    for (int c = 0; c < 4; c++) {
        int i = c * 4;
        uint8_t a0 = state[i], a1 = state[i+1], a2 = state[i+2], a3 = state[i+3];
        uint8_t t = a0 ^ a1 ^ a2 ^ a3;
        state[i]   ^= t ^ aes_xtime(a0 ^ a1);
        state[i+1] ^= t ^ aes_xtime(a1 ^ a2);
        state[i+2] ^= t ^ aes_xtime(a2 ^ a3);
        state[i+3] ^= t ^ aes_xtime(a3 ^ a0);
    }
}

static void aes_encrypt_block(const uint8_t in[16], uint8_t out[16], const uint8_t rk[176]) {
    uint8_t state[16];
    memcpy(state, in, 16);
    aes_add_round_key(state, rk);
    for (int r = 1; r < 10; r++) {
        aes_sub_bytes(state);
        aes_shift_rows(state);
        aes_mix_columns(state);
        aes_add_round_key(state, rk + r * 16);
    }
    aes_sub_bytes(state);
    aes_shift_rows(state);
    aes_add_round_key(state, rk + 160);
    memcpy(out, state, 16);
}

static std::vector<uint8_t> aes_ecb_encrypt(const uint8_t key[16], const uint8_t* data, size_t len) {
    uint8_t rk[176];
    aes_key_expand(key, rk);
    size_t padLen = 16 - (len % 16);
    size_t total = len + padLen;
    std::vector<uint8_t> padded(total);
    memcpy(padded.data(), data, len);
    for (size_t i = len; i < total; i++) padded[i] = (uint8_t)padLen;
    std::vector<uint8_t> out(total);
    for (size_t i = 0; i < total; i += 16)
        aes_encrypt_block(padded.data() + i, out.data() + i, rk);
    return out;
}

/* ============================================================
 * SHA-256 — 标准实现
 * ============================================================ */

static const uint32_t SHA256_K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static uint32_t sha256_rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
static uint32_t sha256_ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
static uint32_t sha256_maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
static uint32_t sha256_bsig0(uint32_t x) { return sha256_rotr(x,2)^sha256_rotr(x,13)^sha256_rotr(x,22); }
static uint32_t sha256_bsig1(uint32_t x) { return sha256_rotr(x,6)^sha256_rotr(x,11)^sha256_rotr(x,25); }
static uint32_t sha256_ssig0(uint32_t x) { return sha256_rotr(x,7)^sha256_rotr(x,18)^(x>>3); }
static uint32_t sha256_ssig1(uint32_t x) { return sha256_rotr(x,17)^sha256_rotr(x,19)^(x>>10); }

static void sha256_transform(uint32_t state[8], const uint8_t block[64]) {
    uint32_t W[64];
    for (int i = 0; i < 16; i++)
        W[i] = ((uint32_t)block[i*4]<<24)|((uint32_t)block[i*4+1]<<16)|((uint32_t)block[i*4+2]<<8)|block[i*4+3];
    for (int i = 16; i < 64; i++)
        W[i] = sha256_ssig1(W[i-2]) + W[i-7] + sha256_ssig0(W[i-15]) + W[i-16];
    uint32_t a=state[0],b=state[1],c=state[2],d=state[3],e=state[4],f=state[5],g=state[6],h=state[7];
    for (int i = 0; i < 64; i++) {
        uint32_t T1 = h + sha256_bsig1(e) + sha256_ch(e,f,g) + SHA256_K[i] + W[i];
        uint32_t T2 = sha256_bsig0(a) + sha256_maj(a,b,c);
        h=g; g=f; f=e; e=d+T1; d=c; c=b; b=a; a=T1+T2;
    }
    state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d; state[4]+=e; state[5]+=f; state[6]+=g; state[7]+=h;
}

static std::string sha256_hex(const std::string& data) {
    uint32_t state[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    size_t len = data.size();
    size_t bitLen = len * 8;
    size_t total = len + 1;
    while (total % 64 != 56) total++;
    total += 8;
    std::vector<uint8_t> msg(total, 0);
    memcpy(msg.data(), data.data(), len);
    msg[len] = 0x80;
    for (int i = 0; i < 8; i++) msg[total - 8 + i] = (uint8_t)(bitLen >> (56 - 8 * i));
    for (size_t i = 0; i < total; i += 64) {
        uint8_t block[64];
        memcpy(block, msg.data() + i, 64);
        sha256_transform(state, block);
    }
    char hex[65];
    for (int i = 0; i < 8; i++)
        snprintf(hex + i * 8, 9, "%08x", state[i]);
    return std::string(hex, 64);
}

/* ============================================================
 * vtable 接口 + 真实加密引擎
 * —— 全部落在**匿名命名空间**里：具名空间/全局作用域下的多态类会
 *    把 vtable 与析构函数写进 .dynsym（nm -D 一眼看到 AesEngine 之类），
 *    放进匿名命名空间后它们变成内部链接，导出表里什么都不剩。
 * ============================================================ */
namespace {

class Seal {
public:
    virtual ~Seal() = default;
    virtual std::string run(const std::string& key, const std::string& data) = 0;
};

class SealAlpha : public Seal {           /* AES-128-ECB */
public:
    std::string run(const std::string& key, const std::string& data) override {
        auto out = aes_ecb_encrypt(
            reinterpret_cast<const uint8_t*>(key.data()),
            reinterpret_cast<const uint8_t*>(data.data()),
            data.size());
        static const char hexc[] = "0123456789abcdef";
        std::string hex;
        hex.reserve(out.size() * 2);
        for (uint8_t b : out) { hex += hexc[b >> 4]; hex += hexc[b & 0x0f]; }
        return hex;
    }
};

class SealBeta : public Seal {            /* 摘要 */
public:
    std::string run(const std::string& key, const std::string& data) override {
        (void) key;
        return sha256_hex(data);
    }
};

/* vtable 分发器：槽位 0=加密、1=摘要 */
class Relay {
    Seal* slots_[2];
public:
    Relay() { slots_[0] = new SealAlpha(); slots_[1] = new SealBeta(); }
    ~Relay() { delete slots_[0]; delete slots_[1]; }
    Relay(const Relay&) = delete;
    Relay& operator=(const Relay&) = delete;
    std::string run(int slot, const std::string& key, const std::string& data) {
        if (slot < 0 || slot >= 2) return std::string();
        return slots_[slot]->run(key, data);
    }
};

} /* anonymous namespace */

static Relay g_relay;

/* ============================================================
 * 伪随机字符串生成器
 * ============================================================ */

static std::string gen_random_string(int len) {
    static const char charset[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    std::string result;
    result.resize(len);
    for (int i = 0; i < len; i++)
        result[i] = charset[rand() % (sizeof(charset) - 1)];
    return result;
}

/* ============================================================
 * 密钥与算法类已整体下移：密钥头段走 K50_AES_HEAD 密文表 +
 * 跨层回调拼尾段；算法类收进上方匿名命名空间。此处不再有任何
 * 以算法命名的具名类（原 KeyProvider/AesEngine/ICipher/CipherDispatcher 已移除）。
 * ============================================================ */

/* ============================================================
 * 业务代码 — 全部是真实的业务函数名，无人调用
 * 以下 ~750 行全部是干扰代码
 * ============================================================ */

// ---------- UserSessionManager ----------
class UserSessionManager {
    std::map<std::string, std::string> activeSessions;
    std::map<std::string, time_t> sessionExpiry;
    int maxSessions;
    int sessionTimeout;
public:
    UserSessionManager() : maxSessions(1000), sessionTimeout(3600) {}

    bool login(const std::string& userId, const std::string& token) {
        if (activeSessions.size() >= (size_t)maxSessions) return false;
        activeSessions[userId] = token;
        sessionExpiry[userId] = time(nullptr) + sessionTimeout;
        return true;
    }

    void logout(const std::string& userId) {
        activeSessions.erase(userId);
        sessionExpiry.erase(userId);
    }

    bool refreshToken(const std::string& userId) {
        auto it = sessionExpiry.find(userId);
        if (it == sessionExpiry.end()) return false;
        it->second = time(nullptr) + sessionTimeout;
        return true;
    }

    bool validateToken(const std::string& userId, const std::string& token) {
        auto it = activeSessions.find(userId);
        if (it == activeSessions.end()) return false;
        if (it->second != token) return false;
        if (sessionExpiry[userId] < time(nullptr)) {
            logout(userId);
            return false;
        }
        return true;
    }

    int getActiveSessionCount() const { return (int)activeSessions.size(); }

    void cleanupExpired() {
        time_t now = time(nullptr);
        for (auto it = sessionExpiry.begin(); it != sessionExpiry.end(); ) {
            if (it->second < now) {
                activeSessions.erase(it->first);
                it = sessionExpiry.erase(it);
            } else {
                ++it;
            }
        }
    }

    std::string getSessionInfo(const std::string& userId) {
        auto it = activeSessions.find(userId);
        if (it == activeSessions.end()) return "not_found";
        time_t exp = sessionExpiry[userId];
        char buf[128];
        snprintf(buf, sizeof(buf), "active,expires=%ld,remaining=%ld", exp, exp - time(nullptr));
        return std::string(buf);
    }

    bool extendSession(const std::string& userId, int extraSeconds) {
        auto it = sessionExpiry.find(userId);
        if (it == sessionExpiry.end()) return false;
        it->second += extraSeconds;
        return true;
    }

    std::vector<std::string> getExpiredUserIds() {
        std::vector<std::string> result;
        time_t now = time(nullptr);
        for (auto& p : sessionExpiry)
            if (p.second < now) result.push_back(p.first);
        return result;
    }
};

// ---------- OrderService ----------
class OrderService {
    struct Order { std::string orderId; std::string userId; double amount; int status; time_t createdAt; };
    std::map<std::string, Order> orders;
    int nextOrderNum;
public:
    OrderService() : nextOrderNum(10000) {}

    std::string createOrder(const std::string& userId, double amount) {
        char buf[32];
        snprintf(buf, sizeof(buf), "ORD-%d", nextOrderNum++);
        Order o;
        o.orderId = buf;
        o.userId = userId;
        o.amount = amount;
        o.status = 0;
        o.createdAt = time(nullptr);
        orders[buf] = o;
        return std::string(buf);
    }

    bool cancelOrder(const std::string& orderId) {
        auto it = orders.find(orderId);
        if (it == orders.end() || it->second.status != 0) return false;
        it->second.status = -1;
        return true;
    }

    int queryStatus(const std::string& orderId) {
        auto it = orders.find(orderId);
        if (it == orders.end()) return -2;
        return it->second.status;
    }

    bool completeOrder(const std::string& orderId) {
        auto it = orders.find(orderId);
        if (it == orders.end() || it->second.status != 0) return false;
        it->second.status = 1;
        return true;
    }

    double getOrderAmount(const std::string& orderId) {
        auto it = orders.find(orderId);
        if (it == orders.end()) return -1.0;
        return it->second.amount;
    }

    std::vector<std::string> getUserOrders(const std::string& userId) {
        std::vector<std::string> result;
        for (auto& p : orders)
            if (p.second.userId == userId) result.push_back(p.first);
        return result;
    }

    int getTotalOrders() const { return (int)orders.size(); }

    double getTotalRevenue() const {
        double sum = 0;
        for (auto& p : orders)
            if (p.second.status == 1) sum += p.second.amount;
        return sum;
    }

    bool updateOrderAmount(const std::string& orderId, double newAmount) {
        auto it = orders.find(orderId);
        if (it == orders.end() || it->second.status != 0) return false;
        it->second.amount = newAmount;
        return true;
    }
};

// ---------- PaymentProcessor ----------
class PaymentProcessor {
    struct PaymentRecord { std::string paymentId; std::string orderId; double amount; int method; int status; };
    std::map<std::string, PaymentRecord> payments;
    int nextPaymentNum;
public:
    PaymentProcessor() : nextPaymentNum(20000) {}

    std::string initPayment(const std::string& orderId, double amount, int method) {
        char buf[32];
        snprintf(buf, sizeof(buf), "PAY-%d", nextPaymentNum++);
        PaymentRecord r;
        r.paymentId = buf;
        r.orderId = orderId;
        r.amount = amount;
        r.method = method;
        r.status = 0;
        payments[buf] = r;
        return std::string(buf);
    }

    bool verifyReceipt(const std::string& paymentId) {
        auto it = payments.find(paymentId);
        if (it == payments.end()) return false;
        it->second.status = 1;
        return true;
    }

    bool refund(const std::string& paymentId) {
        auto it = payments.find(paymentId);
        if (it == payments.end() || it->second.status != 1) return false;
        it->second.status = -1;
        return true;
    }

    int getPaymentStatus(const std::string& paymentId) {
        auto it = payments.find(paymentId);
        if (it == payments.end()) return -2;
        return it->second.status;
    }

    double getPaymentAmount(const std::string& paymentId) {
        auto it = payments.find(paymentId);
        if (it == payments.end()) return -1.0;
        return it->second.amount;
    }

    std::vector<std::string> getPaymentsByOrder(const std::string& orderId) {
        std::vector<std::string> result;
        for (auto& p : payments)
            if (p.second.orderId == orderId) result.push_back(p.first);
        return result;
    }

    int getTotalPayments() const { return (int)payments.size(); }

    bool cancelPayment(const std::string& paymentId) {
        auto it = payments.find(paymentId);
        if (it == payments.end() || it->second.status != 0) return false;
        it->second.status = -2;
        return true;
    }

    double getTotalRefunded() const {
        double sum = 0;
        for (auto& p : payments)
            if (p.second.status == -1) sum += p.second.amount;
        return sum;
    }
};

// ---------- NotificationSender ----------
class NotificationSender {
    struct Notification { std::string id; std::string target; std::string content; int type; bool sent; };
    std::vector<Notification> queue;
    int sentCount;
public:
    NotificationSender() : sentCount(0) {}

    bool sendPush(const std::string& userId, const std::string& title, const std::string& body) {
        Notification n;
        n.id = gen_random_string(16);
        n.target = userId;
        n.content = title + ":" + body;
        n.type = 0;
        n.sent = true;
        queue.push_back(n);
        sentCount++;
        return true;
    }

    bool sendEmail(const std::string& address, const std::string& subject, const std::string& body) {
        Notification n;
        n.id = gen_random_string(16);
        n.target = address;
        n.content = subject + ":" + body;
        n.type = 1;
        n.sent = true;
        queue.push_back(n);
        sentCount++;
        return true;
    }

    bool sendSms(const std::string& phone, const std::string& message) {
        Notification n;
        n.id = gen_random_string(16);
        n.target = phone;
        n.content = message;
        n.type = 2;
        n.sent = true;
        queue.push_back(n);
        sentCount++;
        return true;
    }

    int getPendingCount() const {
        int count = 0;
        for (auto& n : queue) if (!n.sent) count++;
        return count;
    }

    int getSentCount() const { return sentCount; }

    bool cancelNotification(const std::string& id) {
        for (auto& n : queue) {
            if (n.id == id && !n.sent) {
                n.sent = true;
                return true;
            }
        }
        return false;
    }

    std::vector<std::string> getNotificationsByType(int type) {
        std::vector<std::string> result;
        for (auto& n : queue)
            if (n.type == type) result.push_back(n.id);
        return result;
    }

    void clearSent() {
        queue.erase(
            std::remove_if(queue.begin(), queue.end(), [](const Notification& n) { return n.sent; }),
            queue.end()
        );
    }

    std::string getNotificationContent(const std::string& id) {
        for (auto& n : queue)
            if (n.id == id) return n.content;
        return "";
    }
};

// ---------- CacheManager ----------
class CacheManager {
    std::map<std::string, std::pair<std::string, time_t>> cache;
    int maxSize;
    int hits;
    int misses;
public:
    CacheManager() : maxSize(10000), hits(0), misses(0) {}

    void put(const std::string& key, const std::string& value, int ttlSeconds = 300) {
        if ((int)cache.size() >= maxSize) evict();
        cache[key] = {value, time(nullptr) + ttlSeconds};
    }

    std::string get(const std::string& key) {
        auto it = cache.find(key);
        if (it == cache.end()) { misses++; return ""; }
        if (it->second.second < time(nullptr)) {
            cache.erase(it);
            misses++;
            return "";
        }
        hits++;
        return it->second.first;
    }

    bool contains(const std::string& key) {
        auto it = cache.find(key);
        if (it == cache.end()) return false;
        if (it->second.second < time(nullptr)) { cache.erase(it); return false; }
        return true;
    }

    void evict() {
        time_t now = time(nullptr);
        for (auto it = cache.begin(); it != cache.end(); ) {
            if (it->second.second < now) it = cache.erase(it);
            else ++it;
        }
        if ((int)cache.size() >= maxSize) {
            auto it = cache.begin();
            std::advance(it, cache.size() / 4);
            cache.erase(cache.begin(), it);
        }
    }

    void remove(const std::string& key) { cache.erase(key); }

    int size() const { return (int)cache.size(); }

    void clear() { cache.clear(); hits = 0; misses = 0; }

    double getHitRate() const { return (hits + misses) == 0 ? 0.0 : (double)hits / (hits + misses); }

    std::vector<std::string> getKeys() {
        std::vector<std::string> result;
        for (auto& p : cache) result.push_back(p.first);
        return result;
    }

    std::string stats() {
        char buf[128];
        snprintf(buf, sizeof(buf), "size=%d,hits=%d,misses=%d,rate=%.2f",
                 (int)cache.size(), hits, misses, getHitRate());
        return std::string(buf);
    }
};

// ---------- ConfigLoader ----------
class ConfigLoader {
    std::map<std::string, std::string> configs;
    std::string configPath;
    bool loaded;
public:
    ConfigLoader() : loaded(false) {}

    bool loadJson(const std::string& path) {
        configPath = path;
        configs["app.name"] = "FatdogReverse";
        configs["app.version"] = "2.1.0";
        configs["server.host"] = "10.0.2.2";
        configs["server.port"] = "8000";
        loaded = true;
        return true;
    }

    bool loadYaml(const std::string& path) {
        configPath = path;
        return loadJson(path);
    }

    void reload() {
        if (!configPath.empty()) loadJson(configPath);
    }

    std::string getString(const std::string& key, const std::string& defaultVal = "") {
        auto it = configs.find(key);
        return it != configs.end() ? it->second : defaultVal;
    }

    int getInt(const std::string& key, int defaultVal = 0) {
        std::string val = getString(key);
        if (val.empty()) return defaultVal;
        return std::stoi(val);
    }

    bool getBool(const std::string& key, bool defaultVal = false) {
        std::string val = getString(key);
        if (val.empty()) return defaultVal;
        return val == "true" || val == "1";
    }

    void set(const std::string& key, const std::string& value) { configs[key] = value; }

    bool isLoaded() const { return loaded; }

    std::vector<std::string> getAllKeys() {
        std::vector<std::string> result;
        for (auto& p : configs) result.push_back(p.first);
        return result;
    }

    void remove(const std::string& key) { configs.erase(key); }

    bool hasKey(const std::string& key) { return configs.find(key) != configs.end(); }

    void clear() { configs.clear(); loaded = false; }
};

// ---------- LogCollector ----------
class LogCollector {
    struct LogEntry { std::string timestamp; int level; std::string tag; std::string message; };
    std::vector<LogEntry> logs;
    int maxLogs;
    bool enabled;
public:
    LogCollector() : maxLogs(10000), enabled(true) {}

    void collect(int level, const std::string& tag, const std::string& message) {
        if (!enabled) return;
        if ((int)logs.size() >= maxLogs) flush();
        LogEntry e;
        char buf[64];
        time_t now = time(nullptr);
        struct tm* t = localtime(&now);
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", t);
        e.timestamp = buf;
        e.level = level;
        e.tag = tag;
        e.message = message;
        logs.push_back(e);
    }

    void flush() {
        logs.clear();
    }

    void rotate() {
        if ((int)logs.size() > maxLogs / 2) {
            logs.erase(logs.begin(), logs.begin() + logs.size() / 2);
        }
    }

    int getLogCount() const { return (int)logs.size(); }

    std::vector<std::string> getLogsByTag(const std::string& tag) {
        std::vector<std::string> result;
        for (auto& e : logs)
            if (e.tag == tag) result.push_back(e.message);
        return result;
    }

    std::vector<std::string> getLogsByLevel(int level) {
        std::vector<std::string> result;
        for (auto& e : logs)
            if (e.level == level) result.push_back(e.message);
        return result;
    }

    void setEnabled(bool en) { enabled = en; }

    bool isEnabled() const { return enabled; }

    std::string getLastLog() {
        if (logs.empty()) return "";
        auto& e = logs.back();
        return e.timestamp + " [" + std::to_string(e.level) + "] " + e.tag + ": " + e.message;
    }

    void setMaxLogs(int max) { maxLogs = max; }
};

// ---------- RateLimiter ----------
class RateLimiter {
    std::map<std::string, std::vector<time_t>> requestHistory;
    int maxRequests;
    int windowSeconds;
    int cooldownSeconds;
public:
    RateLimiter() : maxRequests(60), windowSeconds(60), cooldownSeconds(30) {}

    bool allow(const std::string& clientId) {
        time_t now = time(nullptr);
        auto& history = requestHistory[clientId];
        history.erase(
            std::remove_if(history.begin(), history.end(), [now, this](time_t t) {
                return now - t > windowSeconds;
            }),
            history.end()
        );
        if ((int)history.size() >= maxRequests) return false;
        history.push_back(now);
        return true;
    }

    bool reject(const std::string& clientId) {
        return !allow(clientId);
    }

    void cooldown(const std::string& clientId) {
        requestHistory.erase(clientId);
    }

    int getRequestCount(const std::string& clientId) {
        time_t now = time(nullptr);
        auto& history = requestHistory[clientId];
        history.erase(
            std::remove_if(history.begin(), history.end(), [now, this](time_t t) {
                return now - t > windowSeconds;
            }),
            history.end()
        );
        return (int)history.size();
    }

    void setMaxRequests(int max) { maxRequests = max; }

    void setWindowSeconds(int sec) { windowSeconds = sec; }

    bool isInCooldown(const std::string& clientId) {
        auto it = requestHistory.find(clientId);
        if (it == requestHistory.end()) return false;
        if (it->second.empty()) return false;
        return (time(nullptr) - it->second.back()) < cooldownSeconds;
    }

    void reset() { requestHistory.clear(); }

    std::map<std::string, int> getAllRequestCounts() {
        std::map<std::string, int> result;
        for (auto& p : requestHistory)
            result[p.first] = (int)p.second.size();
        return result;
    }

    int getTotalTrackedClients() const { return (int)requestHistory.size(); }
};

/* ============================================================
 * 跨层回调：AES 密钥尾段由 Java 侧供给
 *   Bk50 反射造实例 → bindHolder(实例) → 本 so 存全局引用
 *   加密时按方法名回调 slice(int mask)，mask 是 so 侧常量
 * ============================================================ */
static JavaVM *g_vm = NULL;
static jobject g_obj = NULL;
static jmethodID g_cb = NULL;

/* so 侧常量掩码：Java 侧少一个比特，解出来的就是乱码 */
static const jint K50_MASK = 0x4B1D27C3;

static JNIEnv *cur_env() {
    if (g_vm == NULL) return NULL;
    JNIEnv *env = NULL;
    if (g_vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK) return NULL;
    return env;
}

static std::string fetch_tail(JNIEnv *env) {
    if (env == NULL) env = cur_env();
    if (env == NULL || g_obj == NULL || g_cb == NULL) return std::string();
    jstring js = (jstring) env->CallObjectMethod(g_obj, g_cb, K50_MASK);
    if (js == NULL) return std::string();
    const char *cs = env->GetStringUTFChars(js, NULL);
    std::string out;
    if (cs != NULL) { out.assign(cs); env->ReleaseStringUTFChars(js, cs); }
    env->DeleteLocalRef(js);
    if (out == "ERR_JAVA") out.clear();
    return out;
}

/* 拼齐 16 字节 AES key：so 头段 + Java 尾段 */
static std::string aes_key(JNIEnv *env) {
    std::string head = DK(K50_AES_HEAD, 0x2A);   // "Fatdog_abys_"
    std::string tail = fetch_tail(env);          // Sift.slice(K50_MASK) -> "2026"
    if (tail.empty()) return std::string();
    return head + tail;
}

/* 诱饵标记（明文可见，strings 可抓） */
static const char FAKE_MARK[] = "Fatdog_red";

/* ============================================================
 * JNI 实现（静态命名一律取消；由 JNI_OnLoad 动态注册）
 * 以下函数名只是 C 侧的普通标识符，不会出现在 .dynsym 里。
 * ============================================================ */
static jstring implEnc(JNIEnv* env, jobject, jint page, jlong ts) {
    std::string key = aes_key(env);
    if (key.size() != 16) return env->NewStringUTF("");
    std::string payload = "page=" + std::to_string(page) + "&ts=" + std::to_string(ts);
    std::string enc = g_relay.run(0, key, payload);   // vtable 槽 0 → 加密
    return env->NewStringUTF(enc.c_str());
}

static jstring implSign(JNIEnv* env, jobject, jstring encHex) {
    const char* hex = env->GetStringUTFChars(encHex, nullptr);
    std::string encStr = (hex != nullptr) ? std::string(hex) : std::string();
    if (hex != nullptr) env->ReleaseStringUTFChars(encHex, hex);
    std::string sign = g_relay.run(1, std::string(), encStr);   // vtable 槽 1 → 摘要
    return env->NewStringUTF(sign.c_str());
}

static jstring implHint(JNIEnv* env, jobject) {
    return env->NewStringUTF(DK(A_HINT, 0x5A).c_str());
}

static void implBind(JNIEnv* env, jclass, jobject holder) {
    if (g_obj != NULL) { env->DeleteGlobalRef(g_obj); g_obj = NULL; }
    g_cb = NULL;
    if (holder == NULL) return;
    g_obj = env->NewGlobalRef(holder);
    if (g_obj == NULL) return;
    jclass local = env->GetObjectClass(holder);
    if (local == NULL) return;
    std::string cb = DK(A_CB, 0x5A);
    std::string gb = DK(A_GB, 0x5A);
    g_cb = env->GetMethodID(local, cb.c_str(), gb.c_str());
    env->DeleteLocalRef(local);
}

/* ============================================================
 * JNI_OnLoad — 运行时构造 JNINativeMethod 表并 RegisterNatives。
 * 类名/方法名/签名全部来自密文表 → nm -D 只剩 JNI_OnLoad。
 * ============================================================ */

/* 诱饵导出：Java 侧根本没声明这个方法 —— 纯误导。
 * 让 strings/nm 能抓到 "Fatdog_red"，并给符号表添一扇假门。 */
extern "C" JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Bk50_nativeRed(JNIEnv* env, jclass) {
    return env->NewStringUTF(FAKE_MARK);
}

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    g_vm = vm;
    JNIEnv* env = cur_env();
    if (env != NULL) {
        std::string cls = DK(A_CLS, 0x5A);
        jclass c = env->FindClass(cls.c_str());
        if (c != NULL) {
            std::string n1 = DK(A_M1, 0x5A), g1 = DK(A_G1, 0x5A);
            std::string n2 = DK(A_M2, 0x5A), g2 = DK(A_G2, 0x5A);
            std::string n3 = DK(A_M3, 0x5A), g3 = DK(A_G3, 0x5A);
            std::string n4 = DK(A_M4, 0x5A), g4 = DK(A_G4, 0x5A);
            JNINativeMethod m[4];
            m[0].name = const_cast<char*>(n1.c_str()); m[0].signature = const_cast<char*>(g1.c_str()); m[0].fnPtr = (void*)implEnc;
            m[1].name = const_cast<char*>(n2.c_str()); m[1].signature = const_cast<char*>(g2.c_str()); m[1].fnPtr = (void*)implSign;
            m[2].name = const_cast<char*>(n3.c_str()); m[2].signature = const_cast<char*>(g3.c_str()); m[2].fnPtr = (void*)implHint;
            m[3].name = const_cast<char*>(n4.c_str()); m[3].signature = const_cast<char*>(g4.c_str()); m[3].fnPtr = (void*)implBind;
            if (env->RegisterNatives(c, m, 4) != JNI_OK && env->ExceptionCheck())
                env->ExceptionClear();
        } else if (env->ExceptionCheck()) {
            env->ExceptionClear();
        }
    }
    return JNI_VERSION_1_6;
}

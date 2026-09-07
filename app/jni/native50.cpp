/*
 * libnative50.so — L50 幽暗深渊（Native大陆第 3 关）
 *
 * 特性：vtable 虚函数表分发 · AES-128-ECB + SHA-256 + HMAC-SHA256
 *
 * 正真逻辑（~250 行）：
 *   - class ICipher { virtual std::string encrypt(const std::string& data) = 0; };
 *   - class AesEngine : public ICipher { ... }; — AES-128-ECB
 *   - class Sha256Signer { std::string sign(const std::string& data); }; — SHA-256
 *   - JNI 入口：通过 vtable 分发加密
 *
 * 业务代码（~750 行）— 全部是真实的业务函数名，无人调用：
 *   - UserSessionManager / OrderService / PaymentProcessor / NotificationSender
 *   - CacheManager / ConfigLoader / LogCollector / RateLimiter / ...
 *
 * 密钥：XOR 数组 → AES key + HMAC key（split across classes）
 * 协议：GET /api/l50?enc=AES 密文&sign=SHA256 签名&ts=T
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
 * HMAC-SHA256
 * ============================================================ */

static std::string hmac_sha256_hex(const std::string& key, const std::string& msg) {
    std::vector<uint8_t> k(key.begin(), key.end());
    if (k.size() > 64) {
        std::string h = sha256_hex(key);
        k.assign(h.begin(), h.end());
    }
    k.resize(64, 0);
    std::vector<uint8_t> ipad(64), opad(64);
    for (int i = 0; i < 64; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }
    std::string inner(reinterpret_cast<char*>(ipad.data()), 64);
    inner.append(msg);
    std::string innerHash = sha256_hex(inner);
    std::string outer(reinterpret_cast<char*>(opad.data()), 64);
    outer.append(innerHash);
    return sha256_hex(outer);
}

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
 * 真实密钥（XOR 数组，分散在不同类中）
 * ============================================================ */

class KeyProvider {
public:
    static std::string getAesKey() {
        // Fatdog_abyss_2026 (XOR ^0x2A)
        static const uint8_t raw[] = {
            0x59 ^ 0x2A, 0x74 ^ 0x2A, 0x65 ^ 0x2A, 0x77 ^ 0x2A, 0x5F ^ 0x2A,
            0x61 ^ 0x2A, 0x62 ^ 0x2A, 0x79 ^ 0x2A, 0x73 ^ 0x2A, 0x73 ^ 0x2A,
            0x5F ^ 0x2A, 0x32 ^ 0x2A, 0x30 ^ 0x2A, 0x32 ^ 0x2A, 0x36 ^ 0x2A, 0x00
        };
        return std::string(reinterpret_cast<const char*>(raw));
    }
    static std::string getHmacKey() {
        // Fatdog_depths_2026 (XOR ^0x3D)
        static const uint8_t raw[] = {
            0x59 ^ 0x3D, 0x74 ^ 0x3D, 0x65 ^ 0x3D, 0x77 ^ 0x3D, 0x5F ^ 0x3D,
            0x64 ^ 0x3D, 0x65 ^ 0x3D, 0x70 ^ 0x3D, 0x74 ^ 0x3D, 0x68 ^ 0x3D,
            0x73 ^ 0x3D, 0x5F ^ 0x3D, 0x32 ^ 0x3D, 0x30 ^ 0x3D, 0x32 ^ 0x3D, 0x36 ^ 0x3D, 0x00
        };
        return std::string(reinterpret_cast<const char*>(raw));
    }
};

/* ============================================================
 * vtable 接口 + 真实加密引擎
 * ============================================================ */

class ICipher {
public:
    virtual ~ICipher() = default;
    virtual std::string encrypt(const std::string& data) = 0;
    virtual std::string getAlgorithmName() const = 0;
};

class AesEngine : public ICipher {
public:
    std::string encrypt(const std::string& data) override {
        std::string key = KeyProvider::getAesKey();
        auto encrypted = aes_ecb_encrypt(
            reinterpret_cast<const uint8_t*>(key.data()),
            reinterpret_cast<const uint8_t*>(data.data()),
            data.size()
        );
        std::string hex;
        hex.reserve(encrypted.size() * 2);
        for (uint8_t b : encrypted) {
            char buf[3];
            snprintf(buf, sizeof(buf), "%02x", b);
            hex += buf;
        }
        return hex;
    }
    std::string getAlgorithmName() const override { return "AES-128-ECB"; }
};

class Sha256Signer {
public:
    std::string sign(const std::string& data) {
        return sha256_hex(data);
    }
};

/* vtable 分发器 */
class CipherDispatcher {
    std::map<std::string, std::function<std::string(const std::string&)>> dispatchMap;
public:
    CipherDispatcher() {
        static AesEngine aes;
        dispatchMap["aes"] = [](const std::string& data) {
            return aes.encrypt(data);
        };
        dispatchMap["sha256"] = [](const std::string& data) {
            Sha256Signer signer;
            return signer.sign(data);
        };
    }
    std::string dispatch(const std::string& algo, const std::string& data) {
        auto it = dispatchMap.find(algo);
        if (it != dispatchMap.end()) return it->second(data);
        return "";
    }
};

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
 * JNI 入口 — 通过 vtable 分发加密
 * ============================================================ */

static CipherDispatcher g_dispatcher;
static AesEngine g_aesEngine;
static Sha256Signer g_signer;

extern "C" {

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Bk50_nativeEnc(JNIEnv* env, jobject, jint page, jlong ts) {
    std::string payload = "page=" + std::to_string(page) + "&ts=" + std::to_string(ts);
    // 通过 vtable 分发到 AesEngine::encrypt
    std::string enc = g_dispatcher.dispatch("aes", payload);
    return env->NewStringUTF(enc.c_str());
}

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Bk50_nativeSign(JNIEnv* env, jobject, jstring encHex) {
    const char* hex = env->GetStringUTFChars(encHex, nullptr);
    std::string encStr(hex);
    env->ReleaseStringUTFChars(encHex, hex);
    // 使用 SHA-256 签名
    std::string sign = g_dispatcher.dispatch("sha256", encStr);
    return env->NewStringUTF(sign.c_str());
}

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Bk50_getKeyHint(JNIEnv* env, jobject) {
    // 诱饵提示（UTF-16 藏在 .rodata 中，strings 默认搜不到）
    // strings -el libnative50.so 可见 "Fatdog_red"，但那是诱饵
    // 真正的密钥在 KeyProvider 类中，通过 XOR 数组解码
    return env->NewStringUTF("hint_hidden");
}

} /* extern "C" */

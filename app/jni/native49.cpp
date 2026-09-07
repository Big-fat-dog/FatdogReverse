/**
 * native49.cpp — Native大陆 L49 迷雾森林（std::map 分发 · RAII）
 *
 * 考点：C++ std::map 分发 + RAII 内存管理 + SM4-ECB + HMAC-SHA256
 * CryptoBox 类用 std::map<int, function> 做算法分发
 * ManagedBuffer 类用 RAII 自动管理内存
 *
 * Frida 训练：Memory.scanSync 搜索 std::map 内部红黑树节点
 *           hook std::map::operator[] 观察分发逻辑
 *
 * 标记：真 Fatdog_mist / 诱饵 Fatdog_misty（UTF-16 藏 .rodata）
 */

#include <jni.h>
#include <string>
#include <cstring>
#include <cstdio>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>

/* ============================================================
 * SM4-ECB 常量
 * ============================================================ */
static const uint8_t SM4_SBOX[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2,
    0x28, 0xfb, 0x2c, 0x05, 0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3,
    0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99, 0x9c, 0x42, 0x50, 0xf4,
    0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa,
    0x75, 0x8f, 0x3f, 0xa6, 0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba,
    0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8, 0x68, 0x6b, 0x81, 0xb2,
    0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b,
    0x01, 0x21, 0x78, 0x87, 0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52,
    0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e, 0xea, 0xbf, 0x8a, 0xd2,
    0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30,
    0xf5, 0x8c, 0xb1, 0xe3, 0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60,
    0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f, 0xd5, 0xdb, 0x37, 0x45,
    0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41,
    0x1f, 0x10, 0x5a, 0xd8, 0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd,
    0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0, 0x89, 0x69, 0x97, 0x4a,
    0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e,
    0xd7, 0xcb, 0x39, 0x48
};

static const uint32_t SM4_FK[4] = {
    0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
};

static const uint32_t SM4_CK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};

static uint32_t sm4_rotl(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

static uint32_t sm4_tau(uint32_t x) {
    return ((uint32_t)SM4_SBOX[(x >> 24) & 0xFF] << 24) |
           ((uint32_t)SM4_SBOX[(x >> 16) & 0xFF] << 16) |
           ((uint32_t)SM4_SBOX[(x >> 8) & 0xFF] << 8) |
           ((uint32_t)SM4_SBOX[x & 0xFF]);
}

static uint32_t sm4_l(uint32_t x) {
    return x ^ sm4_rotl(x, 2) ^ sm4_rotl(x, 10) ^ sm4_rotl(x, 18) ^ sm4_rotl(x, 24);
}

static uint32_t sm4_l_prime(uint32_t x) {
    return x ^ sm4_rotl(x, 13) ^ sm4_rotl(x, 23);
}

static void sm4_key_expand(const uint8_t key[16], uint32_t rk[32]) {
    uint32_t k[36];
    for (int i = 0; i < 4; i++) {
        k[i] = ((uint32_t)key[i * 4] << 24) | ((uint32_t)key[i * 4 + 1] << 16) |
               ((uint32_t)key[i * 4 + 2] << 8) | (uint32_t)key[i * 4 + 3];
        k[i] ^= SM4_FK[i];
    }
    for (int i = 0; i < 32; i++) {
        k[i + 4] = k[i] ^ sm4_l_prime(sm4_tau(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ SM4_CK[i]));
        rk[i] = k[i + 4];
    }
}

static void sm4_encrypt_block(const uint8_t in[16], uint8_t out[16], const uint32_t rk[32]) {
    uint32_t x[36];
    for (int i = 0; i < 4; i++) {
        x[i] = ((uint32_t)in[i * 4] << 24) | ((uint32_t)in[i * 4 + 1] << 16) |
               ((uint32_t)in[i * 4 + 2] << 8) | (uint32_t)in[i * 4 + 3];
    }
    for (int i = 0; i < 32; i++) {
        x[i + 4] = x[i] ^ sm4_l(sm4_tau(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ rk[i]));
    }
    for (int i = 0; i < 4; i++) {
        uint32_t val = x[35 - i];
        out[i * 4]     = (uint8_t)(val >> 24);
        out[i * 4 + 1] = (uint8_t)(val >> 16);
        out[i * 4 + 2] = (uint8_t)(val >> 8);
        out[i * 4 + 3] = (uint8_t)(val);
    }
}

static std::string sm4_ecb_encrypt(const uint8_t key[16], const std::string& data) {
    uint32_t rk[32];
    sm4_key_expand(key, rk);

    size_t len = data.size();
    size_t padlen = 16 - (len % 16);
    size_t total = len + padlen;
    uint8_t* padded = new uint8_t[total];
    memcpy(padded, data.data(), len);
    for (size_t i = 0; i < padlen; i++) {
        padded[len + i] = (uint8_t)padlen;
    }

    std::string result;
    result.resize(total);
    for (size_t i = 0; i < total; i += 16) {
        sm4_encrypt_block(padded + i, (uint8_t*)result.data() + i, rk);
    }

    delete[] padded;
    return result;
}

/* ============================================================
 * SHA-256 / HMAC-SHA256
 * ============================================================ */
typedef struct {
    unsigned int h[8];
    unsigned char buf[64];
    unsigned long long total;
} sha256_ctx;

static const unsigned int K256[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static unsigned int sha256_rotr(unsigned int x, int n) {
    return (x >> n) | (x << (32 - n));
}

static void sha256_block(sha256_ctx *c, const unsigned char *p) {
    unsigned int w[64];
    int i;
    for (i = 0; i < 16; i++) {
        w[i] = ((unsigned int) p[i * 4] << 24) | ((unsigned int) p[i * 4 + 1] << 16)
             | ((unsigned int) p[i * 4 + 2] << 8) | (unsigned int) p[i * 4 + 3];
    }
    for (i = 16; i < 64; i++) {
        unsigned int s0 = sha256_rotr(w[i - 15], 7) ^ sha256_rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        unsigned int s1 = sha256_rotr(w[i - 2], 17) ^ sha256_rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    {
        unsigned int a = c->h[0], b = c->h[1], cc = c->h[2], d = c->h[3];
        unsigned int e = c->h[4], f = c->h[5], g = c->h[6], h = c->h[7];
        for (i = 0; i < 64; i++) {
            unsigned int S1 = sha256_rotr(e, 6) ^ sha256_rotr(e, 11) ^ sha256_rotr(e, 25);
            unsigned int ch = (e & f) ^ ((~e) & g);
            unsigned int t1 = h + S1 + ch + K256[i] + w[i];
            unsigned int S0 = sha256_rotr(a, 2) ^ sha256_rotr(a, 13) ^ sha256_rotr(a, 22);
            unsigned int maj = (a & b) ^ (a & cc) ^ (b & cc);
            unsigned int t2 = S0 + maj;
            h = g; g = f; f = e; e = d + t1;
            d = cc; cc = b; b = a; a = t1 + t2;
        }
        c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d;
        c->h[4] += e; c->h[5] += f; c->h[6] += g; c->h[7] += h;
    }
}

static void sha256_init(sha256_ctx *c) {
    c->h[0] = 0x6a09e667u; c->h[1] = 0xbb67ae85u;
    c->h[2] = 0x3c6ef372u; c->h[3] = 0xa54ff53au;
    c->h[4] = 0x510e527fu; c->h[5] = 0x9b05688cu;
    c->h[6] = 0x1f83d9abu; c->h[7] = 0x5be0cd19u;
    c->total = 0;
}

static void sha256_update(sha256_ctx *c, const unsigned char *data, size_t len) {
    size_t used, rem, i;
    c->total += len;
    used = (size_t) ((c->total - len) & 63);
    rem = 64 - used;
    if (len >= rem) {
        memcpy(c->buf + used, data, rem);
        sha256_block(c, c->buf);
        for (i = rem; i + 64 <= len; i += 64) {
            sha256_block(c, data + i);
        }
        data += i;
        len -= i;
        used = 0;
    }
    memcpy(c->buf + used, data, len);
}

static void sha256_final(sha256_ctx *c, unsigned char out[32]) {
    unsigned long long bits = c->total * 8;
    unsigned char pad[128];
    size_t used = (size_t) (c->total & 63);
    size_t padlen = (used < 56) ? (56 - used) : (120 - used);
    int i;
    memset(pad, 0, sizeof(pad));
    pad[0] = 0x80;
    for (i = 0; i < 8; i++) {
        pad[padlen + i] = (unsigned char) (bits >> (56 - 8 * i));
    }
    sha256_update(c, pad, padlen + 8);
    for (i = 0; i < 8; i++) {
        out[i * 4]     = (unsigned char) (c->h[i] >> 24);
        out[i * 4 + 1] = (unsigned char) (c->h[i] >> 16);
        out[i * 4 + 2] = (unsigned char) (c->h[i] >> 8);
        out[i * 4 + 3] = (unsigned char) (c->h[i]);
    }
}

static void hmac_sha256(const unsigned char *key, size_t klen,
                        const unsigned char *msg, size_t mlen,
                        unsigned char out[32]) {
    unsigned char k[64];
    unsigned char ipad[64], opad[64], inner[32];
    sha256_ctx c;
    int i;
    memset(k, 0, sizeof(k));
    if (klen > 64) {
        sha256_init(&c);
        sha256_update(&c, key, klen);
        sha256_final(&c, k);
    } else {
        memcpy(k, key, klen);
    }
    for (i = 0; i < 64; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }
    sha256_init(&c);
    sha256_update(&c, ipad, 64);
    sha256_update(&c, msg, mlen);
    sha256_final(&c, inner);
    sha256_init(&c);
    sha256_update(&c, opad, 64);
    sha256_update(&c, inner, 32);
    sha256_final(&c, out);
}

/* ============================================================
 * XOR 数组：三段密钥，运行时解码
 * ============================================================ */
static const uint8_t K49_SM4[] = {
    0x12, 0x00, 0x15, 0x12, 0x36, 0x11, 0x16, 0x5E,
    0x55, 0x45, 0x58, 0x06, 0x16, 0x5E, 0x11, 0x44
};  // ^0x3C → "Fatdog_mist_2026"

static const uint8_t K49_HMAC[] = {
    0x12, 0x54, 0x03, 0x12, 0x34, 0x04, 0x14, 0x16,
    0x55, 0x45, 0x58, 0x06, 0x16, 0x5E, 0x11, 0x44,
    0x4D, 0x45, 0x12, 0x15
};  // ^0x5A → "Fatdog_forest_2026"

/* ============================================================
 * RAII 封装：ManagedBuffer 自动管理内存
 * Frida 训练点：观察构造/析构调用时机
 * ============================================================ */
class ManagedBuffer {
private:
    uint8_t* data_;
    size_t size_;

public:
    ManagedBuffer(size_t size) : size_(size) {
        data_ = new uint8_t[size];
        memset(data_, 0, size);
    }

    ~ManagedBuffer() {
        delete[] data_;
    }

    // 禁止拷贝（RAII 语义）
    ManagedBuffer(const ManagedBuffer&) = delete;
    ManagedBuffer& operator=(const ManagedBuffer&) = delete;

    // 允许移动
    ManagedBuffer(ManagedBuffer&& other) noexcept : data_(other.data_), size_(other.size_) {
        other.data_ = nullptr;
        other.size_ = 0;
    }

    uint8_t* get() { return data_; }
    const uint8_t* get() const { return data_; }
    size_t size() const { return size_; }
};

/* ============================================================
 * CryptoBox 类：std::map 分发 + SM4-ECB + HMAC-SHA256
 *
 * Frida 训练点：
 *   1. std::map 内部红黑树节点结构（_Rb_tree_node）
 *   2. hook std::map::operator[] 观察分发
 *   3. 函数指针表分发（dispatch_[algo_id]）
 * ============================================================ */
class CryptoBox {
private:
    // std::map 分发表：algo_id → 处理函数
    std::map<int, std::function<std::string(const std::string&)>> dispatch_;

    // SM4 密钥（XOR 数组解码）
    uint8_t sm4_key_[16];

    // HMAC 密钥（XOR 数组解码）
    uint8_t hmac_key_[32];

    // SM4 加密函数（内部）
    std::string sm4_encrypt_internal(const std::string& data) {
        return sm4_ecb_encrypt(sm4_key_, data);
    }

    // HMAC 签名函数（内部）
    std::string hmac_sign_internal(const std::string& data) {
        unsigned char digest[32];
        hmac_sha256(hmac_key_, 32,
                    reinterpret_cast<const unsigned char*>(data.data()), data.size(),
                    digest);

        static const char hexc[] = "0123456789abcdef";
        char hex[65];
        for (unsigned int i = 0; i < 32; i++) {
            hex[i * 2]     = hexc[digest[i] >> 4];
            hex[i * 2 + 1] = hexc[digest[i] & 0x0f];
        }
        hex[64] = '\0';
        return std::string(hex);
    }

public:
    CryptoBox() {
        // 解码 SM4 密钥（XOR ^0x3C）
        for (size_t i = 0; i < sizeof(K49_SM4); i++) {
            sm4_key_[i] = K49_SM4[i] ^ 0x3C;
        }

        // 解码 HMAC 密钥（XOR ^0x5A）
        for (size_t i = 0; i < sizeof(K49_HMAC); i++) {
            hmac_key_[i] = K49_HMAC[i] ^ 0x5A;
        }

        // 初始化 std::map 分发表
        // algo_id=0 → SM4 加密
        // algo_id=1 → HMAC 签名
        dispatch_[0] = [this](const std::string& data) -> std::string {
            return this->sm4_encrypt_internal(data);
        };
        dispatch_[1] = [this](const std::string& data) -> std::string {
            return this->hmac_sign_internal(data);
        };
    }

    // 按 algo_id 分发处理
    // Frida 训练点：hook std::map::operator[] 观察 dispatch_[algo_id] 调用
    std::string process(int algo_id, const std::string& data) {
        auto it = dispatch_.find(algo_id);
        if (it != dispatch_.end()) {
            return it->second(data);
        }
        return "";
    }

    // 获取 SM4 密钥（只读）
    const uint8_t* getSm4Key() const { return sm4_key_; }

    // 获取 HMAC 密钥（只读）
    const uint8_t* getHmacKey() const { return hmac_key_; }
};

/* ============================================================
 * 诱饵标记（明文可见，strings 可抓）
 * ============================================================ */
static const char FAKE_MARK[] = "Fatdog_misty";

/* ============================================================
 * 生成请求签名和加密数据
 * ============================================================ */
static std::string build_enc(int page, long ts) {
    CryptoBox box;
    char payload[128];
    snprintf(payload, sizeof(payload), "page=%d&ts=%ld", page, ts);
    return box.process(0, std::string(payload));  // algo_id=0 → SM4 加密
}

static std::string build_sign(const std::string& enc) {
    CryptoBox box;
    return box.process(1, enc);  // algo_id=1 → HMAC 签名
}

/* ============================================================
 * JNI 导出函数
 * ============================================================ */
extern "C" {

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Bk49_nativeEnc(JNIEnv *env, jclass clazz, jint page, jlong ts) {
    std::string enc = build_enc(page, static_cast<long>(ts));
    // 返回 hex 编码
    static const char hexc[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(enc.size() * 2);
    for (unsigned char c : enc) {
        hex += hexc[c >> 4];
        hex += hexc[c & 0x0f];
    }
    return env->NewStringUTF(hex.c_str());
}

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Bk49_nativeSign(JNIEnv *env, jclass clazz, jstring enc_hex) {
    const char* hex_str = env->GetStringUTFChars(enc_hex, nullptr);
    // hex 解码
    size_t len = strlen(hex_str) / 2;
    std::string enc;
    enc.resize(len);
    for (size_t i = 0; i < len; i++) {
        unsigned int byte;
        sscanf(hex_str + i * 2, "%02x", &byte);
        enc[i] = (char)byte;
    }
    env->ReleaseStringUTFChars(enc_hex, hex_str);

    std::string sig = build_sign(enc);
    return env->NewStringUTF(sig.c_str());
}

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Bk49_getKeyHint(JNIEnv *env, jclass clazz) {
    return env->NewStringUTF("sm4_key_derived_from_xor_array");
}

}  /* extern "C" */

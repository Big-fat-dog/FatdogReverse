/**
 * native48.cpp — Native大陆 L48 落日平原（operator+ 重载）
 *
 * 考点：C++ name mangling + std::string + operator+ 运算符重载
 * HMAC 密钥由两段 XOR 数组经 operator+ 拼接而成
 *
 * Frida 训练：Hook C++ mangled 函数名（_ZN7SignKey...），用 DebugSymbol 反解 demangle 名
 *
 * 标记：真 Fatdog_sun / 诱饵 Fatdog_sunrise（UTF-16 藏 .rodata）
 */

#include <jni.h>
#include <string>
#include <cstring>
#include <cstdio>
#include <cstdint>

/* ============================================================
 * SHA-256 / HMAC-SHA256（紧凑实现，复用项目内各关同一套）
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

static unsigned int rotr(unsigned int x, int n) {
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
        unsigned int s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        unsigned int s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    {
        unsigned int a = c->h[0], b = c->h[1], cc = c->h[2], d = c->h[3];
        unsigned int e = c->h[4], f = c->h[5], g = c->h[6], h = c->h[7];
        for (i = 0; i < 64; i++) {
            unsigned int S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            unsigned int ch = (e & f) ^ ((~e) & g);
            unsigned int t1 = h + S1 + ch + K256[i] + w[i];
            unsigned int S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
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
 * XOR 数组：两段密钥，运行时解码后通过 operator+ 拼接
 * ============================================================ */
static const uint8_t K48_A[] = {
    0x7A, 0x5D, 0x48, 0x58, 0x53, 0x5B, 0x63, 0x5F,
    0x5D, 0x50, 0x51, 0x63
};  // ^0x3C → "Fatdog_calm_"

static const uint8_t K48_B[] = {
    0x68, 0x6A, 0x68, 0x6C
};  // ^0x5A → "2026"

#define K48_A_LEN (sizeof(K48_A))
#define K48_B_LEN (sizeof(K48_B))

/* ============================================================
 * SignKey 类：C++ 运算符重载 + HMAC-SHA256
 * ============================================================ */
class SignKey {
private:
    std::string key_;

public:
    /* 默认构造：从 XOR 数组解码左半段 */
    SignKey() {
        key_.resize(K48_A_LEN);
        for (size_t i = 0; i < K48_A_LEN; i++) {
            key_[i] = static_cast<char>(K48_A[i] ^ 0x3C);
        }
    }

    /* 带参构造：直接指定 key */
    explicit SignKey(const std::string& k) : key_(k) {}

    /* 运算符重载：拼接两段密钥
     * Frida 训练点：mangled 名 _ZN7SignKeyplERKS_
     * 玩家需要在 IDA 中定位此函数，理解 operator+ 的语义 */
    SignKey operator+(const SignKey& other) const {
        return SignKey(key_ + other.key_);
    }

    /* 获取密钥引用（只读） */
    const std::string& getKey() const { return key_; }

    /* HMAC-SHA256 签名
     * Frida 训练点：mangled 名 _ZN7SignKey4signERKNSt6__ndk112basic_stringIcNS0_11char_traitsIcEENS0_9allocatorIcEEEE
     * 用 DebugSymbol.fromAddress 可 demangle 为 SignKey::sign(std::string const&) */
    std::string sign(const std::string& msg) const {
        unsigned char digest[32];
        hmac_sha256(
            reinterpret_cast<const unsigned char*>(key_.data()), key_.size(),
            reinterpret_cast<const unsigned char*>(msg.data()), msg.size(),
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
};

/* ============================================================
 * 诱饵标记（明文可见，strings 可抓）
 * ============================================================ */
static const char FAKE_MARK[] = "Fatdog_sunrise";

/* ============================================================
 * 生成请求签名
 * ============================================================ */
static std::string build_sign(int page, long ts) {
    /* 构造两段 SignKey 并用 operator+ 拼接 */
    SignKey left;   // 解码 K48_A → "Fatdog_calm_"
    std::string right_raw(K48_B_LEN, '\0');
    for (size_t i = 0; i < K48_B_LEN; i++) {
        right_raw[i] = static_cast<char>(K48_B[i] ^ 0x5A);
    }
    SignKey right(right_raw);  // 解码 K48_B → "2026"

    SignKey full = left + right;  // operator+ 拼接 → "Fatdog_calm_2026"

    char msg[128];
    snprintf(msg, sizeof(msg), "page=%d&ts=%ld", page, ts);
    return full.sign(std::string(msg));
}

/* ============================================================
 * JNI 导出函数
 * ============================================================ */
extern "C" {

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Bk48_nativeSign(JNIEnv *env, jclass clazz, jint page, jlong ts) {
    std::string sig = build_sign(page, static_cast<long>(ts));
    return env->NewStringUTF(sig.c_str());
}

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Bk48_getKeyHint(JNIEnv *env, jclass clazz) {
    /* 返回右半段提示（不是完整密钥） */
    return env->NewStringUTF("right_part_is_year_string");
}

}  /* extern "C" */

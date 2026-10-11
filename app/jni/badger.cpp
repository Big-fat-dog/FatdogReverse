/**
 * badger.cpp — Native大陆 L48 落日平原（operator+ 重载 · 跨层回调）
 *
 * 考点：
 *   1. C++ name mangling + std::string + operator+ 运算符重载
 *   2. JNI 反向调用：so 回调 Java 的**实例方法**
 *      （GetObjectClass → GetMethodID → CallObjectMethod）
 *
 * 密钥两截跨层拼装：
 *   前半 "Fatdog_calm_" 在本 so（XOR 数组）；
 *   后半 "2026" 在 Java（com.fatdog.reverse.k.Grain —— R8 改名类，
 *   私有构造 + 私有解密函数 + 反射）。Java 反射造好实例后经 bindHolder
 *   递给本 so 存全局引用；so 侧再带常量掩码回调 half(int) 取件。
 *   掩码/盐少一个 → Java 解出乱码 → 签名错 → 服务端 403。
 *
 * Frida 训练：Hook C++ mangled 函数名（_ZN7SignKey...），用 DebugSymbol 反解 demangle 名
 *
 * 标记：诱饵 Fatdog_sunrise（明文可见，strings 可抓）
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

/* 注：本关签名已改走 HMAC-MD5（见 SignKey::sign），原先的 hmac_sha256 实现已删除；
 * SHA-256 仍用于对 body 取摘要。 */

/* ============================================================
 * MD5（供 HMAC-MD5 使用；SHA-256 仍负责 body 摘要）
 * 注意：MD5 是小端（长度字段亦为小端），与 SHA-256 的大端相反
 * ============================================================ */
static const unsigned int md5_k[64] = {
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
};

static const unsigned char md5_s[64] = {
    7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
    5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
    4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
    6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
};

#define MD5_ROTL(x,n) (((x)<<(n))|((x)>>(32-(n))))

static void md5_block(unsigned int h[4], const unsigned char *p) {
    unsigned int a=h[0], b=h[1], c=h[2], d=h[3];
    unsigned int m[16], f, g, tmp, i;
    for (i = 0; i < 16; i++)
        m[i] = (unsigned int)p[4*i] | ((unsigned int)p[4*i+1] << 8) |
               ((unsigned int)p[4*i+2] << 16) | ((unsigned int)p[4*i+3] << 24);
    for (i = 0; i < 64; i++) {
        if (i < 16)      { f = (b & c) | ((~b) & d); g = i; }
        else if (i < 32) { f = (d & b) | ((~d) & c); g = (5*i + 1) & 15; }
        else if (i < 48) { f = b ^ c ^ d;            g = (3*i + 5) & 15; }
        else             { f = c ^ (b | (~d));       g = (7*i) & 15; }
        tmp = d; d = c; c = b;
        b = b + MD5_ROTL(a + f + md5_k[i] + m[g], md5_s[i]);
        a = tmp;
    }
    h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d;
}

static void md5_digest(const unsigned char *msg, size_t len, unsigned char out[16]) {
    unsigned int h[4];
    size_t off, rem, tlen, i;
    unsigned char tail[128];
    unsigned long long bits = (unsigned long long)len * 8ULL;
    h[0]=0x67452301; h[1]=0xefcdab89; h[2]=0x98badcfe; h[3]=0x10325476;
    for (off = 0; off + 64 <= len; off += 64)
        md5_block(h, msg + off);
    rem = len - off;
    memset(tail, 0, sizeof(tail));
    memcpy(tail, msg + off, rem);
    tail[rem] = 0x80;
    tlen = (rem + 9 <= 64) ? 64 : 128;
    /* 长度字段：64 位小端（MD5 规定，勿照抄 SHA-256 的大端写法） */
    for (i = 0; i < 8; i++)
        tail[tlen - 8 + i] = (unsigned char)((bits >> (8 * i)) & 0xFF);
    md5_block(h, tail);
    if (tlen == 128) md5_block(h, tail + 64);
    for (i = 0; i < 4; i++) {
        out[4*i]   = (unsigned char)(h[i] & 0xFF);
        out[4*i+1] = (unsigned char)((h[i] >> 8) & 0xFF);
        out[4*i+2] = (unsigned char)((h[i] >> 16) & 0xFF);
        out[4*i+3] = (unsigned char)((h[i] >> 24) & 0xFF);
    }
}

/* HMAC-MD5：消息不超过 256 字节 */
static void hmac_md5(const unsigned char *key, size_t klen,
                     const unsigned char *msg, size_t mlen,
                     unsigned char out[16]) {
    unsigned char k0[64], ipad[64], opad[64], ih[16], buf[384];
    size_t i;
    memset(k0, 0, sizeof(k0));
    if (klen > 64) md5_digest(key, klen, k0);
    else memcpy(k0, key, klen);
    for (i = 0; i < 64; i++) { ipad[i] = k0[i] ^ 0x36; opad[i] = k0[i] ^ 0x5c; }
    if (mlen > 256) mlen = 256;
    memcpy(buf, ipad, 64);
    memcpy(buf + 64, msg, mlen);
    md5_digest(buf, 64 + mlen, ih);
    memcpy(buf, opad, 64);
    memcpy(buf + 64, ih, 16);
    md5_digest(buf, 80, out);
}

/* ============================================================
 * XOR 数组：只剩左半段；右半段改由 Java 侧供给（见下方跨层回调）
 * ============================================================ */
static const uint8_t K48_A[] = {
    0x7A, 0x5D, 0x48, 0x58, 0x53, 0x5B, 0x63, 0x5F,
    0x5D, 0x50, 0x51, 0x63
};  // ^0x3C → "Fatdog_calm_"

#define K48_A_LEN (sizeof(K48_A))

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
        unsigned char digest[16];
        hmac_md5(
            reinterpret_cast<const unsigned char*>(key_.data()), key_.size(),
            reinterpret_cast<const unsigned char*>(msg.data()), msg.size(),
            digest);

        static const char hexc[] = "0123456789abcdef";
        char hex[33];
        for (unsigned int i = 0; i < 16; i++) {
            hex[i * 2]     = hexc[digest[i] >> 4];
            hex[i * 2 + 1] = hexc[digest[i] & 0x0f];
        }
        hex[32] = '\0';
        return std::string(hex);
    }
};

/* ============================================================
 * 跨层回调：右半段密钥由 Java 侧的 Grain 供给
 *   Java 反射造实例 → bindHolder(实例) → 本 so 存全局引用
 *   算签名时按方法名回调 half(int mask)，mask 是 so 侧常量
 * ============================================================ */
static JavaVM   *g_vm  = NULL;     /* JNI_OnLoad 接住，供无 env 时取用 */
static jclass    g_cls = NULL;     /* Grain 的全局类引用 */
static jobject   g_obj = NULL;     /* Grain 的实例（Java 反射造好递进来） */
static jmethodID g_mid = NULL;     /* Grain.half(int) */

/* so 侧常量掩码：Grain 的私有解密函数少了它就解不出正确明文 */
static const jint K48_MASK = 0x3E5C7B1F;

static std::string fetch_right(JNIEnv *env) {
    if (env == NULL && g_vm != NULL) {
        if (g_vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK) {
            return std::string();
        }
    }
    if (env == NULL || g_obj == NULL || g_mid == NULL) return std::string();

    jstring js = (jstring) env->CallObjectMethod(g_obj, g_mid, K48_MASK);
    if (js == NULL) return std::string();
    const char *cs = env->GetStringUTFChars(js, NULL);
    std::string out;
    if (cs != NULL) {
        out.assign(cs);
        env->ReleaseStringUTFChars(js, cs);
    }
    env->DeleteLocalRef(js);
    if (out == "ERR_JAVA") out.clear();
    return out;
}

/* ============================================================
 * 诱饵标记（明文可见，strings 可抓）
 * ============================================================ */
static const char FAKE_MARK[] = "Fatdog_sunrise";

/* ============================================================
 * 生成请求签名
 * ============================================================ */
static std::string build_sign(JNIEnv *env, int page, long ts) {
    /* 跨层取件：左半段在本 so，右半段回调 Java */
    SignKey left;                                   // 解码 K48_A → "Fatdog_calm_"
    std::string right_raw = fetch_right(env);       // Grain.half(K48_MASK) → "2026"
    if (right_raw.empty()) return std::string("ERR_BIND");

    SignKey full = left + SignKey(right_raw);       // operator+ 拼接 → "Fatdog_calm_2026"

    /* 组装 body → 取 SHA-256 摘要 → 对**摘要**签名（毫秒 ts 写在 body 里） */
    char body[128];
    snprintf(body, sizeof(body), "page=%d&ts=%lld", page, (long long) ts);
    unsigned char dg[32];
    char dghex[65];
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, (const unsigned char *) body, strlen(body));
    sha256_final(&c, dg);
    for (int i = 0; i < 32; i++) snprintf(dghex + i * 2, 3, "%02x", dg[i]);
    dghex[64] = 0;
    return full.sign(std::string(dghex));
}

/* ============================================================
 * JNI 导出函数
 * ============================================================ */
extern "C" {

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void) reserved;
    g_vm = vm;
    return JNI_VERSION_1_6;
}

/* 诱饵导出：Java 侧根本没有声明这个方法 —— 纯误导。
 * 作用有两个：让 strings/nm 能抓到 "Fatdog_sunrise"；
 * 让符号表里多一个看起来像"密钥入口"的假门。 */
JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Bk48_nativeSunrise(JNIEnv *env, jobject thiz) {
    (void) thiz;
    return env->NewStringUTF(FAKE_MARK);
}

/* Java 把反射造好的 Grain 实例递进来，这里缓存成全局引用 */
JNIEXPORT void JNICALL
Java_com_fatdog_reverse_Bk48_bindHolder(JNIEnv *env, jclass clazz, jobject holder) {
    (void) clazz;
    if (g_obj != NULL) { env->DeleteGlobalRef(g_obj); g_obj = NULL; }
    if (g_cls != NULL) { env->DeleteGlobalRef(g_cls); g_cls = NULL; }
    g_mid = NULL;
    if (holder == NULL) return;
    g_obj = env->NewGlobalRef(holder);
    if (g_obj == NULL) return;
    jclass local = env->GetObjectClass(holder);
    if (local == NULL) return;
    g_cls = (jclass) env->NewGlobalRef(local);
    env->DeleteLocalRef(local);
    if (g_cls == NULL) return;
    g_mid = env->GetMethodID(g_cls, "half", "(I)Ljava/lang/String;");
}

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Bk48_nativeSign(JNIEnv *env, jobject thiz, jint page, jlong ts) {
    (void) thiz;
    std::string sig = build_sign(env, page, static_cast<long>(ts));
    return env->NewStringUTF(sig.c_str());
}

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Bk48_getKeyHint(JNIEnv *env, jobject thiz) {
    (void) thiz;
    /* 返回右半段提示（不是完整密钥） */
    return env->NewStringUTF("right_part_is_year_string");
}

}  /* extern "C" */

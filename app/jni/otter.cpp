/**
 * otter.cpp — Native大陆 L49 迷雾森林（std::map 分发 · RAII · 跨层回调）
 *
 * 考点：
 *   1. C++ std::map 分发 + RAII 内存管理（CryptoBox / ManagedBuffer）
 *   2. JNI 反向调用：so 侧用 **NewObject** 直接造 Java 对象（私有构造），
 *      再回调实例方法取件（GetMethodID + CallObjectMethod）
 *
 * 与 L48 的对照：
 *   L48 —— Java 反射把 Grain 实例造好，交 native 缓存（Java 造对象）；
 *   L49 —— Java 只把 Warden.class 递进来，native 自己 NewObject 造实例。
 *
 * 密钥两处跨层拼装（交叉拆，与 L48 故意不对称）：
 *   SM4  : so "Fatdog_mist_"  +  Java Warden.mistTail()  → "2026"
 *   HMAC : Java Warden.forestHead() "Fatdog_forest_"  +  so "2026"
 *   掩码是 so 侧常量、盐在 Java 构造里 —— 只读一边只能解出乱码 → 签名错 → 服务端 403。
 *
 * Frida 训练：Memory.scanSync 搜 std::map 红黑树节点；hook NewObject 观察造对象时机
 *
 * 标记：诱饵 Fatdog_misty（明文可见，strings 可抓）
 */

#include <jni.h>
#include <string>
#include <cstring>
#include <cstdio>
#include <cstdint>
#include <functional>
#include <map>

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
 * MD5 + HMAC-MD5（本关签名已改走 HMAC-MD5；原先的 SHA-256 / hmac_sha256
 * 已无调用方，一并删除，避免死代码与编译告警）
 * 注意：MD5 是小端（长度字段亦为小端）
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
 * XOR 数组：只剩片段；其余改由 Java 侧供给（见下方跨层回调）
 * ============================================================ */
static const uint8_t K49_SM4_A[] = {
    0x7A, 0x5D, 0x48, 0x58, 0x53, 0x5B, 0x63, 0x51,
    0x55, 0x4F, 0x48, 0x63
};  // ^0x3C → "Fatdog_mist_"（SM4 头段）

static const uint8_t K49_HMAC_B[] = {
    0x68, 0x6A, 0x68, 0x6C
};  // ^0x5A → "2026"（HMAC 尾段）

/* ============================================================
 * 跨层回调：两段密钥由 Java 侧的 Warden 供给
 *   Java 只递进 Class → 本 so NewObject 调私有构造造实例
 *   再按方法名回调 mistTail(int) / forestHead(int)，mask 是 so 侧常量
 * ============================================================ */
static JavaVM   *g_vm     = NULL;   /* JNI_OnLoad 接住，供无 env 时取用 */
static jclass    g_cls    = NULL;   /* Warden 的全局类引用（Java 递进来的 Class） */
static jmethodID g_ctor   = NULL;   /* Warden.<init>(int) */
static jmethodID g_mist   = NULL;   /* Warden.mistTail(int) → String */
static jmethodID g_forest = NULL;   /* Warden.forestHead(int) → int[] */

/* so 侧常量：盐在 Java 构造里、掩码在这里 —— 两边都要才解得开 */
static const jint SALT_WARDEN = 0x2C4E;
static const jint MASK_MIST   = 0x5B3D7F21;
static const jint MASK_FOREST = 0x7E2A51C9;

static JNIEnv *get_env() {
    if (g_vm == NULL) return NULL;
    JNIEnv *env = NULL;
    if (g_vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK) return NULL;
    return env;
}

/* native 侧自己造 Java 对象（JNI 不看访问修饰符 → 可直接调私有构造） */
static jobject new_warden(JNIEnv *env) {
    if (env == NULL || g_cls == NULL || g_ctor == NULL) return NULL;
    return env->NewObject(g_cls, g_ctor, SALT_WARDEN);
}

static std::string fetch_mist_tail(JNIEnv *env) {
    if (env == NULL) env = get_env();
    if (env == NULL || g_mist == NULL) return std::string();
    jobject obj = new_warden(env);
    if (obj == NULL) return std::string();
    jstring js = (jstring) env->CallObjectMethod(obj, g_mist, MASK_MIST);
    env->DeleteLocalRef(obj);
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

static std::string fetch_forest_head(JNIEnv *env) {
    if (env == NULL) env = get_env();
    if (env == NULL || g_forest == NULL) return std::string();
    jobject obj = new_warden(env);
    if (obj == NULL) return std::string();
    jintArray arr = (jintArray) env->CallObjectMethod(obj, g_forest, MASK_FOREST);
    env->DeleteLocalRef(obj);
    if (arr == NULL) return std::string();
    jsize n = env->GetArrayLength(arr);
    if (n < 0 || n > 64) n = 0;
    jint *p = env->GetIntArrayElements(arr, NULL);
    std::string out;
    if (p != NULL) {
        for (jsize i = 0; i < n; i++) out.push_back((char)(p[i] & 0xFF));
        env->ReleaseIntArrayElements(arr, p, JNI_ABORT);
    }
    env->DeleteLocalRef(arr);
    return out;
}

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
 * CryptoBox 类：std::map 分发 + SM4-ECB + HMAC-MD5
 *
 * 两段跨层密钥在构造时拼齐：
 *   sm4_key_  = so 头段 12 字节  + Java 尾段 4 字节
 *   hmac_key_ = Java 头段 14 字节 + so 尾段 4 字节
 *
 * Frida 训练点：
 *   1. std::map 内部红黑树节点结构（_Rb_tree_node）
 *   2. hook std::map::operator[] 观察分发
 * ============================================================ */
class CryptoBox {
private:
    // std::map 分发表：algo_id → 处理函数
    std::map<int, std::function<std::string(const std::string&)>> dispatch_;

    // SM4 密钥（so 头段 + Java 尾段）
    uint8_t sm4_key_[16];

    // HMAC 密钥（Java 头段 + so 尾段）
    uint8_t hmac_key_[18];

    // SM4 加密函数（内部）
    std::string sm4_encrypt_internal(const std::string& data) {
        return sm4_ecb_encrypt(sm4_key_, data);
    }

    // HMAC 签名函数（内部）—— 对 hex 字符串签名（与 server 口径一致）
    std::string hmac_sign_internal(const std::string& data) {
        unsigned char digest[16];
        hmac_md5(hmac_key_, sizeof(hmac_key_),
                 reinterpret_cast<const unsigned char*>(data.data()), data.size(),
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

public:
    CryptoBox(const std::string& sm4_tail, const std::string& hmac_head) {
        /* 注意：异或掩码必须走 volatile。K49_* 是 const 数组，若掩码也是字面量，
         * 优化器会在编译期把整段异或折叠成明文常量摆进 .rodata —— 实测 28.2 的
         * -O2 就把 SM4 头段还原成了明文串，strings 一击即中。volatile 强制运行时求值。 */
        volatile uint8_t mk = 0x3C;
        volatile uint8_t hk = 0x5A;

        // SM4：so 头段（XOR ^0x3C） + Java 尾段
        for (size_t i = 0; i < sizeof(K49_SM4_A); i++) {
            sm4_key_[i] = (uint8_t)(K49_SM4_A[i] ^ mk);
        }
        for (size_t i = 0; i < 4; i++) {
            sm4_key_[12 + i] = (uint8_t)(i < sm4_tail.size() ? sm4_tail[i] : 0);
        }

        // HMAC：Java 头段 + so 尾段（XOR ^0x5A）
        for (size_t i = 0; i < 14; i++) {
            hmac_key_[i] = (uint8_t)(i < hmac_head.size() ? hmac_head[i] : 0);
        }
        for (size_t i = 0; i < sizeof(K49_HMAC_B); i++) {
            hmac_key_[14 + i] = (uint8_t)(K49_HMAC_B[i] ^ hk);
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
 * 生成请求密文 / 签名（两段密钥均从 Java 回调取件）
 * ============================================================ */
static std::string build_enc(JNIEnv *env, int page, long ts) {
    std::string sm4_tail = fetch_mist_tail(env);       // Warden.mistTail(MASK_MIST) → "2026"
    std::string hmac_head = fetch_forest_head(env);    // Warden.forestHead(MASK_FOREST) → "Fatdog_forest_"
    if (sm4_tail.empty() || hmac_head.empty()) return std::string("ERR_BIND");

    CryptoBox box(sm4_tail, hmac_head);
    char payload[128];
    snprintf(payload, sizeof(payload), "page=%d&ts=%ld", page, ts);
    return box.process(0, std::string(payload));       // algo_id=0 → SM4 加密
}

static std::string build_sign(JNIEnv *env, const std::string& enc_hex) {
    std::string sm4_tail = fetch_mist_tail(env);
    std::string hmac_head = fetch_forest_head(env);
    if (sm4_tail.empty() || hmac_head.empty()) return std::string("ERR_BIND");

    CryptoBox box(sm4_tail, hmac_head);
    return box.process(1, enc_hex);                    // algo_id=1 → HMAC 签名
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
 * 作用有两个：让 strings/nm 能抓到 "Fatdog_misty"；
 * 让符号表里多一个看起来像"密钥入口"的假门。 */
JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Bk49_nativeMisty(JNIEnv *env, jclass clazz) {
    (void) clazz;
    return env->NewStringUTF(FAKE_MARK);
}

/* Java 只递进 Warden.class；native 侧自己 NewObject 造实例 */
JNIEXPORT void JNICALL
Java_com_fatdog_reverse_Bk49_bindKeys(JNIEnv *env, jclass clazz, jclass holder) {
    (void) clazz;
    if (g_cls != NULL) { env->DeleteGlobalRef(g_cls); g_cls = NULL; }
    g_ctor = g_mist = g_forest = NULL;
    if (holder == NULL) return;
    g_cls = (jclass) env->NewGlobalRef(holder);
    if (g_cls == NULL) return;
    g_ctor   = env->GetMethodID(g_cls, "<init>", "(I)V");
    g_mist   = env->GetMethodID(g_cls, "mistTail", "(I)Ljava/lang/String;");
    g_forest = env->GetMethodID(g_cls, "forestHead", "(I)[I");
}

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Bk49_nativeEnc(JNIEnv *env, jobject thiz, jint page, jlong ts) {
    (void) thiz;
    std::string enc = build_enc(env, page, static_cast<long>(ts));
    if (enc == "ERR_BIND") return env->NewStringUTF("ERR_BIND");

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
Java_com_fatdog_reverse_Bk49_nativeSign(JNIEnv *env, jobject thiz, jstring enc_hex) {
    (void) thiz;
    const char* hex_str = env->GetStringUTFChars(enc_hex, nullptr);
    std::string s = (hex_str != nullptr) ? std::string(hex_str) : std::string();
    if (hex_str != nullptr) env->ReleaseStringUTFChars(enc_hex, hex_str);

    std::string sig = build_sign(env, s);
    return env->NewStringUTF(sig.c_str());
}

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Bk49_getKeyHint(JNIEnv *env, jobject thiz) {
    (void) thiz;
    return env->NewStringUTF("two_halves_split_across_layers");
}

}  /* extern "C" */

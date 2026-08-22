#include <jni.h>
#include <string.h>
#include <stdio.h>

// ============================================================================
// 关卡 30：无名剑冢（native 第三季第 3 关）
//   四个同形的签名函数，只有一个是真身——经函数指针表间接派发，
//   JNI 入口处看不到直接调用；真身压在文件最底部。
//   密钥不用异或：全部以 UTF-16 码元（\x 十六进制字面值）存放，
//   strings 与 IDA 字符串窗口一概不显示，运行时才收窄成 char。
//   谁是真身？服务器当裁判：拿错候选的签名只会换来 403。
//     槽 0 = Fatdog_gloomy（真）  槽 1 = Fatdog_pale
//     槽 2 = Fatdog_sour         槽 3 = Fatdog_mute（Java 层诱饵 Xk 同款）
// ============================================================================

// ---------------- 密钥库：UTF-16LE 码元，\x 十六进制字面值 ----------------

unsigned short K30_GLOOMY[]  /* 非 const：防编译器折叠进指令立即数 */ = {0x0046,0x0061,0x0074,0x0064,0x006f,0x0067,0x005f,0x0067,0x006c,0x006f,0x006f,0x006d,0x0079}; /* Fatdog_gloomy */
unsigned short K30_PALE[]  /* 非 const：防编译器折叠进指令立即数 */   = {0x0046,0x0061,0x0074,0x0064,0x006f,0x0067,0x005f,0x0070,0x0061,0x006c,0x0065};              /* Fatdog_pale   */
unsigned short K30_SOUR[]  /* 非 const：防编译器折叠进指令立即数 */   = {0x0046,0x0061,0x0074,0x0064,0x006f,0x0067,0x005f,0x0073,0x006f,0x0075,0x0072};              /* Fatdog_sour   */
unsigned short K30_MUTE[]  /* 非 const：防编译器折叠进指令立即数 */   = {0x0046,0x0061,0x0074,0x0064,0x006f,0x0067,0x005f,0x006d,0x0075,0x0074,0x0065};              /* Fatdog_mute   */

static void k30_decode(const unsigned short *src, int n, char *dst) {
    int i;
    for (i = 0; i < n; i++) dst[i] = (char) (src[i] & 0xFF);
    dst[n] = '\0';
}

// ---------------- SHA-256 / HMAC-SHA256（紧凑实现） ----------------
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

static void sign_hex(const unsigned char *key, size_t klen, int page, long long ts,
                     char hex[65]) {
    char msg[64];
    unsigned char mac[32];
    static const char hexc[] = "0123456789abcdef";
    int i;
    snprintf(msg, sizeof(msg), "page=%d&ts=%lld", page, ts);
    hmac_sha256(key, klen, (const unsigned char *) msg, strlen(msg), mac);
    for (i = 0; i < 32; i++) {
        hex[i * 2]     = hexc[mac[i] >> 4];
        hex[i * 2 + 1] = hexc[mac[i] & 0x0f];
    }
    hex[64] = '\0';
}

// ---------------- 四个同形签名函数（诱饵在前，真身沉底） ----------------

#define K30_SIGN_BODY(name, ARR, N)                                          \
__attribute__((noinline)) static jstring name(JNIEnv *env, jclass clazz,     \
                                              jint page, jlong ts) {         \
    char key[16];                                                            \
    char hex[65];                                                            \
    (void) clazz;                                                            \
    k30_decode(ARR, N, key);                                                 \
    sign_hex((const unsigned char *) key, N, (int) page, (long long) ts, hex); \
    return (*env)->NewStringUTF(env, hex);                                   \
}

K30_SIGN_BODY(sign_pale,   K30_PALE,   11)
K30_SIGN_BODY(sign_sour,   K30_SOUR,   11)
K30_SIGN_BODY(sign_mute,   K30_MUTE,   11)
K30_SIGN_BODY(sign_gloomy, K30_GLOOMY, 13)

// ---------------- 函数指针表派发：JNI 入口只看得到一次间接调用 ----------------

typedef jstring (*k30_fn)(JNIEnv *, jclass, jint, jlong);

static const k30_fn K30_TABLE[4] = { sign_gloomy, sign_pale, sign_sour, sign_mute };
static volatile int K30_SLOT = 0;   /* volatile：防编译器把槽位折叠成常量 */

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Vn_nativeSign(JNIEnv *env, jclass clazz, jint page, jlong ts) {
    return K30_TABLE[K30_SLOT](env, clazz, page, ts);
}

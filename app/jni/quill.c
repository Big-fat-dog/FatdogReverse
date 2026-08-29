#include <jni.h>
#include <string.h>
#include <stdio.h>

// ============================================================================
// 关卡 31：两界穿针（native 第三季第 4 关）
//   密钥两截跨层拼装：前半 "Fatdog_" 在 Java（q.Ke，R8 改名类，方法名保留），
//   后半 "lonely" 在本 so（UTF-16 码元，\x 字面值）。Java 启动时把 Ke.class
//   递进来缓存成全局引用；每次加密/签名 native 都经
//   GetStaticMethodID → CallStaticObjectMethod 回调取件——单侧永远拿不全。
//   请求形态：enc=hex(RC4(key,"page=N&ts=T")) + sign=HMAC(key,enc) + 动态 ts。
// ============================================================================

/* 后半密钥："lonely"，UTF-16LE 码元（非 const 全局防折叠进指令） */
unsigned short KEY31_B[] = {0x006c, 0x006f, 0x006e, 0x0065, 0x006c, 0x0079};

static jclass g_keyClass = NULL;   /* q.Ke 的全局引用（bindKeyClass 时创建） */
JavaVM *k31_vm = NULL;             /* JNI_OnLoad 时接住，回调 Java 时取 env 用 */

/* 拼合密钥到 buf：partA() 的返回值 + lonely，返回总长 */
static int k31_join_key(char *buf, size_t cap) {
    char a[32];
    const char *pa;
    jstring ja;
    jmethodID mid;
    JNIEnv *env = NULL;
    jint n;
    int len = 0;
    if (k31_vm == NULL || g_keyClass == NULL) return 0;
    if ((*k31_vm)->GetEnv(k31_vm, (void **) &env, JNI_VERSION_1_6) != JNI_OK) return 0;

    mid = (*env)->GetStaticMethodID(env, g_keyClass, "partA", "()Ljava/lang/String;");
    if (mid == NULL) return 0;
    ja = (*env)->CallStaticObjectMethod(env, g_keyClass, mid);
    if (ja == NULL) return 0;
    pa = (*env)->GetStringUTFChars(env, ja, NULL);
    if (pa == NULL) { (*env)->DeleteLocalRef(env, ja); return 0; }

    strncpy(a, pa, sizeof(a) - 1);
    a[sizeof(a) - 1] = '\0';
    (*env)->ReleaseStringUTFChars(env, ja, pa);
    (*env)->DeleteLocalRef(env, ja);

    n = (jint) strlen(a);
    for (len = 0; len < n && (size_t) len < cap - 1; len++) buf[len] = a[len];
    for (n = 0; n < (jint) (sizeof(KEY31_B) / sizeof(KEY31_B[0])) && (size_t) len < cap - 1; n++, len++)
        buf[len] = (char) (KEY31_B[n] & 0xFF);
    buf[len] = '\0';
    return len;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void) reserved;
    k31_vm = vm;
    return JNI_VERSION_1_6;
}

JNIEXPORT void JNICALL
Java_com_fatdog_reverse_Zr_bindKeyClass(JNIEnv *env, jclass clazz, jobject holder) {
    (void) clazz;
    if (g_keyClass == NULL) g_keyClass = (*env)->NewGlobalRef(env, holder);
}

/* ---------------- RC4 ---------------- */

static void k31_rc4(const unsigned char *key, size_t klen,
                    const unsigned char *in, size_t n, unsigned char *out) {
    unsigned char S[256], t;
    int i, j = 0, a = 0, b = 0;
    size_t k;
    for (i = 0; i < 256; i++) S[i] = (unsigned char) i;
    for (i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % klen]) & 0xFF;
        t = S[i]; S[i] = S[j]; S[j] = t;
    }
    for (k = 0; k < n; k++) {
        a = (a + 1) & 0xFF;
        b = (b + S[a]) & 0xFF;
        t = S[a]; S[a] = S[b]; S[b] = t;
        out[k] = in[k] ^ S[(S[a] + S[b]) & 0xFF];
    }
}

static void to_hex(const unsigned char *d, int n, char *hex) {
    static const char h[] = "0123456789abcdef";
    int i;
    for (i = 0; i < n; i++) {
        hex[i * 2]     = h[d[i] >> 4];
        hex[i * 2 + 1] = h[d[i] & 0x0f];
    }
    hex[n * 2] = '\0';
}

/* ---------------- SHA-256 / HMAC-SHA256（紧凑实现） ---------------- */
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

/* ---------------- JNI 入口 ---------------- */

/* 载荷统一为 page=N&ts=T，供 enc 与对拍使用 */
static int k31_payload(int page, long long ts, char *msg, size_t cap) {
    return snprintf(msg, cap, "page=%d&ts=%lld", page, ts);
}

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Zr_nativeEnc(JNIEnv *env, jclass clazz, jint page, jlong ts) {
    char key[40], msg[64];
    unsigned char out[64];
    char hex[129];
    int klen, mlen;
    (void) clazz;
    klen = k31_join_key(key, sizeof(key));
    if (klen <= 0) return (*env)->NewStringUTF(env, "");
    mlen = k31_payload((int) page, (long long) ts, msg, sizeof(msg));
    k31_rc4((const unsigned char *) key, (size_t) klen,
            (const unsigned char *) msg, (size_t) mlen, out);
    to_hex(out, mlen, hex);
    return (*env)->NewStringUTF(env, hex);
}

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Zr_nativeSign(JNIEnv *env, jclass clazz, jstring encHex) {
    char key[40];
    const char *enc;
    unsigned char mac[32];
    char hex[65];
    int klen;
    size_t elen;
    (void) clazz;
    klen = k31_join_key(key, sizeof(key));
    if (klen <= 0) return (*env)->NewStringUTF(env, "");
    enc = (*env)->GetStringUTFChars(env, encHex, NULL);
    if (enc == NULL) return (*env)->NewStringUTF(env, "");
    elen = strlen(enc);
    /* HMAC-SHA256(key, encHex) —— 手写紧凑版 */
    {
        unsigned char k[64], ipad[64], opad[64], inner[32];
        sha256_ctx c;
        int i;
        memset(k, 0, sizeof(k));
        if (klen > 64) {
            sha256_init(&c); sha256_update(&c, (const unsigned char *) key, (size_t) klen);
            sha256_final(&c, k);
        } else {
            memcpy(k, key, (size_t) klen);
        }
        for (i = 0; i < 64; i++) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5c; }
        sha256_init(&c); sha256_update(&c, ipad, 64);
        sha256_update(&c, (const unsigned char *) enc, elen);
        sha256_final(&c, inner);
        sha256_init(&c); sha256_update(&c, opad, 64);
        sha256_update(&c, inner, 32);
        sha256_final(&c, mac);
    }
    (*env)->ReleaseStringUTFChars(env, encHex, enc);
    to_hex(mac, 32, hex);
    return (*env)->NewStringUTF(env, hex);
}

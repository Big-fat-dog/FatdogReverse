#include <jni.h>
#include <string.h>
#include <stdio.h>

// ============================================================================
// 关卡 29：隐姓埋名（native 第三季第 2 关）
//   真身经 JNI_OnLoad → RegisterNatives 动态绑定到 Wq.nativeSign，
//   导出表里没有任何"正确名字"的静态注册函数：
//     - Java_com_fatdog_reverse_Wq_nativeSign（诱饵一：名字完全符合静态注册规则，
//       但被动态绑定覆盖，JVM 永远不会调它；密钥是明文假货 Fatdog_lazy）；
//     - Java_com_fatdog_reverse_Wq_sign（诱饵二：方法名都对不上，返回一串像样的废 hex）。
//   真实现 l29_real_sign 是 static 函数——strip 后在导出表彻底无名。
//   破法：spawn 模式抢时机 + hook libart 的 RegisterNatives 抓映射，或 IDA 静读。
// ============================================================================

// 真密钥的异或形态："Fatdog_angry" ^ 0x69
// 非 static 且非 const：防编译器把"异或解码"常量折叠成明文字面量塞进 .rodata
unsigned char KEY29_KX[] = {47, 8, 29, 13, 6, 14, 54, 8, 7, 14, 27, 16};

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

// ---------------- 真身：static 函数，导出表无名 ----------------

static jstring l29_real_sign(JNIEnv *env, jclass clazz, jint page, jlong ts) {
    char key[16];
    char hex[65];
    int i;
    (void) clazz;
    for (i = 0; i < (int) sizeof(KEY29_KX); i++) key[i] = (char) (KEY29_KX[i] ^ 0x69);
    key[sizeof(KEY29_KX)] = '\0';
    sign_hex((const unsigned char *) key, strlen(key), (int) page, (long long) ts, hex);
    return (*env)->NewStringUTF(env, hex);
}

// ---------------- 诱饵一：名字完全符合静态注册规则，但永远无人调用 ----------------

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Wq_nativeSign(JNIEnv *env, jclass clazz, jint page, jlong ts) {
    char hex[65];
    (void) clazz;
    /* 假密钥 Fatdog_lazy：strings 一眼能看到它，拿去算只会换来服务器 403 */
    sign_hex((const unsigned char *) "Fatdog_lazy", 11, (int) page, (long long) ts, hex);
    return (*env)->NewStringUTF(env, hex);
}

// ---------------- 诱饵二：连方法名都对不上，输出一串像样的废值 ----------------

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Wq_sign(JNIEnv *env, jclass clazz, jint page, jlong ts) {
    char hex[65];
    int i;
    (void) clazz; (void) page; (void) ts;
    for (i = 0; i < 64; i++) hex[i] = (char) ("0f1e2d3c5b6a7988"[i % 16]);
    hex[64] = '\0';
    return (*env)->NewStringUTF(env, hex);
}

// ---------------- JNI_OnLoad：动态注册，把真身绑上 Wq.nativeSign ----------------

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env = NULL;
    jclass cls;
    JNINativeMethod methods[1];
    (void) reserved;
    if ((*vm)->GetEnv(vm, (void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    cls = (*env)->FindClass(env, "com/fatdog/reverse/Wq");
    if (cls == NULL) {
        return JNI_ERR;
    }
    methods[0].name      = "nativeSign";
    methods[0].signature = "(IJ)Ljava/lang/String;";
    methods[0].fnPtr     = (void *) l29_real_sign;
    if ((*env)->RegisterNatives(env, cls, methods, 1) != JNI_OK) {
        return JNI_ERR;
    }
    return JNI_VERSION_1_6;
}

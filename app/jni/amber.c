/* libamber.so ——「以签为钥」（签名校验对抗 · L46，主打关卡）
 * L4 派生型：密钥 = SHA256(certHash ‖ 标记 ‖ vt)，直接作 HMAC-SHA256 签名。
 * 没有任何 if 判断签名对错——重打包者的证书摘要不同→派生 key 不同→服务端必然对不上。
 * 基准 certHash（原包 DER 的 SHA-256）以 ^0x66 异或存放，仅用于"判定当前包是否原包"。
 *
 * 2026-10-02 双层链路改造（同样的病因修一处：原先 nativeKeySeed 把传入的 DER
 * 直接 (void) 丢掉、改用内置基准派生，等于任何包派生的 key 都相同 → ② 形同虚设）：
 *   ① g_door 纯开关常量：出厂 0x2E，改成 0x9B 才允许取数（逼出一次重打包重签）；
 *   ② nativeKeySeed(der) 对**当前包的证书 DER** 做 SHA-256 并与基准比对：
 *        通过 → key = SHA256(运行时 certHash ‖ "Fatdog_bind" ‖ vt)   ← 服务端认，给真数据
 *        不过 → key = SHA256(内置基准    ‖ "Fatdog_band" ‖ vt)       ← 服务端认作诱饵，回脏数据
 *   ③ nativeVerdictToken() 产出一次性随机令牌 vt（门未开则返回空串 → 取不到数）。
 */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#ifndef M8_HOST_TEST
#include <jni.h>
#endif

/* 原包证书 DER 的 SHA-256（32 字节），^0x66 藏匿，非 static 防编译器折叠 */
unsigned char BENCH_X[32] = {
        0x5d,0xd4,0x75,0x2a,0xc5,0xd7,0x6d,0xca,
        0xb2,0x5f,0x03,0xb6,0xe5,0xe8,0x9c,0xf6,
        0x88,0x95,0x10,0x38,0x8b,0xee,0x54,0xf4,
        0xf7,0x0e,0xac,0x68,0x44,0x74,0x51,0x98,
};

static unsigned char g_bench[32];
static int g_bench_ready = 0;

/* 当前包证书 DER 的 SHA-256（nativeKeySeed 填入）+ 记账 */
static unsigned char g_cert[32];
static int g_checked = 0;
static int g_verdict = 0;
static int g_ticks = 0;

/* ---------- ① 第一层障碍：纯开关常量（非判定逻辑，刻意做轻） ----------
 * 出厂值 0x2E；门不开则 nativeVerdictToken / nativeSign 一律返回空串 → App 取不到数。
 * 把这一字节改成 0x9B（或把下面那条比较改掉）即可开门。 */
volatile unsigned int g_door = 0x2E;
#define M8_DOOR_OPEN 0x9B

static int m8_door_open(void) {
    return (g_door == (unsigned int)M8_DOOR_OPEN) ? 1 : 0;
}

/* "Fatdog_bind" ^0x3C ——运行时解码，静态无明文 */
static const unsigned char MARK_X[] = {
    122,93,72,88,83,91,99,94,85,82,88
};
#define MARK_LEN 11

/* "Fatdog_band" ^0x3C ——诱饵标记（与真标记一字之差；校验不过时用它派生 → 服务端回脏数据） */
static const unsigned char DMARK_X[] = {
    122,93,72,88,83,91,99,94,93,82,88
};
#define DMARK_LEN 11

static void m8_unlock_bench(void) {
    int i;
    for (i = 0; i < 32; i++) g_bench[i] = (unsigned char)(BENCH_X[i] ^ 0x66);
    g_bench_ready = 1;
}

/* ---------- SHA-256 ---------- */

static const unsigned int K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static unsigned int m8_rotr(unsigned int x, int n) { return (x >> n) | (x << (32 - n)); }

static void m8_sha_block(unsigned int h[8], const unsigned char p[64]) {
    unsigned int w[64];
    unsigned int a,b,c,d,e,f,g,hh,t1,t2,S0,S1,mj;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = ((unsigned int)p[4*i]<<24)|((unsigned int)p[4*i+1]<<16)
             | ((unsigned int)p[4*i+2]<<8)|(unsigned int)p[4*i+3];
    for (i = 16; i < 64; i++) {
        unsigned int s0 = m8_rotr(w[i-15],7) ^ m8_rotr(w[i-15],18) ^ (w[i-15]>>3);
        unsigned int s1 = m8_rotr(w[i-2],17) ^ m8_rotr(w[i-2],19) ^ (w[i-2]>>10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a=h[0];b=h[1];c=h[2];d=h[3];e=h[4];f=h[5];g=h[6];hh=h[7];
    for (i = 0; i < 64; i++) {
        S1 = m8_rotr(e,6)^m8_rotr(e,11)^m8_rotr(e,25);
        t1 = hh + S1 + ((e&f)^((~e)&g)) + K256[i] + w[i];
        S0 = m8_rotr(a,2)^m8_rotr(a,13)^m8_rotr(a,22);
        mj = (a&b)^(a&c)^(b&c);
        t2 = S0 + mj;
        hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
}

static void m8_sha256(const unsigned char *msg, unsigned int len, unsigned char out[32]) {
    unsigned int h[8];
    unsigned int off, rem, tlen, i;
    unsigned char tail[128];
    unsigned long long bits = (unsigned long long)len * 8ULL;
    h[0]=0x6a09e667;h[1]=0xbb67ae85;h[2]=0x3c6ef372;h[3]=0xa54ff53a;
    h[4]=0x510e527f;h[5]=0x9b05688c;h[6]=0x1f83d9ab;h[7]=0x5be0cd19;
    for (off = 0; off + 64 <= len; off += 64)
        m8_sha_block(h, msg + off);
    rem = len - off;
    memset(tail, 0, sizeof(tail));
    memcpy(tail, msg + off, rem);
    tail[rem] = 0x80;
    tlen = (rem + 9 <= 64) ? 64 : 128;
    for (i = 0; i < 8; i++)
        tail[tlen - 1 - i] = (unsigned char)((bits >> (8 * i)) & 0xFF);
    m8_sha_block(h, tail);
    if (tlen == 128) m8_sha_block(h, tail + 64);
    for (i = 0; i < 8; i++) {
        out[4*i]   = (unsigned char)(h[i]>>24);
        out[4*i+1] = (unsigned char)(h[i]>>16);
        out[4*i+2] = (unsigned char)(h[i]>>8);
        out[4*i+3] = (unsigned char)(h[i]);
    }
}

/* ---------- HMAC-SHA256 ---------- */

static void m8_hmac_sha256(const unsigned char *key, unsigned int klen,
                           const unsigned char *msg, unsigned int mlen,
                           unsigned char out[32]) {
    unsigned char k_pad[64], k_hash[32], o_key[64], i_key[64];
    unsigned char inner[32];
    unsigned char outer[128];
    int i;

    /* 如果 key > 64 字节，先 hash 缩短 */
    if (klen > 64) {
        m8_sha256(key, klen, k_hash);
        key = k_hash;
        klen = 32;
    }

    memset(k_pad, 0, 64);
    memcpy(k_pad, key, klen);

    /* 构建 ipad/opad */
    for (i = 0; i < 64; i++) {
        i_key[i] = k_pad[i] ^ 0x36;
        o_key[i] = k_pad[i] ^ 0x5C;
    }

    /* inner = SHA256(ipad || message) */
    memcpy(outer, i_key, 64);
    memcpy(outer + 64, msg, mlen);
    m8_sha256(outer, 64 + mlen, inner);

    /* outer = SHA256(opad || inner) */
    memcpy(outer, o_key, 64);
    memcpy(outer + 64, inner, 32);
    m8_sha256(outer, 64 + 32, out);
}

/* ---------- ③ 一次性令牌 + 派生密钥 ---------- */

static unsigned int g_rng_state = 0;

static unsigned int m8_rng_next(void) {
    unsigned int x;
    if (g_rng_state == 0) {
        g_rng_state = (((unsigned int)time(NULL)) ^ 0x9E3779B9u) | 1u;
    }
    x = g_rng_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    g_rng_state = x;
    return x;
}

/* key = SHA256(certHash(32) ‖ marker(11) ‖ vt(ascii ≤16))
 *   校验通过 → certHash 用当前包 DER 的摘要、marker = "Fatdog_bind"（与 server.py 一致）
 *   校验不过 / 尚未校验 → certHash 用内置基准、marker = "Fatdog_band"
 *                       → 服务端识别为诱饵，回【脏数据】而不是报错 */
static void m8_make_key(const char *vt, unsigned char out[32]) {
    unsigned char buf[32 + MARK_LEN + 16];
    const unsigned char *m;
    int i, n = 0;
    if (!g_bench_ready) m8_unlock_bench();
    if (g_checked && g_verdict) {
        m = MARK_X;
        memcpy(buf, g_cert, 32);
    } else {
        m = DMARK_X;
        memcpy(buf, g_bench, 32);
    }
    n = 32;
    for (i = 0; i < MARK_LEN; i++)
        buf[n++] = (unsigned char)(m[i] ^ 0x3C);   /* 解码标记 */
    if (vt) {
        for (i = 0; vt[i] && i < 16; i++) buf[n++] = (unsigned char)vt[i];
    }
    m8_sha256(buf, (unsigned int)n, out);
}

#ifndef M8_HOST_TEST

/* 递入当前包的证书 DER：native 内记账(ticks++)、摘要、与内置基准比对，
 * 并返回一份派生密钥（无 vt 的预览值；实际请求用的 key 由 nativeSign 内部按 vt 现算）。 */
JNIEXPORT jbyteArray JNICALL
Java_com_fatdog_reverse_Wg_nativeKeySeed(JNIEnv *env, jclass clazz, jbyteArray der) {
    jbyteArray result;
    unsigned char key[32];

    (void)clazz;
    g_ticks++;
    if (!g_bench_ready) m8_unlock_bench();
    g_checked = 1;

    if (!der) {
        g_verdict = 0;
        memset(g_cert, 0, 32);
    } else {
        jsize len = (*env)->GetArrayLength(env, der);
        jbyte *p = (*env)->GetByteArrayElements(env, der, NULL);
        if (!p) {
            g_verdict = 0;
            memset(g_cert, 0, 32);
        } else {
            m8_sha256((const unsigned char *)p, (unsigned int)len, g_cert);
            (*env)->ReleaseByteArrayElements(env, der, p, JNI_ABORT);
            g_verdict = (memcmp(g_cert, g_bench, 32) == 0) ? 1 : 0;
        }
    }

    m8_make_key("", key);
    result = (*env)->NewByteArray(env, 32);
    if (result)
        (*env)->SetByteArrayRegion(env, result, 0, 32, (jbyte *)key);
    return result;
}

/* nativeSign: HMAC-SHA256(key, "nonce=<n>&page=<p>&ts=<t>") → hex string
 * key    = SHA256(certHash ‖ marker ‖ vt)（marker 由 ② 的结论选定）
 * 被签串按字段名字典序拼接（nonce < page < ts）；nonce 每次请求都变。
 * ① 门未开 → 返回空串（Java 侧据此不发包）。 */
JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Wg_nativeSign(JNIEnv *env, jclass clazz,
                                       jint page, jlong ts, jstring nonce, jstring vt) {
    const char *n = NULL;
    const char *v = NULL;
    char msg[160];
    int mlen;
    unsigned char key[32];
    unsigned char dg[32];
    char hex[65];
    static const char *H = "0123456789abcdef";
    int i;

    (void)clazz;
    if (!m8_door_open()) return (*env)->NewStringUTF(env, "");

    if (nonce) n = (*env)->GetStringUTFChars(env, nonce, NULL);
    if (vt) v = (*env)->GetStringUTFChars(env, vt, NULL);
    mlen = snprintf(msg, sizeof(msg), "nonce=%s&page=%d&ts=%lld",
                    n ? n : "", page, (long long)ts);

    m8_make_key(v, key);
    m8_hmac_sha256(key, 32, (const unsigned char *)msg, (unsigned int)mlen, dg);

    for (i = 0; i < 32; i++) {
        hex[2*i]   = H[dg[i] >> 4];
        hex[2*i+1] = H[dg[i] & 0xF];
    }
    hex[64] = 0;
    if (n) (*env)->ReleaseStringUTFChars(env, nonce, n);
    if (v) (*env)->ReleaseStringUTFChars(env, vt, v);

    return (*env)->NewStringUTF(env, hex);
}

/* ③ 取数令牌：门未开 → 空串（Java 侧据此不发包，即"取不到数"）；门已开 → 16 位 hex */
JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Wg_nativeVerdictToken(JNIEnv *env, jclass clazz) {
    static const char H[] = "0123456789abcdef";
    char out[17];
    unsigned int a, b;
    int i;
    (void)clazz;
    if (!m8_door_open()) return (*env)->NewStringUTF(env, "");
    a = m8_rng_next();
    b = m8_rng_next() ^ (g_ticks * 0x9E3779B9u);
    for (i = 0; i < 8; i++) out[i]     = H[(a >> (4 * i)) & 0xF];
    for (i = 0; i < 8; i++) out[8 + i] = H[(b >> (4 * i)) & 0xF];
    out[16] = 0;
    return (*env)->NewStringUTF(env, out);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm;(void)reserved;
    return JNI_VERSION_1_6;
}

#else /* M8_HOST_TEST */

int main(void) {
    char hex[65];
    static const char *H = "0123456789abcdef";
    int i;
    unsigned char dg[32], key[32];

    printf("=== L46 以签为钥 · 本地自测 ===\n");

    /* SHA-256 标准向量 */
    m8_sha256((const unsigned char *)"abc", 3, dg);
    for (i = 0; i < 32; i++) { hex[2*i] = H[dg[i] >> 4]; hex[2*i+1] = H[dg[i] & 0xF]; }
    hex[64] = 0;
    printf("sha256(abc) = %s\n", hex);

    /* 基准（^0x66 还原） */
    m8_unlock_bench();
    for (i = 0; i < 32; i++) { hex[2*i] = H[g_bench[i] >> 4]; hex[2*i+1] = H[g_bench[i] & 0xF]; }
    hex[64] = 0;
    printf("bench       = %s\n", hex);

    /* ① 门开关：出厂关、改常量后开 */
    printf("door_open(default) = %d (expect 0)\n", m8_door_open());
    g_door = M8_DOOR_OPEN;
    printf("door_open(patched) = %d (expect 1)\n", m8_door_open());

    /* ② 未校验 → 走诱饵；模拟校验通过 → 走真标记 */
    m8_make_key("0123456789abcdef", key);
    for (i = 0; i < 32; i++) { hex[2*i] = H[key[i] >> 4]; hex[2*i+1] = H[key[i] & 0xF]; }
    hex[64] = 0;
    printf("decoy key   = %s\n", hex);

    memcpy(g_cert, g_bench, 32);
    g_checked = 1; g_verdict = 1;
    m8_make_key("0123456789abcdef", key);
    for (i = 0; i < 32; i++) { hex[2*i] = H[key[i] >> 4]; hex[2*i+1] = H[key[i] & 0xF]; }
    hex[64] = 0;
    printf("real  key   = %s\n", hex);

    /* HMAC 与令牌自测 */
    m8_hmac_sha256(key, 32, (const unsigned char *)"nonce=aa&page=1&ts=1700000000", 28, dg);
    for (i = 0; i < 32; i++) { hex[2*i] = H[dg[i] >> 4]; hex[2*i+1] = H[dg[i] & 0xF]; }
    hex[64] = 0;
    printf("hmac sample = %s\n", hex);

    g_ticks = 1;
    printf("vt a = %08x  vt b = %08x  (expect differ)\n", m8_rng_next(), m8_rng_next());

    return 0;
}

#endif /* M8_HOST_TEST */

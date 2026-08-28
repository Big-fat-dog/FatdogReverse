/* libm8.so ——「以签为钥」（签名校验对抗 · L46，主打关卡）
 * L4 派生型：密钥 = SHA256(certDER ‖ "Fatdog_bind")，直接作 HMAC-SHA256 签名。
 * 没有任何 if 判断签名对错——重打包者的证书派生出的 key 必然不同，服务端全部 403 零提示。
 * 基准 certHash（原包 DER 的 SHA-256）以 ^0x66 异或存放，首次使用时才还原。
 * Java 只调 nativeKeySeed(der) 拿派生密钥字节 + nativeSign(page, ts) 拿 hex 签名。
 * 正解唯一：spawn 后 hook MessageDigest 出口（或 m8 导出三联单）拿 App 运行时算出的
 * 真实 certHash，带真哈希离线复刻整条链取数。
 */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

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

/* "Fatdog_bind" ^0x3C ——运行时解码，静态无明文 */
static const unsigned char MARK_X[] = {
    122,93,72,88,83,91,99,94,85,82,88
};
#define MARK_LEN 11

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

/* ---------- 派生密钥: SHA256(certDER ‖ marker) ---------- */

static unsigned char g_key[32];   /* 派生密钥（完整 32 字节） */
static int g_key_ready = 0;

static void m8_derive_key(const unsigned char *der, unsigned int der_len) {
    unsigned char *buf = (unsigned char *)malloc(der_len + MARK_LEN);
    if (!buf) return;
    memcpy(buf, der, der_len);
    int i;
    for (i = 0; i < MARK_LEN; i++)
        buf[der_len + i] = (unsigned char)(MARK_X[i] ^ 0x3C);  /* 解码 marker */
    m8_sha256(buf, der_len + MARK_LEN, g_key);
    free(buf);
    g_key_ready = 1;
}

#ifndef M8_HOST_TEST

/* nativeKeySeed: 传入 DER → 计算派生密钥 → 返回 32 字节派生密钥 */
JNIEXPORT jbyteArray JNICALL
Java_com_fatdog_reverse_Wg_nativeKeySeed(JNIEnv *env, jclass clazz, jbyteArray der) {
    jbyteArray result;
    (void)clazz;
    if (!der) return NULL;
    jsize len = (*env)->GetArrayLength(env, der);
    jbyte *p = (*env)->GetByteArrayElements(env, der, NULL);
    if (!p) return NULL;

    if (!g_bench_ready) m8_unlock_bench();
    m8_derive_key((const unsigned char *)p, (unsigned int)len);
    (*env)->ReleaseByteArrayElements(env, der, p, JNI_ABORT);

    result = (*env)->NewByteArray(env, 32);
    if (result)
        (*env)->SetByteArrayRegion(env, result, 0, 32, (jbyte *)g_key);
    return result;
}

/* nativeSign: HMAC-SHA256(g_key, "page=N&ts=T") → hex string */
JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Wg_nativeSign(JNIEnv *env, jclass clazz,
                                       jint page, jlong ts) {
    (void)clazz;
    char msg[64];
    int mlen = snprintf(msg, sizeof(msg), "page=%d&ts=%lld", page, (long long)ts);
    unsigned char dg[32];
    char hex[65];
    static const char *H = "0123456789abcdef";
    int i;

    m8_hmac_sha256(g_key, 32, (const unsigned char *)msg, (unsigned int)mlen, dg);

    for (i = 0; i < 32; i++) {
        hex[2*i]   = H[dg[i] >> 4];
        hex[2*i+1] = H[dg[i] & 0xF];
    }
    hex[64] = 0;

    return (*env)->NewStringUTF(env, hex);
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

    printf("=== L46 以签为钥 · 本地自测 ===\n");

    /* 用假 DER 做测试 */
    const unsigned char fake_der[] = {0x30,0x82,0x01,0x22,0x30,0x0D,0x06,0x09};
    m8_derive_key(fake_der, sizeof(fake_der));
    for (i = 0; i < 32; i++) {
        hex[2*i]   = H[g_key[i] >> 4];
        hex[2*i+1] = H[g_key[i] & 0xF];
    }
    hex[64] = 0;
    printf("derived_key = %s\n", hex);

    /* 测试 HMAC */
    unsigned char dg[32];
    m8_hmac_sha256(g_key, 32, (const unsigned char *)"page=1&ts=1700000000", 20, dg);
    for (i = 0; i < 32; i++) {
        hex[2*i]   = H[dg[i] >> 4];
        hex[2*i+1] = H[dg[i] & 0xF];
    }
    hex[64] = 0;
    printf("hmac(page=1&ts=1700000000) = %s\n", hex);

    return 0;
}

#endif /* M8_HOST_TEST */

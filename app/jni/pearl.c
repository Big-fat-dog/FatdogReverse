/* libm6.so ——「偷天换日」（签名校验对抗 · L44）
 * 把签名摘要的计算与记账全部下沉 native：
 *   - Java 只递证书 DER 字节（passCert），SHA-256 与基准比对都在本库内完成；
 *   - verdict / ticks 存放在本库全局，Java 层拿不到中间值；
 *   - assertGuard(minTicks) 三连核账：
 *       -1 尚未校验   -2 ticks 踏步（校验函数被整体替换/摘除的典型特征）   -3 verdict 为假
 *     因此 Hook Java 层 MessageDigest 出口彻底失效；
 *     整体替换 passCert/assertGuard 会因 ticks 不再增长而当场现形。
 * 基准哈希以 ^0x66 异或数组存放（非 const 全局，防编译器折叠），
 * 首次使用时才还原到内存——静态分析看到的是一堆乱码字节。
 */
#include <string.h>
#include <stdio.h>

#ifndef M6_HOST_TEST
#include <jni.h>
#endif

/* 信任基准：原版 APK 证书 DER 的 SHA-256（原始 32 字节），^0x66 藏匿 */
/* 非 static：强制真实落盘，防编译器用解密结果整体替换存储 */
unsigned char BENCH_X[32] = {
        0x5d,0xd4,0x75,0x2a,0xc5,0xd7,0x6d,0xca,
        0xb2,0x5f,0x03,0xb6,0xe5,0xe8,0x9c,0xf6,
        0x88,0x95,0x10,0x38,0x8b,0xee,0x54,0xf4,
        0xf7,0x0e,0xac,0x68,0x44,0x74,0x51,0x98,
};

static unsigned char g_bench[32];
static int g_bench_ready = 0;
static int g_checked = 0;
static int g_verdict = 0;
static int g_ticks = 0;

static void m6_unlock_bench(void) {
    int i;
    for (i = 0; i < 32; i++) g_bench[i] = (unsigned char)(BENCH_X[i] ^ 0x66);
    g_bench_ready = 1;
}

/* ---------- 标准 SHA-256 ---------- */

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

static unsigned int m6_rotr(unsigned int x, int n) { return (x >> n) | (x << (32 - n)); }

static void m6_sha_block(unsigned int h[8], const unsigned char p[64]) {
    unsigned int w[64];
    unsigned int a,b,c,d,e,f,g,hh,t1,t2,S0,S1,mj;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = ((unsigned int)p[4*i]<<24)|((unsigned int)p[4*i+1]<<16)
             | ((unsigned int)p[4*i+2]<<8)|(unsigned int)p[4*i+3];
    for (i = 16; i < 64; i++) {
        unsigned int s0 = m6_rotr(w[i-15],7) ^ m6_rotr(w[i-15],18) ^ (w[i-15]>>3);
        unsigned int s1 = m6_rotr(w[i-2],17) ^ m6_rotr(w[i-2],19) ^ (w[i-2]>>10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a=h[0];b=h[1];c=h[2];d=h[3];e=h[4];f=h[5];g=h[6];hh=h[7];
    for (i = 0; i < 64; i++) {
        S1 = m6_rotr(e,6)^m6_rotr(e,11)^m6_rotr(e,25);
        t1 = hh + S1 + ((e&f)^((~e)&g)) + K256[i] + w[i];
        S0 = m6_rotr(a,2)^m6_rotr(a,13)^m6_rotr(a,22);
        mj = (a&b)^(a&c)^(b&c);
        t2 = S0 + mj;
        hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
}

static void m6_sha256(const unsigned char *msg, unsigned int len, unsigned char out[32]) {
    unsigned int h[8];
    unsigned int off, rem, tlen, i;
    unsigned char tail[128];
    unsigned long long bits = (unsigned long long)len * 8ULL;
    h[0]=0x6a09e667;h[1]=0xbb67ae85;h[2]=0x3c6ef372;h[3]=0xa54ff53a;
    h[4]=0x510e527f;h[5]=0x9b05688c;h[6]=0x1f83d9ab;h[7]=0x5be0cd19;
    for (off = 0; off + 64 <= len; off += 64)
        m6_sha_block(h, msg + off);
    rem = len - off;
    memset(tail, 0, sizeof(tail));
    memcpy(tail, msg + off, rem);
    tail[rem] = 0x80;
    tlen = (rem + 9 <= 64) ? 64 : 128;
    for (i = 0; i < 8; i++)
        tail[tlen - 1 - i] = (unsigned char)((bits >> (8 * i)) & 0xFF);
    m6_sha_block(h, tail);
    if (tlen == 128) m6_sha_block(h, tail + 64);
    for (i = 0; i < 8; i++) {
        out[4*i]   = (unsigned char)(h[i]>>24);
        out[4*i+1] = (unsigned char)(h[i]>>16);
        out[4*i+2] = (unsigned char)(h[i]>>8);
        out[4*i+3] = (unsigned char)(h[i]);
    }
}

#ifdef M6_HOST_TEST
static void m6_hex(const unsigned char *d, int n, char *out) {
    static const char *H = "0123456789abcdef";
    int i;
    for (i = 0; i < n; i++) {
        out[2*i] = H[d[i] >> 4];
        out[2*i+1] = H[d[i] & 0xF];
    }
    out[2*n] = 0;
}
#endif

#ifndef M6_HOST_TEST

/* 递入证书 DER：记账 + 摘要 + 比对，全程不出本库 */
JNIEXPORT void JNICALL
Java_com_fatdog_reverse_Wk_passCert(JNIEnv *env, jclass clazz, jbyteArray der) {
    jsize len;
    jbyte *p;
    unsigned char dg[32];
    (void)clazz;
    g_ticks++;
    if (!g_bench_ready) m6_unlock_bench();
    if (!der) { g_checked = 1; g_verdict = 0; return; }
    len = (*env)->GetArrayLength(env, der);
    p = (*env)->GetByteArrayElements(env, der, NULL);
    if (!p) { g_checked = 1; g_verdict = 0; return; }
    m6_sha256((const unsigned char *)p, (unsigned int)len, dg);
    (*env)->ReleaseByteArrayElements(env, der, p, JNI_ABORT);
    g_verdict = (memcmp(dg, g_bench, 32) == 0) ? 1 : 0;
    g_checked = 1;
}

/* 三连核账：返回 0=放行，-1=未校验，-2=ticks 踏步，-3=verdict 假 */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Wk_assertGuard(JNIEnv *env, jclass clazz, jint minTicks) {
    (void)env;(void)clazz;
    if (!g_checked) return -1;
    if (g_ticks < minTicks) return -2;
    if (!g_verdict) return -3;
    return 0;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm;(void)reserved;
    return JNI_VERSION_1_6;
}

#else /* M6_HOST_TEST */

int main(void) {
    char hex[65];
    unsigned char dg[32];
    m6_unlock_bench();
    m6_hex(g_bench, 32, hex);
    printf("bench = %s\n", hex);
    /* SHA-256 标准向量自测 */
    m6_sha256((const unsigned char *)"abc", 3, dg);
    m6_hex(dg, 32, hex);
    printf("sha256(abc) = %s\n", hex);
    return 0;
}

#endif /* M6_HOST_TEST */

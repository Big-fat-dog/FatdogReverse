/* libviola.so ——「金蝉脱壳」（KL17 · 太玄之初：二代壳·类抽取）
 * 仿 360 加固保：把「类抽取」的标记拆成 4 段密文，散布在不同函数/rodata 段，
 * stub「加载」时把各段回填拼回完整标记（模拟类抽取回填）。对应真实：360 把方法体
 * 抽空、运行时 native 还原；脱壳用 FART/youpk 主动调用 + 还原点 dump。
 *
 * 设计要点（按新规范）：
 *  - 标准算法、不魔改：SHA-256 与 HMAC-SHA256 均为标准实现（难度递增，前三关不打血）。
 *  - 类抽取模拟：真标记 Fatdog_reclaim 拆成 4 段（ENC_0..3），每段 rot+xor 密钥不同，
 *    分别藏在 fill_seg0..3 四个函数里；JNI_OnLoad（=stub「加载」）调 refill_marker()
 *    把四段拼回 g_mark（运行时才完整，DEX 不落盘）。
 *  - 真标记：Fatdog_reclaim ；明文诱饵（一字之差）：Fatdog_reclaims 。
 *  - 网络层：KEY = SHA256(<标记> + "kl17")[:32]，对 "page=N&ts=T" 做 HMAC-SHA256 签名
 *    （与 /api/kl17 对拍；同 KL16 不同，本关不再额外 AES 加密请求体）。
 */
#include <string.h>
#include <cstdio>

#ifndef VIOLA_HOST_TEST
#include <jni.h>
#endif

/* ---------- 标记分片存储（类抽取：4 段散布不同函数，各段旋转/异或密钥不同） ---------- */
static const char DECOY_MARK[] = "Fatdog_reclaims";  /* strings 可见，差一个字母 */
static char g_mark[64];
static int g_mark_len = 0;

static unsigned char v_rol8(unsigned char b, int n) {
    return (unsigned char)(((b << n) | (b >> (8 - n))) & 0xFF);
}
static unsigned char v_ror8(unsigned char b, int n) {
    return (unsigned char)(((b >> n) | (b << (8 - n))) & 0xFF);
}

/* 段0 = "Fatd"：rot1 + KEY_0 */
static const unsigned char ENC_0[4] = {0xb0, 0x98, 0xc9, 0xb6};
static const unsigned char KEY_0[4] = {0x3C, 0x5A, 0x21, 0x7E};
/* 段1 = "og_r"：rot3 + KEY_1 */
static const unsigned char ENC_1[4] = {0x21, 0x07, 0x84, 0xb2};
static const unsigned char KEY_1[4] = {0x5A, 0x3C, 0x7E, 0x21};
/* 段2 = "ecl" ：rot2 + KEY_2 */
static const unsigned char ENC_2[3] = {0xb4, 0xf3, 0x8d};
static const unsigned char KEY_2[3] = {0x21, 0x7E, 0x3C};
/* 段3 = "aim" ：rot4 + KEY_3 */
static const unsigned char ENC_3[3] = {0x68, 0xb7, 0x8c};
static const unsigned char KEY_3[3] = {0x7E, 0x21, 0x5A};

/* 每个 fill 函数独立还原一段（模拟被抽取的方法体各自还原、回填到类） */
static void fill_seg0(char *out, int *len) {
    int i; for (i = 0; i < (int)sizeof(ENC_0); i++)
        out[i] = (char)v_ror8((unsigned char)(ENC_0[i] ^ KEY_0[i % 4]), 1);
    *len = (int)sizeof(ENC_0);
}
static void fill_seg1(char *out, int *len) {
    int i; for (i = 0; i < (int)sizeof(ENC_1); i++)
        out[i] = (char)v_ror8((unsigned char)(ENC_1[i] ^ KEY_1[i % 4]), 3);
    *len = (int)sizeof(ENC_1);
}
static void fill_seg2(char *out, int *len) {
    int i; for (i = 0; i < (int)sizeof(ENC_2); i++)
        out[i] = (char)v_ror8((unsigned char)(ENC_2[i] ^ KEY_2[i % 4]), 2);
    *len = (int)sizeof(ENC_2);
}
static void fill_seg3(char *out, int *len) {
    int i; for (i = 0; i < (int)sizeof(ENC_3); i++)
        out[i] = (char)v_ror8((unsigned char)(ENC_3[i] ^ KEY_3[i % 4]), 4);
    *len = (int)sizeof(ENC_3);
}

/* stub「加载」：把四段回填拼回完整标记（类抽取回填） */
static void refill_marker(void) {
    int off = 0, n;
    fill_seg0(g_mark + off, &n); off += n;
    fill_seg1(g_mark + off, &n); off += n;
    fill_seg2(g_mark + off, &n); off += n;
    fill_seg3(g_mark + off, &n); off += n;
    g_mark_len = off;
    g_mark[off] = 0;
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
static unsigned int v_rotr(unsigned int x, int n) { return (x >> n) | (x << (32 - n)); }
static void v_sha_block(unsigned int h[8], const unsigned char p[64]) {
    unsigned int w[64]; unsigned int a,b,c,d,e,f,g,hh,t1,t2,S0,S1,mj; int i;
    for (i = 0; i < 16; i++)
        w[i] = ((unsigned int)p[4*i]<<24)|((unsigned int)p[4*i+1]<<16)
             | ((unsigned int)p[4*i+2]<<8)|(unsigned int)p[4*i+3];
    for (i = 16; i < 64; i++) {
        unsigned int s0 = v_rotr(w[i-15],7) ^ v_rotr(w[i-15],18) ^ (w[i-15]>>3);
        unsigned int s1 = v_rotr(w[i-2],17) ^ v_rotr(w[i-2],19) ^ (w[i-2]>>10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a=h[0];b=h[1];c=h[2];d=h[3];e=h[4];f=h[5];g=h[6];hh=h[7];
    for (i = 0; i < 64; i++) {
        S1 = v_rotr(e,6)^v_rotr(e,11)^v_rotr(e,25);
        t1 = hh + S1 + ((e&f)^((~e)&g)) + K256[i] + w[i];
        S0 = v_rotr(a,2)^v_rotr(a,13)^v_rotr(a,22);
        mj = (a&b)^(a&c)^(b&c);
        t2 = S0 + mj;
        hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
}
static void v_sha256(const unsigned char *msg, unsigned int len, unsigned char out[32]) {
    unsigned int h[8]; unsigned int off; unsigned char tail[128];
    unsigned int rem, tlen, i; unsigned long long bits = (unsigned long long)len * 8ULL;
    h[0]=0x6a09e667;h[1]=0xbb67ae85;h[2]=0x3c6ef372;h[3]=0xa54ff53a;
    h[4]=0x510e527f;h[5]=0x9b05688c;h[6]=0x1f83d9ab;h[7]=0x5be0cd19;
    for (off = 0; off + 64 <= len; off += 64) v_sha_block(h, msg + off);
    rem = len - off; memset(tail, 0, sizeof(tail)); memcpy(tail, msg + off, rem);
    tail[rem] = 0x80; tlen = (rem + 9 <= 64) ? 64 : 128;
    for (i = 0; i < 8; i++) tail[tlen - 1 - i] = (unsigned char)((bits >> (8 * i)) & 0xFF);
    v_sha_block(h, tail);
    if (tlen == 128) v_sha_block(h, tail + 64);
    for (i = 0; i < 8; i++) { out[4*i]=h[i]>>24; out[4*i+1]=h[i]>>16; out[4*i+2]=h[i]>>8; out[4*i+3]=h[i]; }
}
static void v_hmac_sha256(const unsigned char *key, unsigned int klen,
                          const unsigned char *msg, unsigned int mlen, unsigned char out[32]) {
    unsigned char k0[64], ipad[64], opad[64], ih[32], buf[192]; unsigned int i;
    memset(k0, 0, sizeof(k0));
    if (klen > 64) v_sha256(key, klen, k0); else memcpy(k0, key, klen);
    for (i = 0; i < 64; i++) { ipad[i] = k0[i] ^ 0x36; opad[i] = k0[i] ^ 0x5c; }
    if (mlen > 120) mlen = 120;
    memcpy(buf, ipad, 64); memcpy(buf + 64, msg, mlen); v_sha256(buf, 64 + mlen, ih);
    memcpy(buf, opad, 64); memcpy(buf + 64, ih, 32); v_sha256(buf, 96, out);
}
static void v_hex_encode(const unsigned char *d, int n, char *out) {
    static const char *HEX = "0123456789abcdef"; int i;
    for (i = 0; i < n; i++) { out[2*i] = HEX[d[i]>>4]; out[2*i+1] = HEX[d[i]&0xF]; } out[2*n] = 0;
}

/* 生成签名：KEY = SHA256(<标记> + "kl17")[:32]，HMAC-SHA256(KEY, "page=N&ts=T") */
static void viola_sign(int page, long long ts, char hex[65]) {
    unsigned char key[32], dg[32]; char mk[64]; int ml = g_mark_len;
    char msg[64]; int n, i;
    if (ml > 60) ml = 60;
    memcpy(mk, g_mark, (size_t)ml); memcpy(mk + ml, "kl17", 4);
    v_sha256((const unsigned char *)mk, (unsigned int)(ml + 4), key);
    n = snprintf(msg, sizeof(msg), "page=%d&ts=%lld", page, ts);
    if (n < 0) n = 0; if (n > 63) n = 63;
    v_hmac_sha256(key, 32, (const unsigned char *)msg, (unsigned int)n, dg);
    v_hex_encode(dg, 32, hex);
}

/* ---------- JNI 导出面 ---------- */
#ifndef VIOLA_HOST_TEST
extern "C" {
JNIEXPORT jstring JNICALL Java_com_fatdog_reverse_Wn_nativeSign(JNIEnv *env, jclass clazz, jint page, jlong ts) {
    char hex[65]; (void)clazz; viola_sign((int)page, (long long)ts, hex); return env->NewStringUTF(hex);
}
JNIEXPORT jstring JNICALL Java_com_fatdog_reverse_Wn_nativeMarker(JNIEnv *env, jclass clazz) {
    (void)clazz; return env->NewStringUTF(g_mark);
}
JNIEXPORT jstring JNICALL Java_com_fatdog_reverse_Wn_nativeDecoy(JNIEnv *env, jclass clazz) {
    (void)clazz; return env->NewStringUTF(DECOY_MARK);
}
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm;(void)reserved;
    refill_marker();   /* 类抽取回填：stub「加载」时把四段拼回完整标记 */
    return JNI_VERSION_1_6;
}
}  /* end extern "C" */
#endif

#ifdef VIOLA_HOST_TEST
int main(void) {
    char hex[65];
    refill_marker();
    printf("mark = %s\n", g_mark);
    viola_sign(1, 1787013761LL, hex);
    printf("sample_sign(page=1,ts=1787013761) = %s\n", hex);
    printf("expect                             = 865e2cf5e2d7cbe0690730bfc511fd06e995c41a97cc897176b953acbfac0e97\n");
    return 0;
}
#endif

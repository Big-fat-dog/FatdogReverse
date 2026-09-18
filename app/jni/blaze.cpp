/* libblaze.so ——「乾坤迷阵」（KL18 · 太玄之初：二代壳·方法抽取）
 * 仿梆梆方法抽取：真标记的**每个字节**视作一个被抽走的「方法体」，运行时缓冲区先被
 * nop 填满，只有走到「还原点」时才逐条填回；且后一字节的还原依赖前一字节（像指令
 * 被一条条翻译回去）。对应真实：梆梆把方法体 nop/抽空、由 native 在调用前还原；
 * 脱壳要在还原函数上 hook，或用 FART/youpk 主动调用触发还原后再 dump。
 *
 * 与 KL17（类抽取）的递进差异：
 *  - KL17：4 段整体，在 JNI_OnLoad（stub「加载」）时一次性回填；
 *  - KL18：14 个字节逐条，加载时**不还原**（缓冲区仍是 nop），
 *    必须等「还原点」被调用（nativeSign/nativeMarker 内部）才逐条填回。
 *  → 静态 dump 只看到 nop；只有主动触发还原（或 hook 还原点）才拿得到真标记。
 *
 * 设计要点（按新规范）：
 *  - 标准算法、不魔改：SHA-256 / HMAC-SHA256 均为标准实现（前三关不打血）。
 *  - 真标记：Fatdog_reweave ；明文诱饵（一字之差）：Fatdog_reweaves 。
 *  - 网络层：KEY = SHA256(<标记> + "kl18")[:32]，对 "page=N&ts=T" 做 HMAC-SHA256 签名
 *    （与 /api/kl18 对拍；同 KL17 一样不再 AES 加密请求体）。
 */
#include <string.h>
#include <cstdio>

#ifndef BLAZE_HOST_TEST
#include <jni.h>
#endif

/* ---------- 被抽走的「方法体」：标记逐字节密文（顺序依赖） ---------- */
/* EXTRACTED[i] = mark[i] ^ ks(i) ^ (i==0 ? 0x3C : mark[i-1])，ks(i)=(0x5B+41*i)&0xFF */
static const unsigned char EXTRACTED[14] = {
    0x21, 0xa3, 0xb8, 0xc6, 0xf4, 0x20, 0x69, 0x57,
    0xb4, 0xde, 0xe7, 0x1a, 0x50, 0x63
};
#define MARK_LEN 14
#define NOP_FILL 0xFF   /* 抽空后填充的 nop 字节 */

static const char DECOY_MARK[] = "Fatdog_reweaves";  /* strings 可见，差一个字母 */

/* 运行时缓冲区：加载时全是 nop，还原点走过后才是真标记（.bss，DEX 不落盘） */
static char g_mark[64];
static int g_mark_len = 0;

static unsigned char bl_ks(int i) {
    return (unsigned char)((0x5B + 41 * i) & 0xFF);
}

/* stub「加载」：只把缓冲区填成 nop，此时标记仍是抽空状态 */
static void nop_fill(void) {
    int i;
    for (i = 0; i < (int)sizeof(g_mark); i++) g_mark[i] = (char)NOP_FILL;
    g_mark_len = 0;
}

/* ---- 还原点：逐条把被抽走的「方法体」填回（后一条依赖前一条） ---- */
static void restore_point(int idx, unsigned char *prev) {
    unsigned char v = (unsigned char)(EXTRACTED[idx] ^ bl_ks(idx) ^ *prev);
    g_mark[idx] = (char)v;
    *prev = v;
}

/* 还原点入口：把整段抽空的方法体走一遍还原点填回（「调用前」触发） */
static void restore_all(void) {
    unsigned char prev = 0x3C;
    int i;
    for (i = 0; i < MARK_LEN; i++) restore_point(i, &prev);
    g_mark_len = MARK_LEN;
    g_mark[MARK_LEN] = 0;
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
static unsigned int bl_rotr(unsigned int x, int n) { return (x >> n) | (x << (32 - n)); }
static void bl_sha_block(unsigned int h[8], const unsigned char p[64]) {
    unsigned int w[64]; unsigned int a,b,c,d,e,f,g,hh,t1,t2,S0,S1,mj; int i;
    for (i = 0; i < 16; i++)
        w[i] = ((unsigned int)p[4*i]<<24)|((unsigned int)p[4*i+1]<<16)
             | ((unsigned int)p[4*i+2]<<8)|(unsigned int)p[4*i+3];
    for (i = 16; i < 64; i++) {
        unsigned int s0 = bl_rotr(w[i-15],7) ^ bl_rotr(w[i-15],18) ^ (w[i-15]>>3);
        unsigned int s1 = bl_rotr(w[i-2],17) ^ bl_rotr(w[i-2],19) ^ (w[i-2]>>10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a=h[0];b=h[1];c=h[2];d=h[3];e=h[4];f=h[5];g=h[6];hh=h[7];
    for (i = 0; i < 64; i++) {
        S1 = bl_rotr(e,6)^bl_rotr(e,11)^bl_rotr(e,25);
        t1 = hh + S1 + ((e&f)^((~e)&g)) + K256[i] + w[i];
        S0 = bl_rotr(a,2)^bl_rotr(a,13)^bl_rotr(a,22);
        mj = (a&b)^(a&c)^(b&c);
        t2 = S0 + mj;
        hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
}
static void bl_sha256(const unsigned char *msg, unsigned int len, unsigned char out[32]) {
    unsigned int h[8]; unsigned int off; unsigned char tail[128];
    unsigned int rem, tlen, i; unsigned long long bits = (unsigned long long)len * 8ULL;
    h[0]=0x6a09e667;h[1]=0xbb67ae85;h[2]=0x3c6ef372;h[3]=0xa54ff53a;
    h[4]=0x510e527f;h[5]=0x9b05688c;h[6]=0x1f83d9ab;h[7]=0x5be0cd19;
    for (off = 0; off + 64 <= len; off += 64) bl_sha_block(h, msg + off);
    rem = len - off; memset(tail, 0, sizeof(tail)); memcpy(tail, msg + off, rem);
    tail[rem] = 0x80; tlen = (rem + 9 <= 64) ? 64 : 128;
    for (i = 0; i < 8; i++) tail[tlen - 1 - i] = (unsigned char)((bits >> (8 * i)) & 0xFF);
    bl_sha_block(h, tail);
    if (tlen == 128) bl_sha_block(h, tail + 64);
    for (i = 0; i < 8; i++) { out[4*i]=h[i]>>24; out[4*i+1]=h[i]>>16; out[4*i+2]=h[i]>>8; out[4*i+3]=h[i]; }
}
static void bl_hmac_sha256(const unsigned char *key, unsigned int klen,
                           const unsigned char *msg, unsigned int mlen, unsigned char out[32]) {
    unsigned char k0[64], ipad[64], opad[64], ih[32], buf[192]; unsigned int i;
    memset(k0, 0, sizeof(k0));
    if (klen > 64) bl_sha256(key, klen, k0); else memcpy(k0, key, klen);
    for (i = 0; i < 64; i++) { ipad[i] = k0[i] ^ 0x36; opad[i] = k0[i] ^ 0x5c; }
    if (mlen > 120) mlen = 120;
    memcpy(buf, ipad, 64); memcpy(buf + 64, msg, mlen); bl_sha256(buf, 64 + mlen, ih);
    memcpy(buf, opad, 64); memcpy(buf + 64, ih, 32); bl_sha256(buf, 96, out);
}
static void bl_hex_encode(const unsigned char *d, int n, char *out) {
    static const char *HEX = "0123456789abcdef"; int i;
    for (i = 0; i < n; i++) { out[2*i] = HEX[d[i]>>4]; out[2*i+1] = HEX[d[i]&0xF]; } out[2*n] = 0;
}

/* 生成签名：先走还原点把抽空的方法体填回，再派生钥匙签名 */
static void blaze_sign(int page, long long ts, char hex[65]) {
    unsigned char key[32], dg[32]; char mk[64]; int ml = g_mark_len;
    char msg[64]; int n;
    restore_all();                       /* 还原点：调用前逐条填回 */
    ml = g_mark_len;
    if (ml > 60) ml = 60;
    memcpy(mk, g_mark, (size_t)ml); memcpy(mk + ml, "kl18", 4);
    bl_sha256((const unsigned char *)mk, (unsigned int)(ml + 4), key);
    n = snprintf(msg, sizeof(msg), "page=%d&ts=%lld", page, ts);
    if (n < 0) n = 0; if (n > 63) n = 63;
    bl_hmac_sha256(key, 32, (const unsigned char *)msg, (unsigned int)n, dg);
    bl_hex_encode(dg, 32, hex);
}

/* ---------- JNI 导出面 ---------- */
#ifndef BLAZE_HOST_TEST
extern "C" {
JNIEXPORT jstring JNICALL Java_com_fatdog_reverse_Fk_nativeSign(JNIEnv *env, jclass clazz, jint page, jlong ts) {
    char hex[65]; (void)clazz; blaze_sign((int)page, (long long)ts, hex); return env->NewStringUTF(hex);
}
JNIEXPORT jstring JNICALL Java_com_fatdog_reverse_Fk_nativeMarker(JNIEnv *env, jclass clazz) {
    (void)clazz; restore_all(); return env->NewStringUTF(g_mark);   /* 主动调用即触发还原 */
}
JNIEXPORT jstring JNICALL Java_com_fatdog_reverse_Fk_nativeDecoy(JNIEnv *env, jclass clazz) {
    (void)clazz; return env->NewStringUTF(DECOY_MARK);
}
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm;(void)reserved;
    nop_fill();   /* 加载时只填 nop——标记此刻仍是抽空状态，等还原点 */
    return JNI_VERSION_1_6;
}
}  /* end extern "C" */
#endif

#ifdef BLAZE_HOST_TEST
int main(void) {
    char hex[65]; int i;
    nop_fill();
    printf("after load : ");
    for (i = 0; i < MARK_LEN; i++) printf("%02x", (unsigned char)g_mark[i]);
    printf("  (nop-filled, len=%d)\n", g_mark_len);
    restore_all();
    printf("mark = %s\n", g_mark);
    blaze_sign(1, 1787013761LL, hex);
    printf("sample_sign(page=1,ts=1787013761) = %s\n", hex);
    printf("expect                             = 77ea63593ceee6461abb675279fcd7831e32a235c9e35b0e2dfc1723d22dff69\n");
    return 0;
}
#endif

/* libbison.so ——「虚空造化」（KL19 · 太玄之初：二代综合·指令抽取 + 反调试 + SO 自校验）
 * 在 KL18 方法抽取之上叠加 **so 内反调试与完整性自检**：还原逻辑被保护起来，
 * 一旦判定处于被调试/被篡改环境，就把还原出的标记抹掉（签名随之失效）。
 * 对应真实：二代壳把抽取还原逻辑塞进受保护的 so，再加反调试与反 Hook。
 *
 * 与 KL18 的差异：KL18 只管「抽空→还原点填回」；KL19 在还原点外面裹了一层哨兵，
 * 玩家必须先让哨兵失明（bypass 反调试 / 绕过自校验），还原点的内容才拿得到。
 *
 * 设计要点（按新规范）：
 *  - 标准算法、不魔改：SHA-256 / HMAC-SHA256 / CRC32 均为标准实现。
 *  - 还原点：与 KL18 同构的链式填回（后一字节依赖前一字节），参数不同。
 *  - 真标记：Fatdog_rekindle ；明文诱饵（一字之差）：Fatdog_rekindles 。
 *  - 网络层：KEY = SHA256(<标记> + "kl19")[:32]，对 "page=N&ts=T" 做 HMAC-SHA256 签名。
 *
 * 反调试评分（防误报，SKILL 32/33）：五个信号各记 1 分，**命中 ≥2 项才判定被调试**。
 * 这样单一信号的误报（例如某些 ROM 的 seccomp 让 ptrace 直接返回 EPERM）不会误杀正常玩家。
 *   ① ptrace(PTRACE_TRACEME) 自占坑失败（errno==EPERM）
 *   ② /proc/self/status 的 TracerPid != 0
 *   ③ connect 127.0.0.1:27042 成功（Frida 默认端口）
 *   ④ /proc/self/maps 含 frida / gadget / gum 指纹
 *   ⑤ CRC32(EXTRACTED) 与烘焙基线不符（SO 自校验：表被 patch 过）
 */
#include <string.h>
#include <cstdio>
#include <cstdlib>

#ifndef BISON_HOST_TEST
#include <jni.h>
#endif

/* ---------- 被抽走的「方法体」：标记逐字节密文（顺序依赖） ---------- */
/* EXTRACTED[i] = mark[i] ^ ks(i) ^ prev，ks(i)=(0x3F+53*i)&0xFF，首字节前导 0x5A */
static const unsigned char EXTRACTED[15] = {
    0x23, 0x53, 0xbc, 0xce, 0x18, 0x40, 0x45, 0x9f,
    0xf0, 0x12, 0x53, 0x81, 0xb1, 0xf8, 0x2c
};
#define MARK_LEN 15
#define NOP_FILL 0xFF

/* SO 自校验基线：CRC32(EXTRACTED)，离线算好烘进 rodata */
#define CRC_BASELINE 0x53006fcdU

static const char DECOY_MARK[] = "Fatdog_rekindles";  /* strings 可见，差一个字母 */

static char g_mark[64];
static int g_mark_len = 0;

/* ---------- 标准 CRC32（IEEE，poly 0xEDB88320，与 zlib 一致） ---------- */
static unsigned int bs_crc32(const unsigned char *d, int n) {
    unsigned int c = 0xFFFFFFFFU; int i, k;
    for (i = 0; i < n; i++) {
        c ^= d[i];
        for (k = 0; k < 8; k++)
            c = (c & 1u) ? ((c >> 1) ^ 0xEDB88320U) : (c >> 1);
    }
    return c ^ 0xFFFFFFFFU;
}

/* ---------- 反调试 + 自校验（仅真机；宿主自测用空实现） ---------- */
#ifndef BISON_HOST_TEST
#include <errno.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int bs_hit_ptrace(void) {
    long r = ptrace(PTRACE_TRACEME, 0, 0, 0);
    if (r == -1 && errno == EPERM) return 1;   /* 已被占坑 */
    return 0;
}
static int bs_hit_tracerpid(void) {
    FILE *f = fopen("/proc/self/status", "r");
    char line[256]; int v = 0;
    if (!f) return 0;
    while (fgets(line, sizeof(line), f)) {
        if (!strncmp(line, "TracerPid:", 10)) { v = atoi(line + 10); break; }
    }
    fclose(f);
    return v != 0 ? 1 : 0;
}
static int bs_hit_frida_port(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a; int rc = -1;
    if (fd < 0) return 0;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(27042);
    a.sin_addr.s_addr = inet_addr("127.0.0.1");
    rc = connect(fd, (struct sockaddr *)&a, sizeof(a));
    close(fd);
    return rc == 0 ? 1 : 0;
}
static int bs_hit_maps(void) {
    FILE *f = fopen("/proc/self/maps", "r");
    char line[512]; int hit = 0;
    if (!f) return 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "frida") || strstr(line, "gadget") || strstr(line, "gum")) { hit = 1; break; }
    }
    fclose(f);
    return hit;
}
static int bs_guard_hits(void) {
    int h = 0;
    h += bs_hit_ptrace();
    h += bs_hit_tracerpid();
    h += bs_hit_frida_port();
    h += bs_hit_maps();
    h += (bs_crc32(EXTRACTED, MARK_LEN) != CRC_BASELINE) ? 1 : 0;
    return h;
}
static void bs_guard_detail(char out[128]) {
    int n = 0;
    out[0] = 0;
    if (bs_hit_ptrace())    n += snprintf(out + n, 128 - n, "ptrace,");
    if (bs_hit_tracerpid()) n += snprintf(out + n, 128 - n, "tracerpid,");
    if (bs_hit_frida_port())n += snprintf(out + n, 128 - n, "port27042,");
    if (bs_hit_maps())      n += snprintf(out + n, 128 - n, "maps,");
    if (bs_crc32(EXTRACTED, MARK_LEN) != CRC_BASELINE)
                            n += snprintf(out + n, 128 - n, "crc,");
    if (n > 0 && out[n - 1] == ',') out[n - 1] = 0;
}
#else
static int bs_guard_hits(void) { return 0; }          /* 宿主自测：不跑反调试 */
static void bs_guard_detail(char out[128]) { out[0] = 0; }
#endif

/* 判定：命中 ≥2 项才算被调试（防单项误报） */
#define GUARD_THRESHOLD 2
static int g_guard_cached = -1;
static int bs_guard_tripped(void) {
    if (g_guard_cached < 0) g_guard_cached = (bs_guard_hits() >= GUARD_THRESHOLD) ? 1 : 0;
    return g_guard_cached;
}

/* ---------- 还原点 ---------- */
static unsigned char bs_ks(int i) {
    return (unsigned char)((0x3F + 53 * i) & 0xFF);
}
static void nop_fill(void) {
    int i;
    for (i = 0; i < (int)sizeof(g_mark); i++) g_mark[i] = (char)NOP_FILL;
    g_mark_len = 0;
}
static void restore_all(void) {
    unsigned char prev = 0x5A; int i;
    for (i = 0; i < MARK_LEN; i++) {
        unsigned char v = (unsigned char)(EXTRACTED[i] ^ bs_ks(i) ^ prev);
        g_mark[i] = (char)v; prev = v;
    }
    g_mark_len = MARK_LEN; g_mark[MARK_LEN] = 0;
}
/* 哨兵判定成立 → 抹掉刚还原出来的标记（签名随之失效） */
static void wipe_mark(void) {
    int i;
    for (i = 0; i < MARK_LEN; i++) g_mark[i] = 'x';
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
static unsigned int bs_rotr(unsigned int x, int n) { return (x >> n) | (x << (32 - n)); }
static void bs_sha_block(unsigned int h[8], const unsigned char p[64]) {
    unsigned int w[64]; unsigned int a,b,c,d,e,f,g,hh,t1,t2,S0,S1,mj; int i;
    for (i = 0; i < 16; i++)
        w[i] = ((unsigned int)p[4*i]<<24)|((unsigned int)p[4*i+1]<<16)
             | ((unsigned int)p[4*i+2]<<8)|(unsigned int)p[4*i+3];
    for (i = 16; i < 64; i++) {
        unsigned int s0 = bs_rotr(w[i-15],7) ^ bs_rotr(w[i-15],18) ^ (w[i-15]>>3);
        unsigned int s1 = bs_rotr(w[i-2],17) ^ bs_rotr(w[i-2],19) ^ (w[i-2]>>10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a=h[0];b=h[1];c=h[2];d=h[3];e=h[4];f=h[5];g=h[6];hh=h[7];
    for (i = 0; i < 64; i++) {
        S1 = bs_rotr(e,6)^bs_rotr(e,11)^bs_rotr(e,25);
        t1 = hh + S1 + ((e&f)^((~e)&g)) + K256[i] + w[i];
        S0 = bs_rotr(a,2)^bs_rotr(a,13)^bs_rotr(a,22);
        mj = (a&b)^(a&c)^(b&c);
        t2 = S0 + mj;
        hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
}
static void bs_sha256(const unsigned char *msg, unsigned int len, unsigned char out[32]) {
    unsigned int h[8]; unsigned int off; unsigned char tail[128];
    unsigned int rem, tlen, i; unsigned long long bits = (unsigned long long)len * 8ULL;
    h[0]=0x6a09e667;h[1]=0xbb67ae85;h[2]=0x3c6ef372;h[3]=0xa54ff53a;
    h[4]=0x510e527f;h[5]=0x9b05688c;h[6]=0x1f83d9ab;h[7]=0x5be0cd19;
    for (off = 0; off + 64 <= len; off += 64) bs_sha_block(h, msg + off);
    rem = len - off; memset(tail, 0, sizeof(tail)); memcpy(tail, msg + off, rem);
    tail[rem] = 0x80; tlen = (rem + 9 <= 64) ? 64 : 128;
    for (i = 0; i < 8; i++) tail[tlen - 1 - i] = (unsigned char)((bits >> (8 * i)) & 0xFF);
    bs_sha_block(h, tail);
    if (tlen == 128) bs_sha_block(h, tail + 64);
    for (i = 0; i < 8; i++) { out[4*i]=h[i]>>24; out[4*i+1]=h[i]>>16; out[4*i+2]=h[i]>>8; out[4*i+3]=h[i]; }
}
static void bs_hmac_sha256(const unsigned char *key, unsigned int klen,
                           const unsigned char *msg, unsigned int mlen, unsigned char out[32]) {
    unsigned char k0[64], ipad[64], opad[64], ih[32], buf[192]; unsigned int i;
    memset(k0, 0, sizeof(k0));
    if (klen > 64) bs_sha256(key, klen, k0); else memcpy(k0, key, klen);
    for (i = 0; i < 64; i++) { ipad[i] = k0[i] ^ 0x36; opad[i] = k0[i] ^ 0x5c; }
    if (mlen > 120) mlen = 120;
    memcpy(buf, ipad, 64); memcpy(buf + 64, msg, mlen); bs_sha256(buf, 64 + mlen, ih);
    memcpy(buf, opad, 64); memcpy(buf + 64, ih, 32); bs_sha256(buf, 96, out);
}
static void bs_hex_encode(const unsigned char *d, int n, char *out) {
    static const char *HEX = "0123456789abcdef"; int i;
    for (i = 0; i < n; i++) { out[2*i] = HEX[d[i]>>4]; out[2*i+1] = HEX[d[i]&0xF]; } out[2*n] = 0;
}

/* 生成签名：先过哨兵，再走还原点，最后派生钥匙签名 */
static void bison_sign(int page, long long ts, char hex[65]) {
    unsigned char key[32], dg[32]; char mk[64]; int ml;
    char msg[64]; int n;
    restore_all();                     /* 还原点：逐条填回 */
    if (bs_guard_tripped()) wipe_mark();   /* 哨兵判定成立 → 抹掉 */
    ml = g_mark_len; if (ml > 60) ml = 60;
    memcpy(mk, g_mark, (size_t)ml); memcpy(mk + ml, "kl19", 4);
    bs_sha256((const unsigned char *)mk, (unsigned int)(ml + 4), key);
    n = snprintf(msg, sizeof(msg), "page=%d&ts=%lld", page, ts);
    if (n < 0) n = 0; if (n > 63) n = 63;
    bs_hmac_sha256(key, 32, (const unsigned char *)msg, (unsigned int)n, dg);
    bs_hex_encode(dg, 32, hex);
}

/* ---------- JNI 导出面 ---------- */
#ifndef BISON_HOST_TEST
extern "C" {
JNIEXPORT jstring JNICALL Java_com_fatdog_reverse_Gk_nativeSign(JNIEnv *env, jclass clazz, jint page, jlong ts) {
    char hex[65]; (void)clazz; bison_sign((int)page, (long long)ts, hex); return env->NewStringUTF(hex);
}
JNIEXPORT jstring JNICALL Java_com_fatdog_reverse_Gk_nativeMarker(JNIEnv *env, jclass clazz) {
    (void)clazz;
    restore_all();
    if (bs_guard_tripped()) wipe_mark();   /* 主动调用也会触发哨兵 */
    return env->NewStringUTF(g_mark);
}
JNIEXPORT jstring JNICALL Java_com_fatdog_reverse_Gk_nativeDecoy(JNIEnv *env, jclass clazz) {
    (void)clazz; return env->NewStringUTF(DECOY_MARK);
}
/* 只读自检：只报告哨兵命中了哪些信号，不还原、不判胜、不吐标记 */
JNIEXPORT jstring JNICALL Java_com_fatdog_reverse_Gk_nativeStatus(JNIEnv *env, jclass clazz) {
    char det[128]; char out[192]; (void)clazz;
    bs_guard_detail(det);
    snprintf(out, sizeof(out), "guard_hits=%d threshold=%d signals=[%s] %s",
             bs_guard_hits(), GUARD_THRESHOLD, det,
             bs_guard_tripped() ? "TRIPPED" : "clean");
    return env->NewStringUTF(out);
}
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm;(void)reserved;
    nop_fill();   /* 加载时只填 nop——标记此刻仍是抽空状态 */
    return JNI_VERSION_1_6;
}
}  /* end extern "C" */
#endif

#ifdef BISON_HOST_TEST
int main(void) {
    char hex[65]; int i;
    nop_fill();
    printf("after load : ");
    for (i = 0; i < MARK_LEN; i++) printf("%02x", (unsigned char)g_mark[i]);
    printf("  (nop-filled, len=%d)\n", g_mark_len);
    restore_all();
    printf("mark = %s\n", g_mark);
    printf("crc32(EXTRACTED) = 0x%08x (baseline 0x%08x, match=%d)\n",
           bs_crc32(EXTRACTED, MARK_LEN), CRC_BASELINE,
           bs_crc32(EXTRACTED, MARK_LEN) == CRC_BASELINE);
    bison_sign(1, 1787013761LL, hex);
    printf("sample_sign(page=1,ts=1787013761) = %s\n", hex);
    printf("expect                             = 8ff3feebad8060378fc2ef76def0b0403b85ac7954e275226825607740186db7\n");
    return 0;
}
#endif

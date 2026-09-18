/* libdelta.so ——「破壁飞升」（KL20 · 太玄之初：三代壳·腾讯乐固·不落地 + SO 加固 + anti-frida）
 * 仿腾讯乐固：DEX 内存解密不落盘 + SO 自加固（anti-frida + 反篡改综合）。
 * 对应真实：乐固把 DEX 在内存里解密、绝不写回磁盘；脱壳需 bypass anti-frida
 *   （hook open/read/connect 中和 /proc/self/maps 与 27042 端口）→ frida-dexdump(OpenMemory)
 *   → 修 DEX 头（早期乐固仅加密头 0x70 字节）。
 *
 * 本关「不落地」体现：真标记 Fatdog_unsheathe 不在磁盘落明文——静态段只存密文分片 EXTRACTED，
 * 运行时由 mmap 匿名内存持有、走还原点逐字节拼回；磁盘 ELF 里只有诱饵与密文。
 *
 * 设计要点（按新规范，与 KL17-19 同源）：
 *  - 标准算法、不魔改：SHA-256 / HMAC-SHA256 / CRC32 均为标准实现。
 *  - 真标记：Fatdog_unsheathe（16B）；明文诱饵（一字之差）：Fatdog_unsheathes（多一 s）。
 *  - 还原点：链式填回（后一字节依赖前一字节），参数与前几关不同。
 *  - anti-frida：扫 /proc/self/maps 含 frida/gadget/gum、探 127.0.0.1:27042、命名管道
 *    /data/local/tmp/frida-* ；任一命中即记 1 分，≥2 分判定注入、抹掉还原结果（签名失效）。
 *  - 网络层：KEY = SHA256(<标记> + "kl20")[:32]，对 "page=N&ts=T" 做 HMAC-SHA256 签名。
 */
#include <string.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#ifndef DELTA_HOST_TEST
#include <jni.h>
#include <sys/mman.h>
#else
/* 宿主自测：不引 jni/linux 头，用普通 malloc 顶替 mmap */
#endif

/* ---------- 被抽走的「方法体」：标记逐字节密文（顺序依赖，分片存于 rodata，运行时内存拼回） ---------- */
/* EXTRACTED[i] = mark[i] ^ ks(i) ^ prev，ks(i)=(0x55+37*i)&0xFF，首字节前导 0x3C */
static const unsigned char EXTRACTED[16] = {
    0x2F, 0x34, 0xDF, 0x7F, 0xF9, 0x90, 0xFC, 0xD1,
    0xC2, 0x13, 0xBC, 0x35, 0x45, 0x07, 0x34, 0xD1
};
#define MARK_LEN 16
#define NOP_FILL 0xFF

/* SO 自校验基线：CRC32(EXTRACTED)，离线算好烘进 rodata */
#define CRC_BASELINE 0xDCE53BFAU

static const char DECOY_MARK[] = "Fatdog_unsheathes";  /* strings 可见，多一个 s */

/* 不落地缓冲：mmap 匿名内存持有真实标记（绝不落盘） */
static char *g_mark = nullptr;
static int g_mark_len = 0;

static void alloc_mark(void) {
#ifdef DELTA_HOST_TEST
    g_mark = (char*)malloc(64);
#else
    g_mark = (char*)mmap(nullptr, 64, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#endif
    if (!g_mark) g_mark = (char*)malloc(64);
}

/* ---------- 标准 CRC32（IEEE，poly 0xEDB88320，与 zlib 一致） ---------- */
static unsigned int dl_crc32(const unsigned char *d, int n) {
    unsigned int c = 0xFFFFFFFFU; int i, k;
    for (i = 0; i < n; i++) {
        c ^= d[i];
        for (k = 0; k < 8; k++)
            c = (c & 1u) ? ((c >> 1) ^ 0xEDB88320U) : (c >> 1);
    }
    return c ^ 0xFFFFFFFFU;
}

/* ---------- anti-frida + 自校验（仅真机；宿主自测用空实现） ---------- */
#ifndef DELTA_HOST_TEST
#include <errno.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <dirent.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int dl_hit_maps(void) {
    FILE *f = fopen("/proc/self/maps", "r");
    char line[512]; int hit = 0;
    if (!f) return 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "frida") || strstr(line, "gadget") || strstr(line, "gum")) { hit = 1; break; }
    }
    fclose(f);
    return hit;
}
static int dl_hit_frida_port(void) {
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
static int dl_hit_pipe(void) {
    /* 命名管道 /data/local/tmp/frida-* 是 frida-server 注入痕迹 */
    DIR *d = opendir("/data/local/tmp");
    struct dirent *e;
    if (!d) return 0;
    int hit = 0;
    while ((e = readdir(d))) {
        if (!strncmp(e->d_name, "frida", 5)) { hit = 1; break; }
    }
    closedir(d);
    return hit;
}
static int dl_guard_hits(void) {
    int h = 0;
    h += dl_hit_maps();
    h += dl_hit_frida_port();
    h += dl_hit_pipe();
    h += (dl_crc32(EXTRACTED, MARK_LEN) != CRC_BASELINE) ? 1 : 0;
    return h;
}
static void dl_guard_detail(char out[128]) {
    int n = 0;
    out[0] = 0;
    if (dl_hit_maps())       n += snprintf(out + n, 128 - n, "maps,");
    if (dl_hit_frida_port()) n += snprintf(out + n, 128 - n, "port27042,");
    if (dl_hit_pipe())       n += snprintf(out + n, 128 - n, "pipe,");
    if (dl_crc32(EXTRACTED, MARK_LEN) != CRC_BASELINE)
                              n += snprintf(out + n, 128 - n, "crc,");
    if (n > 0 && out[n - 1] == ',') out[n - 1] = 0;
}
#else
static int dl_guard_hits(void) { return 0; }
static void dl_guard_detail(char out[128]) { (void)out; out[0] = 0; }
#endif

#define GUARD_THRESHOLD 2
static int g_guard_cached = -1;
static int dl_guard_tripped(void) {
    if (g_guard_cached < 0) g_guard_cached = (dl_guard_hits() >= GUARD_THRESHOLD) ? 1 : 0;
    return g_guard_cached;
}

/* ---------- 还原点 ---------- */
static unsigned char dl_ks(int i) { return (unsigned char)((0x55 + 37 * i) & 0xFF); }
static void nop_fill(void) {
    int i;
    if (!g_mark) return;
    for (i = 0; i < 64; i++) g_mark[i] = (char)NOP_FILL;
    g_mark_len = 0;
}
static void restore_all(void) {
    unsigned char prev = 0x3C; int i;
    if (!g_mark) return;
    /* 链式还原：prev 跟随「上一字节密文」(EXTRACTED[i-1])，与生成端同链（生成端 prev=v=EX[i]）。
       若用还原值链(=MARK[i])则须同步改生成脚本重算 EXTRACTED，这里选密文链，EXTRACTED/CRC 不变。 */
    for (i = 0; i < MARK_LEN; i++) {
        unsigned char v = (unsigned char)(EXTRACTED[i] ^ dl_ks(i) ^ prev);
        g_mark[i] = (char)v; prev = EXTRACTED[i];
    }
    g_mark_len = MARK_LEN; g_mark[MARK_LEN] = 0;
}
static void wipe_mark(void) {
    int i;
    if (!g_mark) return;
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
static unsigned int dl_rotr(unsigned int x, int n) { return (x >> n) | (x << (32 - n)); }
static void dl_sha_block(unsigned int h[8], const unsigned char p[64]) {
    unsigned int w[64]; unsigned int a,b,c,d,e,f,g,hh,t1,t2,S0,S1,mj; int i;
    for (i = 0; i < 16; i++)
        w[i] = ((unsigned int)p[4*i]<<24)|((unsigned int)p[4*i+1]<<16)
             | ((unsigned int)p[4*i+2]<<8)|(unsigned int)p[4*i+3];
    for (i = 16; i < 64; i++) {
        unsigned int s0 = dl_rotr(w[i-15],7) ^ dl_rotr(w[i-15],18) ^ (w[i-15]>>3);
        unsigned int s1 = dl_rotr(w[i-2],17) ^ dl_rotr(w[i-2],19) ^ (w[i-2]>>10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a=h[0];b=h[1];c=h[2];d=h[3];e=h[4];f=h[5];g=h[6];hh=h[7];
    for (i = 0; i < 64; i++) {
        S1 = dl_rotr(e,6)^dl_rotr(e,11)^dl_rotr(e,25);
        t1 = hh + S1 + ((e&f)^((~e)&g)) + K256[i] + w[i];
        S0 = dl_rotr(a,2)^dl_rotr(a,13)^dl_rotr(a,22);
        mj = (a&b)^(a&c)^(b&c);
        t2 = S0 + mj;
        hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
}
static void dl_sha256(const unsigned char *msg, unsigned int len, unsigned char out[32]) {
    unsigned int h[8]; unsigned int off; unsigned char tail[128];
    unsigned int rem, tlen, i; unsigned long long bits = (unsigned long long)len * 8ULL;
    h[0]=0x6a09e667;h[1]=0xbb67ae85;h[2]=0x3c6ef372;h[3]=0xa54ff53a;
    h[4]=0x510e527f;h[5]=0x9b05688c;h[6]=0x1f83d9ab;h[7]=0x5be0cd19;
    for (off = 0; off + 64 <= len; off += 64) dl_sha_block(h, msg + off);
    rem = len - off; memset(tail, 0, sizeof(tail)); memcpy(tail, msg + off, rem);
    tail[rem] = 0x80; tlen = (rem + 9 <= 64) ? 64 : 128;
    for (i = 0; i < 8; i++) tail[tlen - 1 - i] = (unsigned char)((bits >> (8 * i)) & 0xFF);
    dl_sha_block(h, tail);
    if (tlen == 128) dl_sha_block(h, tail + 64);
    for (i = 0; i < 8; i++) { out[4*i]=h[i]>>24; out[4*i+1]=h[i]>>16; out[4*i+2]=h[i]>>8; out[4*i+3]=h[i]; }
}
static void dl_hmac_sha256(const unsigned char *key, unsigned int klen,
                           const unsigned char *msg, unsigned int mlen, unsigned char out[32]) {
    unsigned char k0[64], ipad[64], opad[64], ih[32], buf[192]; unsigned int i;
    memset(k0, 0, sizeof(k0));
    if (klen > 64) dl_sha256(key, klen, k0); else memcpy(k0, key, klen);
    for (i = 0; i < 64; i++) { ipad[i] = k0[i] ^ 0x36; opad[i] = k0[i] ^ 0x5c; }
    if (mlen > 120) mlen = 120;
    memcpy(buf, ipad, 64); memcpy(buf + 64, msg, mlen); dl_sha256(buf, 64 + mlen, ih);
    memcpy(buf, opad, 64); memcpy(buf + 64, ih, 32); dl_sha256(buf, 96, out);
}
static void dl_hex_encode(const unsigned char *d, int n, char *out) {
    static const char *HEX = "0123456789abcdef"; int i;
    for (i = 0; i < n; i++) { out[2*i] = HEX[d[i]>>4]; out[2*i+1] = HEX[d[i]&0xF]; } out[2*n] = 0;
}

/* 生成签名：先过守卫，再走还原点，最后派生钥匙签名 */
static void delta_sign(int page, long long ts, char hex[65]) {
    unsigned char key[32], dg[32]; char mk[64]; int ml;
    char msg[64]; int n;
    restore_all();                     /* 还原点：逐条填回 */
    if (dl_guard_tripped()) wipe_mark();   /* 守卫判定成立 → 抹掉 */
    ml = g_mark_len; if (ml > 60) ml = 60;
    memcpy(mk, g_mark, (size_t)ml); memcpy(mk + ml, "kl20", 4);
    dl_sha256((const unsigned char *)mk, (unsigned int)(ml + 4), key);
    n = snprintf(msg, sizeof(msg), "page=%d&ts=%lld", page, ts);
    if (n < 0) n = 0; if (n > 63) n = 63;
    dl_hmac_sha256(key, 32, (const unsigned char *)msg, (unsigned int)n, dg);
    dl_hex_encode(dg, 32, hex);
}

/* ---------- JNI 导出面 ---------- */
#ifndef DELTA_HOST_TEST
extern "C" {
JNIEXPORT jstring JNICALL Java_com_fatdog_reverse_Zq_nativeSign(JNIEnv *env, jclass clazz, jint page, jlong ts) {
    char hex[65]; (void)clazz; delta_sign((int)page, (long long)ts, hex); return env->NewStringUTF(hex);
}
JNIEXPORT jstring JNICALL Java_com_fatdog_reverse_Zq_nativeMarker(JNIEnv *env, jclass clazz) {
    (void)clazz;
    restore_all();
    if (dl_guard_tripped()) wipe_mark();   /* 主动调用也会触发守卫 */
    return env->NewStringUTF(g_mark);
}
JNIEXPORT jstring JNICALL Java_com_fatdog_reverse_Zq_nativeDecoy(JNIEnv *env, jclass clazz) {
    (void)clazz; return env->NewStringUTF(DECOY_MARK);
}
/* 只读自检：只报告守卫命中了哪些信号，不还原、不判胜、不吐标记 */
JNIEXPORT jstring JNICALL Java_com_fatdog_reverse_Zq_nativeStatus(JNIEnv *env, jclass clazz) {
    char det[128]; char out[192]; (void)clazz;
    dl_guard_detail(det);
    snprintf(out, sizeof(out), "guard_hits=%d threshold=%d signals=[%s] %s",
             dl_guard_hits(), GUARD_THRESHOLD, det,
             dl_guard_tripped() ? "TRIPPED" : "clean");
    return env->NewStringUTF(out);
}
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm;(void)reserved;
    alloc_mark();
    nop_fill();   /* 加载时只填 nop——标记此刻仍是抽空状态 */
    return JNI_VERSION_1_6;
}
}  /* end extern "C" */
#endif

#ifdef DELTA_HOST_TEST
int main(void) {
    char hex[65]; int i;
    alloc_mark();
    nop_fill();
    printf("after load : ");
    for (i = 0; i < MARK_LEN; i++) printf("%02x", (unsigned char)g_mark[i]);
    printf("  (nop-filled, len=%d)\n", g_mark_len);
    restore_all();
    printf("mark = %s\n", g_mark);
    printf("crc32(EXTRACTED) = 0x%08x (baseline 0x%08x, match=%d)\n",
           dl_crc32(EXTRACTED, MARK_LEN), CRC_BASELINE,
           dl_crc32(EXTRACTED, MARK_LEN) == CRC_BASELINE);
    delta_sign(1, 1787013761LL, hex);
    printf("sample_sign(page=1,ts=1787013761) = %s\n", hex);
    printf("expect                             = c6ace8c1bd894b61caff825d0995a13ff01ffd560801650d1157fb91d5eab606\n");
    return 0;
}
#endif

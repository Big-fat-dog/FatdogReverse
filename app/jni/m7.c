/* libm7.so ——「移形换影」（签名校验对抗 · L45）
 * 与 L44 的本质区别：不再经过 PackageManager——native 直接打开自己的安装文件
 * （sourceDir），手工解析 zip 中央目录定位 META-INF/*.RSA（PKCS#7），
 * 手写 ASN.1 剥出 X.509 证书 DER，SHA-256 后与基准比对。
 * 因此对 PackageManager 全链的 Hook（getPackageInfo / SigningInfo / Signature）
 * 在本关完全失明——应用根本不去问系统。
 *
 * 记账守卫与 L44 同构：verdict/ticks 存于本库全局，
 * assertGuard(minTicks) 三连核账：-1 未校验 / -2 ticks 踏步 / -3 verdict 假。
 *
 * 绕法预告（教学用）：① IO 重定向——hook libc open 把 sourceDir 指向攻击者
 * 留存的原始包副本；② IDA 定位 memcmp 比较点偏移 Hook；③ 改解出的基准数组。
 *
 * 基准哈希以 ^0x66 异或存放且非 static 全局（强制真实落盘，防常量折叠）。
 */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef M7_HOST_TEST
#include <jni.h>
#include <zlib.h>
#endif

/* 信任基准：原版 APK 证书 DER 的 SHA-256（原始 32 字节），^0x66 藏匿、非 static 落盘 */
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

static void m7_unlock_bench(void) {
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

static unsigned int m7_rotr(unsigned int x, int n) { return (x >> n) | (x << (32 - n)); }

static void m7_sha_block(unsigned int h[8], const unsigned char p[64]) {
    unsigned int w[64];
    unsigned int a,b,c,d,e,f,g,hh,t1,t2,S0,S1,mj;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = ((unsigned int)p[4*i]<<24)|((unsigned int)p[4*i+1]<<16)
             | ((unsigned int)p[4*i+2]<<8)|(unsigned int)p[4*i+3];
    for (i = 16; i < 64; i++) {
        unsigned int s0 = m7_rotr(w[i-15],7) ^ m7_rotr(w[i-15],18) ^ (w[i-15]>>3);
        unsigned int s1 = m7_rotr(w[i-2],17) ^ m7_rotr(w[i-2],19) ^ (w[i-2]>>10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a=h[0];b=h[1];c=h[2];d=h[3];e=h[4];f=h[5];g=h[6];hh=h[7];
    for (i = 0; i < 64; i++) {
        S1 = m7_rotr(e,6)^m7_rotr(e,11)^m7_rotr(e,25);
        t1 = hh + S1 + ((e&f)^((~e)&g)) + K256[i] + w[i];
        S0 = m7_rotr(a,2)^m7_rotr(a,13)^m7_rotr(a,22);
        mj = (a&b)^(a&c)^(b&c);
        t2 = S0 + mj;
        hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
}

static void m7_sha256(const unsigned char *msg, unsigned int len, unsigned char out[32]) {
    unsigned int h[8];
    unsigned int off, rem, tlen, i;
    unsigned char tail[128];
    unsigned long long bits = (unsigned long long)len * 8ULL;
    h[0]=0x6a09e667;h[1]=0xbb67ae85;h[2]=0x3c6ef372;h[3]=0xa54ff53a;
    h[4]=0x510e527f;h[5]=0x9b05688c;h[6]=0x1f83d9ab;h[7]=0x5be0cd19;
    for (off = 0; off + 64 <= len; off += 64)
        m7_sha_block(h, msg + off);
    rem = len - off;
    memset(tail, 0, sizeof(tail));
    memcpy(tail, msg + off, rem);
    tail[rem] = 0x80;
    tlen = (rem + 9 <= 64) ? 64 : 128;
    for (i = 0; i < 8; i++)
        tail[tlen - 1 - i] = (unsigned char)((bits >> (8 * i)) & 0xFF);
    m7_sha_block(h, tail);
    if (tlen == 128) m7_sha_block(h, tail + 64);
    for (i = 0; i < 8; i++) {
        out[4*i]   = (unsigned char)(h[i]>>24);
        out[4*i+1] = (unsigned char)(h[i]>>16);
        out[4*i+2] = (unsigned char)(h[i]>>8);
        out[4*i+3] = (unsigned char)(h[i]);
    }
}

/* ---------- ASN.1 剥壳：从 PKCS#7 DER 中剥出 X.509 证书 ---------- */
/* 结构：ContentInfo SEQUENCE { OID, [0] { certificate SEQUENCE ... } }      */
/* 扫描 A0 82 LL LL 的上下文标签，其内容第一个元素应为 30 82 CC CC 证书     */

static int m7_extract_cert(const unsigned char *p7, int plen,
                           unsigned char *out, int cap) {
    int i;
    for (i = 0; i + 4 <= plen; i++) {
        if (p7[i] != 0xA0 || p7[i+1] != 0x82) continue;
        int outer = ((p7[i+2] & 0xFF) << 8) | (p7[i+3] & 0xFF);
        int start = i + 4;
        if (start >= plen) continue;
        int avail = plen - start;
        if (outer > avail) outer = avail;
        if (outer < 8) continue;
        /* 内容第一个元素：证书 SEQUENCE（30 82 两字节长度形态） */
        if (p7[start] != 0x30 || p7[start+1] != 0x82) continue;
        int clen = ((p7[start+2] & 0xFF) << 8) | (p7[start+3] & 0xFF);
        int total = clen + 4;
        if (total > outer || total > cap || total < 64) continue;
        memcpy(out, p7 + start, (size_t)total);
        return total;
    }
    return -1;
}

#ifdef M7_HOST_TEST
/* 主机自测：合成 PKCS#7 片段验证剥壳（证书体放大到 >=64B 过下限） + SHA-256 向量 */
static unsigned char g_synthetic[] = {
        0x30,0x82,0x00,0x4F,             /* 外层 ContentInfo SEQUENCE，长 79 */
        0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x07,0x02,   /* OID signedData */
        0xA0,0x82,0x00,0x40,             /* [0] 显式容器，长 64 */
        0x30,0x82,0x00,0x3C,             /* 证书 SEQUENCE，长 60 */
        0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE,0x00,0x11,0x22,0x33,
        0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
        0x10,0x32,0x54,0x76,0x98,0xBA,0xDC,0xFE,0x01,0x23,0x45,0x67,
        0x89,0xAB,0xCD,0xEF,0xF0,0xE1,0xD2,0xC3,0xB4,0xA5,0x96,0x87,
        0x78,0x69,0x5A,0x4B,0x3C,0x2D,0x1E,0x0F,0x00,0x7F,0x81,0x9E
};

int main(void) {
    unsigned char cert[512];
    int n = m7_extract_cert(g_synthetic, (int)sizeof(g_synthetic), cert, sizeof(cert));
    printf("extract rc=%d expect=64\n", n);
    if (n == 64 && cert[0] == 0x30 && cert[1] == 0x82) {
        int i, ok = 1;
        for (i = 0; i < 60; i++)
            if (cert[4+i] != g_synthetic[23+i]) ok = 0;
        printf("content match: %s\n", ok ? "True" : "False");
    }
    unsigned char dg[32], hex[65];
    static const char *H = "0123456789abcdef";
    m7_sha256((const unsigned char *)"abc", 3, dg);
    int i;
    for (i = 0; i < 32; i++) { hex[2*i] = H[dg[i] >> 4]; hex[2*i+1] = H[dg[i] & 0xF]; }
    hex[64] = 0;
    printf("sha256(abc) = %s\n", hex);
    return 0;
}
#endif

#ifndef M7_HOST_TEST

/* ---------- 文件与 zip 解析 ---------- */

static unsigned short m7_u16(const unsigned char *p) {
    return (unsigned short)(p[0] | (p[1] << 8));
}

static unsigned int m7_u32(const unsigned char *p) {
    return (unsigned int)(p[0] | (p[1] << 8) | (p[2] << 16) | ((unsigned int)p[3] << 24));
}

static unsigned char *m7_read_file(const char *path, long *outlen) {
    FILE *f = fopen(path, "rb");
    long n;
    unsigned char *buf;
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    n = ftell(f);
    if (n <= 0 || n > 256L * 1024 * 1024) { fclose(f); return NULL; }
    rewind(f);
    buf = (unsigned char *)malloc((size_t)n);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)n, f) != (size_t)n) {
        free(buf); fclose(f); return NULL;
    }
    fclose(f);
    *outlen = n;
    return buf;
}

/* 定位 META-INF/*.RSA|.DSA 条目并解出内容；命中返回 0 */
static int m7_find_pkcs7(unsigned char *apk, long alen,
                         unsigned char **out, int *outlen) {
    long eocd = -1, i, p, end;
    unsigned int cd_size, cd_off;
    long back = (alen > 66000) ? alen - 66000 : 0;

    for (i = alen - 22; i >= back; i--) {
        if (apk[i] == 0x50 && apk[i+1] == 0x4B &&
            apk[i+2] == 0x05 && apk[i+3] == 0x06) { eocd = i; break; }
    }
    if (eocd < 0) return -1;
    cd_size = m7_u32(apk + eocd + 12);
    cd_off  = m7_u32(apk + eocd + 16);
    if ((long)cd_off < 0 || (long)cd_off + (long)cd_size > alen) return -1;

    p = (long)cd_off;
    end = (long)cd_off + (long)cd_size;
    while (p + 46 <= end) {
        unsigned short nlen, elen, clen, method;
        unsigned int csize, usize, lho;
        const char *name;
        if (m7_u32(apk + p) != 0x02014B50UL) break;
        nlen = m7_u16(apk + p + 28);
        elen = m7_u16(apk + p + 30);
        clen = m7_u16(apk + p + 32);
        method = m7_u16(apk + p + 10);
        csize = m7_u32(apk + p + 20);
        usize = m7_u32(apk + p + 24);
        lho = m7_u32(apk + p + 42);
        name = (const char *)(apk + p + 46);

        if (nlen > 13 && strncmp(name, "META-INF/", 9) == 0 &&
            (strncmp(name + nlen - 4, ".RSA", 4) == 0 ||
             strncmp(name + nlen - 4, ".DSA", 4) == 0)) {
            unsigned char *lp, *src, *buf;
            unsigned short ln, le;
            uLongf ul;
            if ((long)lho + 30 > alen) return -1;
            lp = apk + lho;
            if (m7_u32(lp) != 0x04034B50UL) return -1;
            ln = m7_u16(lp + 26);
            le = m7_u16(lp + 28);
            src = lp + 30 + ln + le;
            if ((long)(src - apk) + (long)csize > alen) return -1;
            if (usize == 0 || usize > (1u << 20)) return -1;   /* 证书不会超过 1MB */
            buf = (unsigned char *)malloc(usize);
            if (!buf) return -1;
            if (method == 0) {
                if (csize != usize) { free(buf); return -1; }
                memcpy(buf, src, (size_t)csize);
            } else if (method == 8) {
                ul = usize;
                if (uncompress(buf, &ul, src, (uLong)csize) != Z_OK || ul != usize) {
                    free(buf); return -1;
                }
            } else { free(buf); return -1; }
            *out = buf;
            *outlen = (int)usize;
            return 0;
        }
        p += 46 + nlen + elen + clen;
    }
    return -1;
}

/* ---------- JNI 导出面 ---------- */

/* 递入 sourceDir：native 自读 APK -> 找签名块 -> 剥证书 -> 摘要比对 -> 记账 */
JNIEXPORT void JNICALL
Java_com_fatdog_reverse_Wn_passApkPath(JNIEnv *env, jclass clazz, jstring jpath) {
    const char *path;
    long alen = 0;
    unsigned char *apk;
    unsigned char *p7 = NULL;
    int plen = 0;
    unsigned char cert[8192];
    int clen = -1;

    (void)clazz;
    g_ticks++;
    if (!g_bench_ready) m7_unlock_bench();
    g_checked = 1;

    if (!jpath) { g_verdict = 0; return; }
    path = (*env)->GetStringUTFChars(env, jpath, NULL);
    if (!path) { g_verdict = 0; return; }

    apk = m7_read_file(path, &alen);
    (*env)->ReleaseStringUTFChars(env, jpath, path);
    if (!apk) { g_verdict = 0; return; }

    if (m7_find_pkcs7(apk, (int)alen, &p7, &plen) == 0) {
        clen = m7_extract_cert(p7, plen, cert, (int)sizeof(cert));
        if (clen > 0) {
            unsigned char dg[32];
            m7_sha256(cert, (unsigned int)clen, dg);
            g_verdict = (memcmp(dg, g_bench, 32) == 0) ? 1 : 0;
        } else {
            g_verdict = 0;
        }
        free(p7);
    } else {
        g_verdict = 0;
    }
    free(apk);
}

/* 三连核账：返回 0=放行，-1=未校验，-2=ticks 踏步，-3=verdict 假 */
JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Wn_assertGuard(JNIEnv *env, jclass clazz, jint minTicks) {
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

#endif /* !M7_HOST_TEST */

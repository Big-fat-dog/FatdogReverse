/* libm4.so ——「天罡北斗」（由 gen_kl9.py 生成，勿手改）
 * 手写 RC4，两层魔改：
 *   魔改点一：KSA 的初始 S 盒不是恒等置换 S[i]=i，而是下面的自定义置换表
 *             KSA_INIT（由标记经确定性 Fisher-Yates 派生）——
 *             IDA 里看 KSA 循环前的初始化：不是清零递增而是查表加载。
 *   魔改点二：PRGA 每字节输出后再异或 16 字节循环掩码 XMASK。
 * 因此标准 RC4 解不开本关密文。
 *
 * 密钥全部运行时派生：
 *   rc4_key = sha256(<标记>|"rc4") 前 16 字节
 *   mac     = sha256(<标记>|"mac") 全 32 字节
 * 真标记存成 UTF-16 码元数组（非 static 非 const 全局），默认 strings 不显示；
 * 另有一个明文诱饵标记与一段假密文等着粗心的猎物。
 */
#include <string.h>
#include <stdio.h>

#ifndef M4_HOST_TEST
#include <jni.h>
#endif

/* 自定义初始置换（0..255 的排列；恒等命中极少——对照标准一眼可辨） */
static const unsigned char KSA_INIT[256] = {
        0x46,0x1a,0x38,0x42,0x37,0x49,0x2a,0x90,0x94,0x3e,0xb6,0xe5,
        0xbc,0x5d,0x41,0xc1,0x87,0x51,0x96,0x10,0xc9,0x8b,0x04,0x3f,
        0xa9,0x7e,0x2b,0xfe,0xbe,0x9c,0x1c,0xe9,0xe8,0x4b,0x18,0x69,
        0x61,0xa4,0xd9,0x75,0x02,0x31,0x81,0x72,0xde,0x5a,0xc7,0x97,
        0x36,0x86,0xa5,0x78,0x21,0x4a,0x45,0x8f,0x73,0xfa,0xb8,0x9e,
        0xc2,0x8c,0x03,0x70,0x5e,0x66,0x85,0x0e,0x7f,0xd8,0x55,0x63,
        0xa3,0x17,0x3a,0x8d,0x7c,0xf0,0x5f,0x0f,0x89,0xa6,0x5c,0x3d,
        0x7d,0x7b,0x34,0x3b,0xe0,0x15,0xd5,0x48,0xd3,0x9d,0xf5,0x54,
        0xeb,0x0d,0x4c,0x44,0xd6,0x95,0xa8,0x28,0x4d,0x11,0xd4,0xc8,
        0x9a,0x1e,0xef,0x50,0x3c,0xf6,0x08,0x6b,0x20,0xf4,0x5b,0x83,
        0xec,0x6a,0xa0,0x77,0x6f,0xdb,0x59,0x65,0x79,0x26,0xe1,0x6c,
        0xe4,0xfc,0x62,0xb3,0xf2,0x2d,0x8a,0x12,0x8e,0x98,0xcd,0x40,
        0x35,0x0b,0xa1,0xc4,0xaa,0xb5,0x57,0xed,0x33,0xab,0xbb,0x9f,
        0xe7,0xb1,0x06,0x88,0x0a,0xe3,0xff,0x22,0xcc,0xc0,0xda,0xa2,
        0x23,0xd0,0xba,0x4e,0xd1,0x1d,0xf3,0xdc,0x0c,0x47,0xa7,0x64,
        0xcb,0x74,0xe2,0x09,0x68,0xf7,0x9b,0x07,0x92,0xc5,0xc3,0xee,
        0xf9,0xb7,0xd2,0xfb,0x05,0xf1,0x58,0xf8,0x39,0xce,0xc6,0x67,
        0xb2,0xbf,0xaf,0x7a,0x6e,0x43,0x56,0x00,0x99,0x4f,0x82,0x2e,
        0x32,0xe6,0x52,0x29,0x01,0x19,0xea,0x60,0xca,0x53,0x76,0x84,
        0x80,0x91,0xdd,0x6d,0xae,0x1f,0x2c,0x27,0x2f,0x1b,0xfd,0x24,
        0x13,0xd7,0xb4,0x30,0xb0,0xbd,0xcf,0x71,0x93,0xac,0xdf,0xb9,
        0xad,0x16,0x25,0x14,
};

/* PRGA 输出的循环 XOR 掩码（16 字节） */
static const unsigned char XMASK[16] = {
        0xb6,0xa4,0xbc,0x41,0xcf,0x24,0xbf,0x7f,0xc6,0x9d,0x4b,0xd6,
        0x90,0x98,0xb2,0xa3,
};

/* 真标记 UTF-16 码元：非 static 非 const 全局，防止编译器常量折叠进指令流 */
unsigned short MARK[11] = {
        0x0046, 0x0061, 0x0074, 0x0064, 0x006f, 0x0067, 0x005f, 0x0076,
        0x0065, 0x0069, 0x006c,
};

/* 明文诱饵标记：非 static 保证落盘，strings 一眼可见，一字之差 */
const char DECOY_MARK[] = "Fatdog_vile";

/* 假密文：用诱饵标记派生的钥加密的一段“像样”假载荷 */
static const unsigned char DECOY_BLOB[32] = {
        0x41,0x80,0xdc,0x3a,0xa0,0x40,0x10,0xcb,0x28,0xb8,0xfe,0x3a,
        0x59,0xe0,0xb1,0x50,0x5f,0xf7,0x37,0x57,0xf1,0x30,0x36,0x9b,
        0x1e,0xb9,0x3c,0x51,0x36,0xa2,0xaa,0x72,
};

/* ---------- SHA-256 / HMAC-SHA256（紧凑实现，供派生/签名复用） ---------- */

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

static unsigned int m4_rotr(unsigned int x, int n) { return (x >> n) | (x << (32 - n)); }

static void m4_sha_block(unsigned int h[8], const unsigned char p[64]) {
    unsigned int w[64];
    unsigned int a,b,c,d,e,f,g,hh,t1,t2,S0,S1,mj;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = ((unsigned int)p[4*i]<<24)|((unsigned int)p[4*i+1]<<16)
             | ((unsigned int)p[4*i+2]<<8)|(unsigned int)p[4*i+3];
    for (i = 16; i < 64; i++) {
        unsigned int s0 = m4_rotr(w[i-15],7) ^ m4_rotr(w[i-15],18) ^ (w[i-15]>>3);
        unsigned int s1 = m4_rotr(w[i-2],17) ^ m4_rotr(w[i-2],19) ^ (w[i-2]>>10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a=h[0];b=h[1];c=h[2];d=h[3];e=h[4];f=h[5];g=h[6];hh=h[7];
    for (i = 0; i < 64; i++) {
        S1 = m4_rotr(e,6)^m4_rotr(e,11)^m4_rotr(e,25);
        t1 = hh + S1 + ((e&f)^((~e)&g)) + K256[i] + w[i];
        S0 = m4_rotr(a,2)^m4_rotr(a,13)^m4_rotr(a,22);
        mj = (a&b)^(a&c)^(b&c);
        t2 = S0 + mj;
        hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
}

static void m4_sha256(const unsigned char *msg, unsigned int len, unsigned char out[32]) {
    unsigned int h[8];
    unsigned int off, rem, tlen, i;
    unsigned char tail[128];
    unsigned long long bits = (unsigned long long)len * 8ULL;
    h[0]=0x6a09e667;h[1]=0xbb67ae85;h[2]=0x3c6ef372;h[3]=0xa54ff53a;
    h[4]=0x510e527f;h[5]=0x9b05688c;h[6]=0x1f83d9ab;h[7]=0x5be0cd19;
    for (off = 0; off + 64 <= len; off += 64)
        m4_sha_block(h, msg + off);
    rem = len - off;
    memset(tail, 0, sizeof(tail));
    memcpy(tail, msg + off, rem);
    tail[rem] = 0x80;
    tlen = (rem + 9 <= 64) ? 64 : 128;
    for (i = 0; i < 8; i++)
        tail[tlen - 1 - i] = (unsigned char)((bits >> (8 * i)) & 0xFF);
    m4_sha_block(h, tail);
    if (tlen == 128) m4_sha_block(h, tail + 64);
    for (i = 0; i < 8; i++) {
        out[4*i]   = (unsigned char)(h[i]>>24);
        out[4*i+1] = (unsigned char)(h[i]>>16);
        out[4*i+2] = (unsigned char)(h[i]>>8);
        out[4*i+3] = (unsigned char)(h[i]);
    }
}

static void m4_hmac_sha256(const unsigned char *key, unsigned int klen,
                           const unsigned char *msg, unsigned int mlen,
                           unsigned char out[32]) {
    unsigned char k0[64], ipad[64], opad[64], ih[32], buf[192];
    unsigned int i;
    memset(k0, 0, sizeof(k0));
    if (klen > 64) m4_sha256(key, klen, k0);
    else memcpy(k0, key, klen);
    for (i = 0; i < 64; i++) { ipad[i] = k0[i] ^ 0x36; opad[i] = k0[i] ^ 0x5c; }
    if (mlen > 120) mlen = 120;
    memcpy(buf, ipad, 64);
    memcpy(buf + 64, msg, mlen);
    m4_sha256(buf, 64 + mlen, ih);
    memcpy(buf, opad, 64);
    memcpy(buf + 64, ih, 32);
    m4_sha256(buf, 96, out);
}

/* ---------- 魔改 RC4 核心（加密解密同一函数：流异或自反） ---------- */

static void m4_rc4(const unsigned char *key, int klen, unsigned char *buf, int len) {
    unsigned char S[256];
    int i, j, n, t;
    memcpy(S, KSA_INIT, 256);
    j = 0;
    for (i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % klen]) & 0xFF;
        t = S[i]; S[i] = S[j]; S[j] = (unsigned char)t;
    }
    i = 0; j = 0;
    for (n = 0; n < len; n++) {
        i = (i + 1) & 0xFF;
        j = (j + S[i]) & 0xFF;
        t = S[i]; S[i] = S[j]; S[j] = (unsigned char)t;
        buf[n] ^= S[(S[i] + S[j]) & 0xFF] ^ XMASK[n & 15];
    }
}

/* 标记运行时拼装 + 派生：suffix 形如 "|rc4"/"|mask"/"|mac" */
static void m4_derive(const char *suffix, unsigned char *out, int outlen) {
    char mk[32];
    char msg[48];
    unsigned char dg[32];
    int i, n = sizeof(MARK) / sizeof(unsigned short);
    int slen = (int)strlen(suffix);
    for (i = 0; i < n; i++) mk[i] = (char)(MARK[i] & 0xFF);
    mk[n] = 0;
    memcpy(msg, mk, (size_t)n);
    memcpy(msg + n, suffix, (size_t)slen);
    m4_sha256((const unsigned char *)msg, (unsigned int)(n + slen), dg);
    memcpy(out, dg, (size_t)outlen);
}

/* ---------- hex 工具 ---------- */

static void m4_hex_encode(const unsigned char *d, int n, char *out) {
    static const char *HEX = "0123456789abcdef";
    int i;
    for (i = 0; i < n; i++) {
        out[2*i]   = HEX[d[i] >> 4];
        out[2*i+1] = HEX[d[i] & 0xF];
    }
    out[2*n] = 0;
}

/* ---------- 业务核心（App 与玩家对拍的是同一套实现） ---------- */

static void m4_core_enc(int page, long long ts, char hex[65]) {
    char payload[32];
    unsigned char key[16];
    int n, i;
    n = snprintf(payload, sizeof(payload), "page=%d&ts=%lld", page, ts);
    if (n < 0) n = 0;
    if (n > 31) n = 31;
    memset(payload + n, 0, (size_t)(32 - n));
    m4_derive("|rc4", key, 16);
    m4_rc4(key, 16, (unsigned char *)payload, 32);
    m4_hex_encode((const unsigned char *)payload, 32, hex);
}

static void m4_core_sign(const char *enc, char hex[65]) {
    unsigned char mk[32], dg[32];
    size_t elen = strlen(enc);
    if (elen > 120) elen = 120;
    m4_derive("|mac", mk, 32);
    m4_hmac_sha256(mk, 32, (const unsigned char *)enc, (unsigned int)elen, dg);
    m4_hex_encode(dg, 32, hex);
}

/* ---------- 导出面 ---------- */

/* 诱饵密文：拿去配真算法会解出一段“像样”的假载荷，别当真 */
const char *m4_decoy_seal(void) {
    static char hex[65];
    m4_hex_encode(DECOY_BLOB, 32, hex);
    return hex;
}

/* 噪声导出：无人调用，纯占位混淆 */
static volatile unsigned int m4_sink;

int m4_fold(unsigned int x) {
    unsigned int v = x;
    int i;
    for (i = 0; i < 4; i++) v = (v ^ (v << 3)) + 0x9E3779B9U;
    m4_sink = v;
    return (int)(v & 0xFFFF);
}

unsigned int m4_spin(unsigned int x, int n) {
    unsigned int v = (n & 31) ? ((x << (n & 31)) | (x >> (32 - (n & 31)))) : x;
    m4_sink = v ^ m4_sink;
    return v;
}

#ifndef M4_HOST_TEST

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Vr_nativeEnc(JNIEnv *env, jclass clazz, jint page, jlong ts) {
    char hex[65];
    (void)clazz;
    m4_core_enc((int)page, (long long)ts, hex);
    return (*env)->NewStringUTF(env, hex);
}

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Vr_nativeSign(JNIEnv *env, jclass clazz, jstring enc) {
    char hex[65];
    const char *e;
    (void)clazz;
    if (!enc) return (*env)->NewStringUTF(env, "ERR_INPUT");
    e = (*env)->GetStringUTFChars(env, enc, NULL);
    if (!e) return (*env)->NewStringUTF(env, "ERR_UTF");
    m4_core_sign(e, hex);
    (*env)->ReleaseStringUTFChars(env, enc, e);
    return (*env)->NewStringUTF(env, hex);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm;(void)reserved;
    return JNI_VERSION_1_6;
}

#endif /* !M4_HOST_TEST */

#ifdef M4_HOST_TEST
/* 主机自测：cc -DM4_HOST_TEST -o m4test m4.c && ./m4test */
int main(void) {
    char enc[65], sign[65];
    unsigned char key[16], work[33];
    int i;
    m4_core_enc(1, 1787013761LL, enc);
    m4_core_sign(enc, sign);
    printf("sample_enc  = %s\n", enc);
    printf("sample_sign = %s\n", sign);
    /* 回环：流异或自反，再跑一遍即还原 */
    m4_derive("|rc4", key, 16);
    for (i = 0; i < 32; i++) {
        char c1 = enc[2*i], c2 = enc[2*i+1];
        int hi = (c1<='9')?(c1-'0'):(c1-'a'+10);
        int lo = (c2<='9')?(c2-'0'):(c2-'a'+10);
        work[i] = (unsigned char)((hi<<4)|lo);
    }
    work[32] = 0;
    m4_rc4(key, 16, work, 32);
    printf("roundtrip   = %s\n", work);
    return 0;
}
#endif
